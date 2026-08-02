//! Bounded subprocess execution and executable lookup.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Maximum number of bytes retained from each subprocess output stream.
pub const MAX_CAPTURE_BYTES: usize = 256 * 1024;

/// Captured result of a bounded subprocess.
#[derive(Debug)]
pub struct CommandOutput {
    /// Child exit status, including the signal status after a timeout kill.
    pub status: ExitStatus,
    /// First [`MAX_CAPTURE_BYTES`] bytes written to standard output.
    pub stdout: Vec<u8>,
    /// First [`MAX_CAPTURE_BYTES`] bytes written to standard error.
    pub stderr: Vec<u8>,
    /// Whether Silvervine terminated the child after the deadline.
    pub timed_out: bool,
}

/// Resolve an executable name against the current `PATH`.
#[must_use]
pub fn find_executable(name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.components().count() > 1 {
        return is_executable_file(path).then(|| path.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable_file(candidate))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Run a subprocess while draining and bounding both output streams.
///
/// # Errors
///
/// Returns a categorized error when spawning, waiting, reading output, or
/// joining a reader thread fails.
pub fn run_output_with_timeout(
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|error| {
        Error::other(format!("failed to spawn {}", program.display())).with_source(error)
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::other("subprocess stdout pipe was not available"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::other("subprocess stderr pipe was not available"))?;
    let stdout_reader = thread::spawn(move || read_capped(stdout));
    let stderr_reader = thread::spawn(move || read_capped(stderr));

    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().map_err(Error::from)? {
            break (status, false);
        }
        if started.elapsed() >= timeout {
            terminate_child(&mut child, program)?;
            break (child.wait().map_err(Error::from)?, true);
        }
        thread::sleep(Duration::from_millis(5));
    };

    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
        timed_out,
    })
}
fn terminate_child(child: &mut Child, program: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        terminate_process_group(child.id(), program)
    }
    #[cfg(not(unix))]
    {
        child.kill().map_err(|error| {
            Error::other(format!("failed to terminate {}", program.display())).with_source(error)
        })
    }
}

#[cfg(unix)]
fn terminate_process_group(process_id: u32, program: &Path) -> Result<()> {
    let process_group = i32::try_from(process_id)
        .map_err(|_| Error::other("subprocess ID does not fit a Unix process-group ID"))?;
    // SAFETY: the child starts a fresh process group whose ID is its PID.
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(Error::other(format!("failed to terminate {}", program.display())).with_source(error))
    }
}

fn read_capped(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(retained)
}

fn join_reader(handle: thread::JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| Error::other("subprocess output reader panicked"))?
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::{find_executable, run_output_with_timeout, MAX_CAPTURE_BYTES};
    use crate::test_support::env_lock;

    struct ScopedPath(Option<OsString>);

    impl ScopedPath {
        fn set(value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os("PATH");
            // SAFETY: every environment-mutating test holds the crate-wide lock.
            unsafe { std::env::set_var("PATH", value) };
            Self(previous)
        }
    }

    impl Drop for ScopedPath {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                // SAFETY: the crate-wide environment lock remains held until after this guard drops.
                unsafe { std::env::set_var("PATH", previous) };
            } else {
                // SAFETY: see above.
                unsafe { std::env::remove_var("PATH") };
            }
        }
    }

    #[test]
    fn find_executable_rejects_directories_and_non_executable_files() {
        let _guard = env_lock();
        let tmp = TempDir::new().expect("tempdir");
        fs::create_dir(tmp.path().join("directory-tool")).expect("directory");
        fs::write(tmp.path().join("plain-tool"), b"not executable").expect("plain file");
        let _path = ScopedPath::set(tmp.path());

        assert_eq!(find_executable("directory-tool"), None);
        assert_eq!(find_executable("plain-tool"), None);
    }

    #[cfg(unix)]
    #[test]
    fn find_executable_returns_first_executable_path_entry() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        let first = TempDir::new().expect("first");
        let second = TempDir::new().expect("second");
        let tool = second.path().join("media-tool");
        fs::write(&tool, b"#!/bin/sh\nexit 0\n").expect("script");
        let mut permissions = fs::metadata(&tool).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tool, permissions).expect("chmod");
        let joined = std::env::join_paths([first.path(), second.path()]).expect("PATH");
        let _path = ScopedPath::set(&joined);

        assert_eq!(find_executable("media-tool"), Some(tool));
    }

    #[test]
    fn run_output_with_timeout_captures_successful_output() {
        let output = run_output_with_timeout(
            Path::new("/bin/sh"),
            &["-c", "printf stdout; printf stderr >&2"],
            Duration::from_secs(1),
        )
        .expect("command");

        assert!(!output.timed_out);
        assert!(output.status.success());
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
    }

    #[test]
    fn run_output_with_timeout_kills_slow_child() {
        let output = run_output_with_timeout(
            Path::new("/usr/bin/sleep"),
            &["2"],
            Duration::from_millis(40),
        )
        .expect("command");

        assert!(output.timed_out);
        assert!(!output.status.success());
    }
    #[cfg(unix)]
    #[test]
    fn run_output_with_timeout_kills_descendants_holding_output_pipes() {
        let started = std::time::Instant::now();
        let output = run_output_with_timeout(
            Path::new("/bin/sh"),
            &["-c", "sleep 5 & wait"],
            Duration::from_millis(40),
        )
        .expect("command");

        assert!(output.timed_out);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "descendant inherited an output pipe after the timeout"
        );
    }

    #[test]
    fn run_output_with_timeout_caps_verbose_output() {
        let output =
            run_output_with_timeout(Path::new("/usr/bin/yes"), &[], Duration::from_millis(40))
                .expect("command");

        assert!(output.timed_out);
        assert_eq!(output.stdout.len(), MAX_CAPTURE_BYTES);
    }
}
