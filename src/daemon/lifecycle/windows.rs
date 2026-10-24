//! Per-user Startup shortcuts; no machine-wide registration or elevation.
use crate::error::{Error, Result};
use std::os::windows::process::CommandExt;
use std::{path::PathBuf, process::Command};

fn startup_path(name: &str) -> Result<PathBuf> {
    dirs::config_dir()
        .map(|p| {
            p.join("Microsoft/Windows/Start Menu/Programs/Startup")
                .join(name)
        })
        .ok_or_else(|| Error::other("cannot resolve Windows roaming AppData"))
}
pub(super) fn registration_path() -> Result<PathBuf> {
    startup_path("Silvervine.lnk")
}
fn legacy_path() -> Result<PathBuf> {
    startup_path("Neon.lnk")
}
fn powershell_path() -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| Error::other("cannot resolve absolute Windows SystemRoot"))?;
    Ok(root.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
}

// Only an exact executable command line (quoted or unquoted), with no arguments,
// identifies our tray daemon. CLI patch/update processes must never be stopped.
const DAEMON_FILTER: &str = r#"
$target=$w.CreateShortcut($env:SILVERVINE_LINK).TargetPath;
$bare='^\s*'+[regex]::Escape($target)+'\s*$';
$quoted='^\s*"'+[regex]::Escape($target)+'"\s*$';
$p=@(Get-CimInstance Win32_Process | Where-Object {
    $exe=$_.ExecutablePath;
    if ($exe -and $exe.StartsWith('\\?\')) { $exe=$exe.Substring(4) };
    $parent=if ($exe) { [IO.Path]::GetDirectoryName($exe) } else { '' };
    $relocated=$exe -and [IO.Path]::GetFileName($exe) -eq 'silvervine.exe' -and
        [IO.Path]::GetFileName($parent).StartsWith('.silvervine-update-') -and
        [IO.Path]::GetDirectoryName($parent) -eq [IO.Path]::GetDirectoryName($target);
    ($exe -eq $target -or $relocated) -and
        ($_.CommandLine -match $bare -or $_.CommandLine -match $quoted) -and
        $_.ProcessId -ne [int]$env:SILVERVINE_PID
})"#;

fn powershell(script: &str, values: &[(&str, &std::ffi::OsStr)]) -> Result<String> {
    let output = Command::new(powershell_path()?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .envs(values.iter().copied())
        .creation_flags(0x0800_0000)
        .output()?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "Windows lifecycle: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
fn start() -> Result<()> {
    Command::new(std::env::current_exe()?)
        .creation_flags(0x0800_0000)
        .spawn()?;
    Ok(())
}
fn write_shortcut(path: &std::path::Path, executable: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(
        path.parent()
            .ok_or_else(|| Error::other("invalid Startup path"))?,
    )?;
    powershell("$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($env:SILVERVINE_LINK); $s.TargetPath=$env:SILVERVINE_EXE; $s.Arguments=''; $s.WorkingDirectory=[IO.Path]::GetDirectoryName($env:SILVERVINE_EXE); $s.WindowStyle=7; $s.Save()", &[("SILVERVINE_LINK", path.as_os_str()), ("SILVERVINE_EXE", executable.as_os_str())])?;
    Ok(())
}
pub(super) fn register() -> Result<()> {
    write_shortcut(&registration_path()?, &std::env::current_exe()?)?;
    start()
}
fn stop_link(path: &std::path::Path) -> Result<bool> {
    if !path.try_exists()? {
        return Ok(false);
    }
    let own_pid = std::process::id().to_string();
    let script = format!("$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; {DAEMON_FILTER}; foreach($item in $p) {{ Stop-Process -Id $item.ProcessId -ErrorAction Stop }}; $p.Count");
    let result = powershell(
        &script,
        &[
            ("SILVERVINE_LINK", path.as_os_str()),
            ("SILVERVINE_PID", own_pid.as_ref()),
        ],
    )?;
    Ok(result != "0")
}
fn remove(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
pub(super) fn unregister() -> Result<()> {
    let path = registration_path()?;
    stop_link(&path)?;
    remove(&path)
}
pub(super) fn unregister_for_rollback() -> Result<()> {
    unregister()
}
pub(super) fn restart() -> Result<()> {
    let path = registration_path()?;
    if !path.try_exists()? {
        return Ok(());
    }
    stop_link(&path)?;
    // Only a daemon restarting itself needs delayed termination; a CLI caller
    // must remain alive to finish its update transaction and report the result.
    let pid = std::process::id().to_string();
    Command::new(powershell_path()?).args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; $target=$w.CreateShortcut($env:SILVERVINE_LINK).TargetPath; if ($env:SILVERVINE_STOP_SELF -eq '1') { $p=Get-Process -Id ([int]$env:SILVERVINE_PID) -ErrorAction Stop; Start-Sleep -Seconds 2; if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit() } }; Start-Process -FilePath $target -WindowStyle Hidden"])
        .env("SILVERVINE_PID", pid).env("SILVERVINE_LINK", path)
        .env("SILVERVINE_STOP_SELF", if std::env::args_os().len() == 1 { "1" } else { "0" })
        .creation_flags(0x0800_0000).spawn()?;
    Ok(())
}
pub(super) fn legacy_is_registered() -> Result<bool> {
    Ok(legacy_path()?.try_exists()?)
}
pub(super) fn stop_legacy() -> Result<bool> {
    stop_link(&legacy_path()?)
}
pub(super) fn restore_legacy(was_running: bool) -> Result<()> {
    if was_running {
        let path = legacy_path()?;
        powershell(
            "$ErrorActionPreference='Stop'; Start-Process -FilePath $env:SILVERVINE_LINK",
            &[("SILVERVINE_LINK", path.as_os_str())],
        )?;
    }
    Ok(())
}
pub(super) fn remove_legacy_registration() -> Result<()> {
    remove(&legacy_path()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_round_trip_stays_in_temporary_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary
            .path()
            .join("Startup with spaces")
            .join("Silvervine.lnk");
        let executable = std::env::current_exe().unwrap();
        write_shortcut(&path, &executable).unwrap();
        let actual = powershell("$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($env:SILVERVINE_LINK); if ($s.TargetPath -ne $env:SILVERVINE_EXE -or $s.Arguments -ne '' -or $s.WindowStyle -ne 7 -or $s.WorkingDirectory -ne [IO.Path]::GetDirectoryName($env:SILVERVINE_EXE)) { throw 'Shortcut properties differ' }; 'ok'", &[("SILVERVINE_LINK", path.as_os_str()), ("SILVERVINE_EXE", executable.as_os_str())]).unwrap();
        assert_eq!(actual, "ok");
        remove(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn daemon_filter_excludes_cli_arguments() {
        let script = format!(
            r#"$ErrorActionPreference='Stop'; $target='C:\Program Files\Silvervine\silvervine.exe'; $w=New-Object PSObject; $w | Add-Member ScriptMethod CreateShortcut {{ param($path) [pscustomobject]@{{ TargetPath=$target }} }}; function Get-CimInstance {{ @([pscustomobject]@{{ExecutablePath=$target;CommandLine='"'+$target+'"';ProcessId=1}}, [pscustomobject]@{{ExecutablePath=$target;CommandLine='"'+$target+'" patch';ProcessId=2}}, [pscustomobject]@{{ExecutablePath=$target;CommandLine=$target+' update-self';ProcessId=3}}, [pscustomobject]@{{ExecutablePath='C:\Program Files\Silvervine\.silvervine-update-abc\silvervine.exe';CommandLine='"'+$target+'"';ProcessId=4}}, [pscustomobject]@{{ExecutablePath='C:\Other\.silvervine-update-abc\silvervine.exe';CommandLine='"'+$target+'"';ProcessId=5}}) }}; {DAEMON_FILTER}; if ($p.Count -ne 2 -or $p[0].ProcessId -ne 1 -or $p[1].ProcessId -ne 4) {{ throw 'Selected a CLI process' }}; 'ok'"#
        );
        assert_eq!(
            powershell(&script, &[("SILVERVINE_PID", std::ffi::OsStr::new("0"))]).unwrap(),
            "ok"
        );
    }
}
