#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use objc2_app_kit::{
        NSApplicationActivationPolicy, NSRunningApplication,
    };

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let home = tempfile::TempDir::new().expect("temporary daemon home");
    let mut daemon = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_silvervine"))
            .env("HOME", home.path())
            .env("SILVERVINE_TEST_DATA_MIGRATION_NOOP", "1")
            .env("SILVERVINE_TEST_LIFECYCLE_NOOP", "1")
            .env("SILVERVINE_TEST_POWER_NOOP", "1")
            .env("SILVERVINE_TEST_NOTIFY_NOOP", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn Silvervine daemon"),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut observed = None;
    while Instant::now() < deadline {
        if let Some(status) = daemon.0.try_wait().expect("query daemon status") {
            panic!("Silvervine daemon exited before AppKit initialization: {status}");
        }
        if let Some(application) =
            NSRunningApplication::runningApplicationWithProcessIdentifier(
                daemon.0.id() as libc::pid_t,
            )
        {
            observed = Some(application.activationPolicy());
            if observed == Some(NSApplicationActivationPolicy::Accessory) {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    assert_eq!(
        observed,
        Some(NSApplicationActivationPolicy::Accessory),
        "tray daemon must register as an accessory AppKit application"
    );
}
