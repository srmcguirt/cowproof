//! Starting a program that was written a moment ago.
//!
//! On Linux, `exec` of a file fails with `ETXTBSY` (`io::ErrorKind::ExecutableFileBusy`)
//! while any process holds the file open for writing. In a program with more than one thread
//! that writes an executable and then runs it, a `fork` on another thread can inherit the
//! write handle for the moment between its fork and its exec (`O_CLOEXEC` closes it at the
//! exec), and an exec of the new file in that window fails. The failure is brief and nothing
//! is wrong with the file, so the right answer is to start again a few milliseconds later.
//!
//! This module is the one place that does it: [`retry_busy`] and [`retry_busy_async`] run an
//! operation and repeat it while it fails with `ExecutableFileBusy`, up to [`BUSY_RETRIES`]
//! times, [`BUSY_BACKOFF`] apart (about a second in all). Every other error, and the last
//! `ExecutableFileBusy` once the retries are spent, comes back unchanged. [`spawn`],
//! [`spawn_async`] and [`exec`] apply it to a [`Command`](std::process::Command).
//!
//! A `Command` can be started again after a failed start, so the retry reuses it: stdio set
//! to `Stdio::piped()` makes new pipes each time.

use std::io;
use std::time::Duration;

/// How many times an operation that failed with `ExecutableFileBusy` is repeated.
pub const BUSY_RETRIES: u32 = 50;
/// How long to wait between two attempts.
pub const BUSY_BACKOFF: Duration = Duration::from_millis(20);

fn is_busy(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ExecutableFileBusy
}

/// Run `op`, and again while it fails with `ExecutableFileBusy`: up to [`BUSY_RETRIES`] more
/// times, [`BUSY_BACKOFF`] apart. Blocks the calling thread while it waits, so an async
/// caller uses [`retry_busy_async`].
pub fn retry_busy<T>(op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_busy_with(BUSY_RETRIES, BUSY_BACKOFF, op)
}

/// [`retry_busy`] with the number of repeats and the wait chosen by the caller.
pub fn retry_busy_with<T>(
    retries: u32,
    backoff: Duration,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut left = retries;
    loop {
        match op() {
            Err(e) if is_busy(&e) && left > 0 => {
                left -= 1;
                std::thread::sleep(backoff);
            }
            other => return other,
        }
    }
}

/// [`retry_busy`] for async code: it waits on the tokio timer, so it never blocks the
/// executor.
pub async fn retry_busy_async<T>(op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_busy_async_with(BUSY_RETRIES, BUSY_BACKOFF, op).await
}

/// [`retry_busy_async`] with the number of repeats and the wait chosen by the caller.
pub async fn retry_busy_async_with<T>(
    retries: u32,
    backoff: Duration,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut left = retries;
    loop {
        match op() {
            Err(e) if is_busy(&e) && left > 0 => {
                left -= 1;
                tokio::time::sleep(backoff).await;
            }
            other => return other,
        }
    }
}

/// `command.spawn()`, repeated while the program is busy ([`retry_busy`]).
pub fn spawn(command: &mut std::process::Command) -> io::Result<std::process::Child> {
    retry_busy(|| command.spawn())
}

/// `command.spawn()` for a tokio command, repeated while the program is busy
/// ([`retry_busy_async`]).
pub async fn spawn_async(
    command: &mut tokio::process::Command,
) -> io::Result<tokio::process::Child> {
    retry_busy_async(|| command.spawn()).await
}

/// Replace this process with `command` (`CommandExt::exec`), repeated while the program is
/// busy. It returns only the error that stopped it.
#[cfg(unix)]
pub fn exec(command: &mut std::process::Command) -> io::Error {
    use std::os::unix::process::CommandExt;
    match retry_busy(|| Err::<std::convert::Infallible, _>(command.exec())) {
        Err(e) => e,
        Ok(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn busy() -> io::Error {
        io::Error::from(io::ErrorKind::ExecutableFileBusy)
    }

    const FAST: Duration = Duration::from_millis(1);

    #[test]
    fn a_busy_start_is_repeated_until_it_works() {
        let calls = Cell::new(0u32);
        let got = retry_busy_with(10, FAST, || {
            calls.set(calls.get() + 1);
            if calls.get() < 4 {
                Err(busy())
            } else {
                Ok("started")
            }
        });
        assert_eq!(got.unwrap(), "started");
        assert_eq!(calls.get(), 4);
    }

    #[test]
    fn a_start_that_stays_busy_gives_up_after_the_retries() {
        let calls = Cell::new(0u32);
        let got: io::Result<()> = retry_busy_with(5, FAST, || {
            calls.set(calls.get() + 1);
            Err(busy())
        });
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::ExecutableFileBusy);
        assert_eq!(calls.get(), 6, "the first try and five retries");
    }

    #[test]
    fn every_other_error_passes_straight_through() {
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
        ] {
            let calls = Cell::new(0u32);
            let got: io::Result<()> = retry_busy_with(5, FAST, || {
                calls.set(calls.get() + 1);
                Err(io::Error::from(kind))
            });
            assert_eq!(got.unwrap_err().kind(), kind);
            assert_eq!(calls.get(), 1, "{kind:?} is not retried");
        }
    }

    #[tokio::test]
    async fn the_async_retry_repeats_a_busy_start_and_passes_other_errors() {
        let calls = Cell::new(0u32);
        let got = retry_busy_async_with(10, FAST, || {
            calls.set(calls.get() + 1);
            if calls.get() < 3 {
                Err(busy())
            } else {
                Ok(())
            }
        })
        .await;
        assert!(got.is_ok());
        assert_eq!(calls.get(), 3);

        let calls = Cell::new(0u32);
        let got: io::Result<()> = retry_busy_async_with(10, FAST, || {
            calls.set(calls.get() + 1);
            Err(io::Error::from(io::ErrorKind::NotFound))
        })
        .await;
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(calls.get(), 1);
    }

    /// A script that a handle still holds open for writing. On Linux the kernel refuses to
    /// exec it (`ETXTBSY`) until the handle closes; a plain spawn fails and the helper waits
    /// the writer out. On other systems the same open file runs, so the helper must not
    /// change the outcome.
    #[cfg(unix)]
    mod writer_still_open {
        use super::*;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Stdio;

        fn held_script(dir: &std::path::Path) -> (std::path::PathBuf, std::fs::File) {
            let path = dir.join("fresh.sh");
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
            file.flush().unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            (path, file)
        }

        fn command(path: &std::path::Path) -> std::process::Command {
            let mut command = std::process::Command::new(path);
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_refuses_a_file_open_for_writing_and_the_helper_waits_for_the_writer() {
            let dir = tempfile::Builder::new()
                .prefix("pk-etxtbsy-")
                .tempdir_in("/var/tmp")
                .unwrap();
            let (path, file) = held_script(dir.path());

            // The plain spawn fails: this is the failure the helper exists for. It is
            // asserted, so the test cannot pass without the kernel behavior it covers.
            let plain = command(&path).spawn();
            assert_eq!(
                plain.unwrap_err().kind(),
                io::ErrorKind::ExecutableFileBusy,
                "exec of a file open for writing must fail with ETXTBSY on Linux"
            );

            // Release the writer after about 100 ms, on another thread.
            let releaser = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                drop(file);
            });
            let attempts = Cell::new(0u32);
            let mut cmd = command(&path);
            let mut child = retry_busy(|| {
                attempts.set(attempts.get() + 1);
                cmd.spawn()
            })
            .expect("the helper's spawn succeeds once the writer has closed");
            assert!(child.wait().unwrap().success());
            assert!(
                attempts.get() > 1,
                "the helper really retried ({} attempts)",
                attempts.get()
            );
            releaser.join().unwrap();

            // The public wrappers behave the same way.
            let (path2, file2) = held_script(dir.path());
            let releaser = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                drop(file2);
            });
            let mut child = spawn(&mut command(&path2)).unwrap();
            assert!(child.wait().unwrap().success());
            releaser.join().unwrap();
        }

        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn linux_the_async_spawn_waits_for_the_writer_too() {
            let dir = tempfile::Builder::new()
                .prefix("pk-etxtbsy-")
                .tempdir_in("/var/tmp")
                .unwrap();
            let (path, file) = held_script(dir.path());
            let releaser = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                drop(file);
            });
            let mut cmd = tokio::process::Command::from(command(&path));
            let mut child = spawn_async(&mut cmd).await.unwrap();
            assert!(child.wait().await.unwrap().success());
            releaser.join().unwrap();
        }

        #[cfg(not(target_os = "linux"))]
        #[test]
        fn without_etxtbsy_the_helper_starts_the_program_at_once() {
            // macOS does not refuse the exec of a file open for writing: there is nothing to
            // retry, and the helper must start the program on its first try.
            let dir = tempfile::Builder::new()
                .prefix("pk-etxtbsy-")
                .tempdir_in("/var/tmp")
                .unwrap();
            let (path, file) = held_script(dir.path());
            let attempts = Cell::new(0u32);
            let mut cmd = command(&path);
            let mut child = retry_busy(|| {
                attempts.set(attempts.get() + 1);
                cmd.spawn()
            })
            .unwrap();
            assert!(child.wait().unwrap().success());
            assert_eq!(attempts.get(), 1);
            drop(file);
        }
    }
}
