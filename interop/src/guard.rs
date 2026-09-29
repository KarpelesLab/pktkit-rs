//! Making sure the guest never outlives the harness, and the harness never
//! outlives its deadline.
//!
//! QEMU is a child process, and nothing about that ties its life to ours:
//! a harness that exits without dropping its `Vm` (`process::exit`), dies
//! of a signal, or hangs, leaves the guest running, holding whatever it
//! inherited open. So QEMU's pid is kept here where a signal handler and
//! the watchdog can reach it, QEMU writes a pidfile that the next run
//! checks for a leftover, and on Linux the kernel kills QEMU when the
//! harness dies, however it dies.

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The running guest's pid, or 0. Read by the signal handler, so an atomic
/// rather than anything that locks.
static QEMU_PID: AtomicI32 = AtomicI32::new(0);

pub fn set_qemu_pid(pid: u32) {
    QEMU_PID.store(pid as i32, Ordering::SeqCst);
}

pub fn clear_qemu_pid() {
    QEMU_PID.store(0, Ordering::SeqCst);
}

/// Kill the guest outright. Async-signal-safe: it is all the signal
/// handler does besides `_exit`.
pub fn kill_qemu() {
    let pid = QEMU_PID.swap(0, Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    kill_qemu();
    // Nothing that allocates or locks: the signal may have landed in the
    // middle of either.
    let msg = b"interop: interrupted, guest killed\n";
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
        libc::_exit(128 + sig);
    }
}

/// On SIGINT, SIGTERM or SIGHUP (^C, a CI runner cancelling the job, a
/// closed terminal), kill the guest and exit.
pub fn install_signal_handlers() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe {
            libc::signal(
                sig,
                on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
            );
        }
    }
}

/// Kill the QEMU a previous run left behind, if `pidfile` names one that
/// is still running and is QEMU (a pid can be reused by anything).
pub fn kill_stale(pidfile: &Path) {
    let Some(pid) = std::fs::read_to_string(pidfile)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|&p| p > 0)
    else {
        return;
    };
    let comm = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if comm.contains("qemu-system") {
        eprintln!("killing a guest left over from an earlier run (pid {pid})");
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        // Wait for it to go, so it does not hold the pidfile's lock.
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end && unsafe { libc::kill(pid, 0) } == 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let _ = std::fs::remove_file(pidfile);
}

/// What the watchdog needs to leave a useful report behind.
#[derive(Debug, Default)]
pub struct Progress {
    /// The report so far.
    pub report: String,
    /// The test running, and when it is overdue.
    pub test: Option<(&'static str, Instant)>,
}

/// Exit, with the guest killed and what was reported so far written out,
/// once `deadline` passes or a test overruns its own. Tests have limits of
/// their own on everything they wait for; this catches whatever slips
/// past those (a lost wakeup, a peer that never answers) so that a run
/// always ends.
pub fn watchdog(progress: Arc<Mutex<Progress>>, deadline: Instant, report_path: &Path) {
    let report_path = report_path.to_path_buf();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = Instant::now();
            let why = {
                let p = progress.lock().unwrap_or_else(|e| e.into_inner());
                match p.test {
                    _ if now >= deadline => Some("the run's deadline".to_string()),
                    Some((name, end)) if now >= end => Some(format!("{name}'s time limit")),
                    _ => None,
                }
            };
            let Some(why) = why else { continue };
            kill_qemu();
            let mut p = progress.lock().unwrap_or_else(|e| e.into_inner());
            let line = match p.test {
                Some((name, _)) => format!("TIMEOUT {name}: past {why}; guest killed"),
                None => format!("TIMEOUT: past {why}; guest killed"),
            };
            p.report.push_str(&line);
            p.report.push('\n');
            let _ = std::fs::write(&report_path, &p.report);
            eprintln!("{line}");
            let _ = std::io::stderr().flush();
            std::process::exit(124);
        }
    });
}
