//! The guest: QEMU booting the image directly (no firmware, no disk), its
//! NIC on a pktkit `qemu::Listener`, and the agent's console on a TCP
//! socket of the harness's.

use crate::image::{Arch, Image};
use pktkit::qemu;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const GUEST_MAC: &str = "52:54:00:12:34:56";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accel {
    Hvf,
    Kvm,
    Tcg,
}

impl Accel {
    pub fn parse(s: &str) -> Option<Accel> {
        match s {
            "hvf" => Some(Accel::Hvf),
            "kvm" => Some(Accel::Kvm),
            "tcg" => Some(Accel::Tcg),
            _ => None,
        }
    }

    /// The fastest the host offers for a guest of `arch`.
    pub fn best(arch: Arch) -> Accel {
        if arch != Arch::host() {
            return Accel::Tcg;
        }
        if cfg!(target_os = "macos") {
            Accel::Hvf
        } else if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
        {
            Accel::Kvm
        } else {
            Accel::Tcg
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Accel::Hvf => "hvf",
            Accel::Kvm => "kvm",
            Accel::Tcg => "tcg",
        }
    }
}

/// A reply from the agent: `OK` with its `k=v` fields.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub line: String,
    pub kv: HashMap<String, String>,
}

impl Reply {
    fn parse(line: &str) -> Reply {
        let kv = line
            .split_whitespace()
            .filter_map(|w| w.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Reply {
            line: line.to_string(),
            kv,
        }
    }

    pub fn get(&self, k: &str) -> &str {
        self.kv.get(k).map_or("", String::as_str)
    }

    pub fn num(&self, k: &str) -> u64 {
        self.get(k).parse().unwrap_or(0)
    }

    pub fn flag(&self, k: &str) -> bool {
        self.get(k) == "1"
    }
}

/// The QEMU process, killed and reaped when dropped, whatever state it is
/// in: a boot that fails half-way must not leave it running.
#[derive(Debug)]
struct Qemu(Child);

impl Drop for Qemu {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        crate::guard::clear_qemu_pid();
    }
}

#[derive(Debug)]
pub struct Vm {
    child: Qemu,
    ctl: BufReader<TcpStream>,
    ctl_w: TcpStream,
    pub kernel: String,
    pub console_log: PathBuf,
    pub nic: Arc<qemu::Conn>,
    seq: u64,
}

fn accept_timeout<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
    t: Duration,
    what: &str,
) -> io::Result<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(t)
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("no {what}")))?
}

impl Vm {
    /// Boot the guest. QEMU writes its pid to `pidfile`, for the next run to
    /// find if this one is killed before it can clean up; its own messages
    /// go to `qemu.log` in `results`, not to our stderr, which a guest that
    /// outlived us would otherwise hold open (and whoever reads our output
    /// would wait on).
    pub fn boot(
        arch: Arch,
        accel: Accel,
        image: &Image,
        results: &Path,
        pidfile: &Path,
    ) -> io::Result<Vm> {
        let nic_ln = qemu::Listener::bind_tcp("127.0.0.1:0")?;
        let nic_port = nic_ln.local_addr()?.port();
        let ctl_ln = TcpListener::bind("127.0.0.1:0")?;
        let ctl_port = ctl_ln.local_addr()?.port();
        let console_log = results.join("console.log");
        let qemu_log = results.join("qemu.log");

        let (bin, machine, console) = match arch {
            Arch::Aarch64 => ("qemu-system-aarch64", "virt", "ttyAMA0"),
            Arch::X86_64 => ("qemu-system-x86_64", "q35", "ttyS0"),
        };
        let cpu = match accel {
            Accel::Tcg => "max",
            _ => "host",
        };
        let mut cmd = Command::new(bin);
        cmd.args(["-M", machine, "-accel", accel.name(), "-cpu", cpu])
            .args([
                "-smp", "2", "-m", "512", "-display", "none", "-monitor", "none",
            ])
            .args(["-no-reboot", "-nodefaults"])
            .arg("-kernel")
            .arg(&image.kernel)
            .arg("-initrd")
            .arg(&image.initrd)
            .arg("-append")
            .arg(format!("console={console} panic=-1 loglevel=4"))
            .arg("-serial")
            .arg(format!("file:{}", console_log.display()))
            .arg("-netdev")
            .arg(format!(
                "stream,id=n0,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={nic_port}"
            ))
            .arg("-device")
            .arg(format!("virtio-net-pci,netdev=n0,mac={GUEST_MAC},romfile="))
            .args(["-device", "virtio-serial-pci"])
            .arg("-chardev")
            .arg(format!(
                "socket,id=ctl,host=127.0.0.1,port={ctl_port},server=off"
            ))
            .args(["-device", "virtconsole,chardev=ctl"])
            .arg("-pidfile")
            .arg(pidfile)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(&qemu_log)?);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            // Whatever kills the harness, SIGKILL included, takes the
            // guest with it. The signal follows the thread that forked,
            // which is the main thread, there for the whole run.
            unsafe {
                cmd.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = Qemu(
            cmd.spawn()
                .map_err(|e| io::Error::other(format!("{bin}: {e}")))?,
        );
        crate::guard::set_qemu_pid(child.0.id());
        // A boot that fails because QEMU quit says why QEMU quit.
        let failed = |mut child: Qemu, e: io::Error| -> io::Error {
            if let Ok(Some(st)) = child.0.try_wait() {
                let log = std::fs::read_to_string(&qemu_log).unwrap_or_default();
                return io::Error::other(format!("QEMU exited ({st}): {}", log.trim()));
            }
            e
        };

        let boot_limit = match accel {
            Accel::Tcg => Duration::from_secs(300),
            _ => Duration::from_secs(60),
        };
        let nic = match accept_timeout(
            move || nic_ln.accept(),
            boot_limit,
            "NIC connection from QEMU",
        ) {
            Ok(n) => n,
            Err(e) => return Err(failed(child, e)),
        };
        let (ctl, _) = match accept_timeout(
            move || ctl_ln.accept(),
            boot_limit,
            "console connection from QEMU",
        ) {
            Ok(c) => c,
            Err(e) => return Err(failed(child, e)),
        };
        ctl.set_nodelay(true)?;
        let ctl_w = ctl.try_clone()?;
        let mut vm = Vm {
            child,
            ctl: BufReader::new(ctl),
            ctl_w,
            kernel: String::new(),
            console_log,
            nic,
            seq: 0,
        };
        let start = Instant::now();
        loop {
            let line = vm.read_line(boot_limit.saturating_sub(start.elapsed()))?;
            if let Some(rest) = line.strip_prefix("READY ") {
                vm.kernel = Reply::parse(rest).get("kernel").to_string();
                break;
            }
        }
        Ok(vm)
    }

    fn read_line(&mut self, limit: Duration) -> io::Result<String> {
        self.ctl
            .get_ref()
            .set_read_timeout(Some(limit.max(Duration::from_millis(1))))?;
        let mut line = String::new();
        match self.ctl.read_line(&mut line) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the agent's console closed (guest died?)",
            )),
            Ok(_) => Ok(line.trim_end().to_string()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Err(io::Error::new(io::ErrorKind::TimedOut, "agent timed out"))
            }
            Err(e) => Err(e),
        }
    }

    /// Send one command and wait up to `limit` for its reply. A timeout
    /// leaves the reply to come unread, so the connection is unusable
    /// after: the caller gives up on the guest.
    pub fn cmd(&mut self, line: &str, limit: Duration) -> Result<Reply, String> {
        self.seq += 1;
        let tag = format!("#{}", self.seq);
        writeln!(self.ctl_w, "{tag} {line}").map_err(|e| format!("agent: {e}"))?;
        let end = Instant::now() + limit;
        loop {
            let r = self
                .read_line(end.saturating_duration_since(Instant::now()))
                .map_err(|e| format!("`{line}`: {e}"))?;
            let Some((status, rest)) = r.split_once(' ') else {
                continue;
            };
            // A reply to an earlier command that timed out: skip it.
            let Some(rest) = rest
                .strip_prefix(&tag)
                .filter(|r| r.is_empty() || r.starts_with(' '))
            else {
                continue;
            };
            return match status {
                "OK" => Ok(Reply::parse(rest)),
                _ => Err(format!("`{line}`: {}", rest.trim())),
            };
        }
    }

    pub fn sysctl(&mut self, k: &str, v: &str) -> Result<(), String> {
        self.cmd(&format!("sysctl {k} {v}"), Duration::from_secs(5))
            .map(|_| ())
    }

    pub fn netstat(&mut self) -> Result<Reply, String> {
        self.cmd("netstat", Duration::from_secs(5))
    }

    /// Whether the guest is still there.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.0.try_wait(), Ok(None))
    }
}

impl Drop for Vm {
    /// Ask the guest to power off, and give it a moment; `Qemu`'s own drop
    /// then kills it if it has not.
    fn drop(&mut self) {
        let _ = writeln!(self.ctl_w, "quit");
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if let Ok(Some(_)) = self.child.0.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
