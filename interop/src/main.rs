//! Interoperability tests of pktkit's TCP engine (vtcp, through vclient
//! and slirp) against the Linux kernel's TCP, in a QEMU guest. See
//! README.md.

mod guard;
mod image;
mod net;
mod pattern;
mod tests;
mod vm;
mod xfer;

use image::{Arch, Kernel};
use net::Net;
use pktkit::impair::Impairment;
use pktkit::vclient::{Client, ClientConfig};
use pktkit::vtcp::Tuning;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vm::{Accel, Reply, Vm};
use xfer::{Run, ServerMode, VcEnd};

/// The guest's TCP settings at the start of every test, which a test
/// changes as it needs: the kernel's defaults, but with Fast Open on for
/// both roles, as the Fast Open tests need a server-side cookie secret
/// from boot.
const LINUX_DEFAULTS: &[(&str, &str)] = &[
    ("net.ipv4.tcp_ecn", "2"),
    ("net.ipv4.tcp_sack", "1"),
    ("net.ipv4.tcp_timestamps", "1"),
    ("net.ipv4.tcp_window_scaling", "1"),
    ("net.ipv4.tcp_mtu_probing", "0"),
    ("net.ipv4.tcp_fastopen", "3"),
    ("net.ipv4.tcp_congestion_control", "cubic"),
    ("net.ipv4.tcp_no_metrics_save", "1"),
    // Sized for the fast link: 64 MiB transfers should not be held back by
    // the guest's buffers any more than by the kernel's defaults elsewhere.
    ("net.core.rmem_max", "33554432"),
    ("net.core.wmem_max", "33554432"),
    ("net.ipv4.tcp_rmem", "4096,131072,33554432"),
    ("net.ipv4.tcp_wmem", "4096,65536,33554432"),
];

pub struct Ctx {
    pub vm: Vm,
    pub net: Net,
    pub quick: bool,
    port: u16,
    /// Lines for the report, besides pass or fail.
    pub notes: Vec<String>,
}

impl Ctx {
    /// A fresh port for each listener: a vclient keeps TIME-WAIT, and so
    /// does the guest.
    pub fn port(&mut self) -> u16 {
        self.port += 1;
        self.port
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    /// A vclient with these TCP settings in place of the last one.
    pub fn client(&mut self, tcp: Tuning) -> Arc<Client> {
        self.net.station.swap(ClientConfig::default().tcp(tcp))
    }

    pub fn agent(&mut self, cmd: &str, limit: Duration) -> Result<Reply, String> {
        self.vm.cmd(cmd, limit)
    }

    pub fn sysctl(&mut self, k: &str, v: &str) -> Result<(), String> {
        self.vm.sysctl(k, v)
    }

    pub fn impair(&mut self, i: Impairment) {
        self.net.impair.set_impairment(i);
    }

    /// The limit for a transfer of `bytes` at no less than `mbps`.
    pub fn limit(&self, bytes: u64, mbps: f64) -> Duration {
        Duration::from_secs_f64(20.0 + bytes as f64 * 8.0 / (mbps * 1e6))
    }

    fn reset(&mut self) -> Result<(), String> {
        self.net.impair.set_impairment(Impairment::default());
        self.net.narrow.set_clamp(None);
        for (k, v) in LINUX_DEFAULTS {
            self.vm.sysctl(k, v)?;
        }
        self.vm.cmd("mtu eth0 1500", Duration::from_secs(5))?;
        // Forget the path MTUs ICMP taught the guest, which outlive the
        // test (for ten minutes) in its route cache.
        self.vm.sysctl("net.ipv4.route.flush", "1")?;
        Ok(())
    }

    /// The vclient connects to a guest listener: it sends `c2s` bytes and
    /// half-closes, the guest sends `s2c` bytes back after EOF. `lx` is
    /// extra arguments for the guest's `listen`.
    pub fn vc_to_linux(
        &mut self,
        client: &Client,
        lx: &str,
        c2s: u64,
        s2c: u64,
        fast_open: bool,
        limit: Duration,
    ) -> Result<Run, String> {
        let port = self.port();
        let seed = port as u64 * 7919;
        self.agent(
            &format!(
                "listen {port} send={s2c} seed={seed} timeout={} {lx}",
                limit.as_millis()
            ),
            Duration::from_secs(5),
        )?;
        let vc = xfer::vc_client(client, port, c2s, s2c, seed, fast_open, limit);
        let linux = self.agent(&format!("result {port} 15000"), Duration::from_secs(20));
        let _ = self.agent(&format!("unlisten {port}"), Duration::from_secs(5));
        let linux = match linux {
            Ok(r) => r,
            Err(e) => return Err(format!("{e}; vclient: {:?}", vc.err)),
        };
        Ok(Run {
            vc,
            linux,
            c2s,
            s2c,
            vc_is_client: true,
        })
    }

    /// The guest connects to a vclient listener: it sends `c2s` bytes and
    /// half-closes, the vclient sends `s2c` back after EOF. `lx` is extra
    /// arguments for the guest's `connect`.
    pub fn linux_to_vc(
        &mut self,
        client: &Arc<Client>,
        lx: &str,
        c2s: u64,
        s2c: u64,
        limit: Duration,
    ) -> Result<Run, String> {
        let port = self.port();
        let seed = port as u64 * 7919;
        let srv = xfer::vc_server(client, port, ServerMode::Sink, s2c, seed, 1, limit)
            .map_err(|e| format!("listen: {e}"))?;
        let linux = self.agent(
            &format!(
                "connect {} {port} send={c2s} recv={s2c} seed={seed} timeout={} {lx}",
                xfer::host_ip(),
                limit.as_millis()
            ),
            limit + Duration::from_secs(15),
        )?;
        let vc = srv
            .join()
            .map_err(|_| "vclient server panicked".to_string())?
            .pop()
            .unwrap_or_else(|| VcEnd {
                rx: 0,
                rx_ok: false,
                bad_at: None,
                rx_time: None,
                elapsed: Duration::ZERO,
                err: Some("no connection".into()),
                info: None,
            });
        Ok(Run {
            vc,
            linux,
            c2s,
            s2c,
            vc_is_client: false,
        })
    }
}

/// An error starting with this skips the test rather than failing it:
/// what it needs is not there (a kernel feature, say).
pub const SKIP: &str = "skip:";

pub type TestFn = fn(&mut Ctx) -> Result<(), String>;

pub struct Test {
    pub name: &'static str,
    /// Part of the CI subset.
    pub quick: bool,
    pub run: TestFn,
}

struct Opts {
    arch: Arch,
    kernel: Kernel,
    accel: Option<Accel>,
    quick: bool,
    filter: Vec<String>,
    keep_pcaps: bool,
    list: bool,
    /// The whole run's limit, after which the watchdog ends it.
    deadline: Option<Duration>,
}

/// How long one test may take before the watchdog gives up on it: well
/// past any test's own limits, which cover everything it waits for.
const TEST_LIMIT: Duration = Duration::from_secs(600);

fn usage() -> ! {
    eprintln!(
        "usage: interop [--arch aarch64|x86_64] [--kernel lts|stable] [--accel hvf|kvm|tcg] [--quick] \
         [--keep-pcaps] [--deadline SECS] [--list] [FILTER...]"
    );
    std::process::exit(2);
}

fn opts() -> Opts {
    let mut o = Opts {
        arch: Arch::host(),
        kernel: Kernel::Lts,
        accel: None,
        quick: false,
        filter: Vec::new(),
        keep_pcaps: false,
        list: false,
        deadline: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--arch" => {
                o.arch = args
                    .next()
                    .and_then(|s| Arch::parse(&s))
                    .unwrap_or_else(|| usage())
            }
            "--accel" => {
                o.accel = Some(
                    args.next()
                        .and_then(|s| Accel::parse(&s))
                        .unwrap_or_else(|| usage()),
                )
            }
            "--kernel" => {
                o.kernel = args
                    .next()
                    .and_then(|s| Kernel::parse(&s))
                    .unwrap_or_else(|| usage())
            }
            "--quick" => o.quick = true,
            "--keep-pcaps" => o.keep_pcaps = true,
            "--list" => o.list = true,
            "--deadline" => {
                o.deadline = Some(Duration::from_secs(
                    args.next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| usage()),
                ))
            }
            "-h" | "--help" => usage(),
            f if f.starts_with('-') => usage(),
            f => o.filter.push(f.to_string()),
        }
    }
    o
}

fn main() {
    guard::install_signal_handlers();
    // Everything the run owns, the guest included, is dropped by the time
    // `run` returns; `process::exit` would skip that.
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let o = opts();
    let all = tests::all();
    let chosen: Vec<&Test> = all
        .iter()
        .filter(|t| !o.quick || t.quick)
        .filter(|t| o.filter.is_empty() || o.filter.iter().any(|f| t.name.contains(f.as_str())))
        .collect();
    if o.list {
        for t in &chosen {
            println!("{}", t.name);
        }
        return 0;
    }
    if chosen.is_empty() {
        eprintln!("no test matches");
        return 2;
    }
    let accel = o.accel.unwrap_or_else(|| Accel::best(o.arch));
    let dir = image::root()
        .join("target")
        .join("results")
        .join(o.arch.name());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("results directory");
    let pidfile = image::root()
        .join("target")
        .join(format!("qemu-{}.pid", o.arch.name()));
    guard::kill_stale(&pidfile);

    let progress = Arc::new(Mutex::new(guard::Progress::default()));
    let deadline = o.deadline.unwrap_or(if o.quick {
        Duration::from_secs(15 * 60)
    } else {
        Duration::from_secs(90 * 60)
    });
    guard::watchdog(
        progress.clone(),
        Instant::now() + deadline,
        &dir.join("report.txt"),
    );

    let t0 = Instant::now();
    let img = match image::build(o.arch, o.kernel) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("image: {e}");
            return 1;
        }
    };
    eprintln!(
        "image: {} ({}), built in {:.1?}",
        img.kernel_pkg,
        o.arch.name(),
        t0.elapsed()
    );
    let t0 = Instant::now();
    let vm = match Vm::boot(o.arch, accel, &img, &dir, &pidfile) {
        Ok(vm) => vm,
        Err(e) => {
            eprintln!(
                "boot ({}): {e}; see {}",
                accel.name(),
                dir.join("console.log").display()
            );
            return 1;
        }
    };
    eprintln!(
        "guest: Linux {} on {} ({}), up in {:.1?}",
        vm.kernel,
        o.arch.name(),
        accel.name(),
        t0.elapsed()
    );
    let net = Net::new(vm.nic.clone());
    let mut ctx = Ctx {
        vm,
        net,
        quick: o.quick,
        port: 20000,
        notes: Vec::new(),
    };

    let mut report = String::new();
    let _ = writeln!(
        report,
        "pktkit interop: Linux {} ({}, {}), {}",
        ctx.vm.kernel,
        o.arch.name(),
        accel.name(),
        if o.quick {
            "quick matrix"
        } else {
            "full matrix"
        }
    );
    let mut failed = 0;
    let mut skipped = 0;
    // What the watchdog writes out if it has to end the run.
    let checkpoint = |report: &str, test: Option<&'static str>| {
        let mut p = progress.lock().unwrap_or_else(|e| e.into_inner());
        p.report = report.to_string();
        p.test = test.map(|t| (t, Instant::now() + TEST_LIMIT));
    };
    for t in &chosen {
        checkpoint(&report, Some(t.name));
        let pcap = dir.join(format!("{}.pcap", t.name));
        let _ = ctx.net.station.capture(Some(&pcap));
        ctx.notes.clear();
        let start = Instant::now();
        eprintln!("--- {}", t.name);
        // A test that panics fails, and the run goes on to the next.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ctx.reset().and_then(|()| (t.run)(&mut ctx))
        }))
        .unwrap_or_else(|p| {
            let msg = p
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| p.downcast_ref::<&str>().copied())
                .unwrap_or("?");
            Err(format!("panicked: {msg}"))
        });
        let _ = ctx.net.station.capture(None);
        let took = start.elapsed();
        let (status, keep) = match &r {
            Ok(()) => ("PASS", o.keep_pcaps),
            Err(e) if e.starts_with(SKIP) => {
                skipped += 1;
                ("SKIP", o.keep_pcaps)
            }
            Err(_) => {
                failed += 1;
                ("FAIL", true)
            }
        };
        if !keep {
            let _ = std::fs::remove_file(&pcap);
        }
        let line = format!("{status} {:<34} {:>6.1}s", t.name, took.as_secs_f64());
        eprintln!("{line}");
        let _ = writeln!(report, "{line}");
        if let Err(e) = &r {
            let e = e
                .strip_prefix(SKIP)
                .map_or(format!("error: {e}"), |s| s.trim().to_string());
            eprintln!("     {e}");
            let _ = writeln!(report, "     {e}");
        }
        for n in &ctx.notes {
            eprintln!("     {n}");
            let _ = writeln!(report, "     {n}");
        }
        if !ctx.vm.alive() {
            let _ = writeln!(report, "the guest died; see console.log");
            eprintln!("the guest died; see {}", ctx.vm.console_log.display());
            failed += 1;
            break;
        }
    }
    let _ = writeln!(
        report,
        "{} of {} passed, {skipped} skipped",
        chosen.len() - (failed + skipped).min(chosen.len()),
        chosen.len()
    );
    checkpoint(&report, None);
    let _ = std::fs::write(dir.join("report.txt"), &report);
    println!("{report}");
    println!("results: {}", dir.display());
    // Power the guest off now, rather than leave it to the end of `main`.
    drop(ctx);
    if failed > 0 { 1 } else { 0 }
}
