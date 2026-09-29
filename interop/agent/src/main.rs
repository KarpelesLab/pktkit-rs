//! The interop guest agent: runs inside the Linux VM, takes orders from the
//! harness over a virtio console, one line each, and answers each with one
//! line, `OK k=v ...` or `ERR reason`.
//!
//! It drives the guest kernel's TCP stack the way the tests need: listeners
//! and clients moving a seeded byte stream (see `pattern.rs`) and checking
//! every byte, with the kernel's own view of each connection read back from
//! `TCP_INFO`, plus sysctls, the link MTU and the kernel's TCP counters.
//!
//! Commands:
//!
//! - `ping`
//! - `sysctl <name> [value]`: set (commas in `value` become spaces) and read
//!   back a `/proc/sys` entry.
//! - `mtu <dev> <mtu>`
//! - `netstat`: every non-zero `Tcp` and `TcpExt` counter.
//! - `listen <port> [cc=] [tfo=<qlen>] [mode=sink|rst|hold] [send=] [seed=]
//!   [rcvbuf=] [sndbuf=]`: serve connections in the background, each result
//!   queued for `result`.
//! - `result <port> <timeout_ms>`: the next finished connection's result.
//! - `unlisten <port>`
//! - `connect <ip> <port> [send=] [recv=] [seed=] [cc=] [tfo=1] [count=]
//!   [mode=bulk|rst|hold] [timeout=<ms>]`: run `count` client connections
//!   one after another.
//! - `quit`: power off.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the interop agent runs inside a Linux guest only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[path = "../../src/pattern.rs"]
#[allow(dead_code)]
mod pattern;

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use super::pattern::{Pattern, Verifier, reverse_seed};
    use std::collections::{HashMap, VecDeque};
    use std::fmt::Write as _;
    use std::fs::{File, OpenOptions};
    use std::io::{self, BufRead, BufReader, Write};
    use std::mem::{size_of, zeroed};
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    const TCP_FASTOPEN: libc::c_int = 23;
    const TCP_FASTOPEN_CONNECT: libc::c_int = 30;
    const TCP_CONGESTION: libc::c_int = 13;
    const TCP_INFO: libc::c_int = 11;
    const CHUNK: usize = 256 * 1024;

    /// `struct tcp_info` as of Linux 6.18 (include/uapi/linux/tcp.h). An
    /// older kernel fills in a prefix and leaves the rest zero.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct TcpInfo {
        state: u8,
        ca_state: u8,
        retransmits: u8,
        probes: u8,
        backoff: u8,
        options: u8,
        /// snd_wscale : 4, rcv_wscale : 4 (low bits first).
        wscale: u8,
        /// delivery_rate_app_limited : 1, fastopen_client_fail : 2.
        flags: u8,
        rto: u32,
        ato: u32,
        snd_mss: u32,
        rcv_mss: u32,
        unacked: u32,
        sacked: u32,
        lost: u32,
        retrans: u32,
        fackets: u32,
        last_data_sent: u32,
        last_ack_sent: u32,
        last_data_recv: u32,
        last_ack_recv: u32,
        pmtu: u32,
        rcv_ssthresh: u32,
        rtt: u32,
        rttvar: u32,
        snd_ssthresh: u32,
        snd_cwnd: u32,
        advmss: u32,
        reordering: u32,
        rcv_rtt: u32,
        rcv_space: u32,
        total_retrans: u32,
        pacing_rate: u64,
        max_pacing_rate: u64,
        bytes_acked: u64,
        bytes_received: u64,
        segs_out: u32,
        segs_in: u32,
        notsent_bytes: u32,
        min_rtt: u32,
        data_segs_in: u32,
        data_segs_out: u32,
        delivery_rate: u64,
        busy_time: u64,
        rwnd_limited: u64,
        sndbuf_limited: u64,
        delivered: u32,
        delivered_ce: u32,
        bytes_sent: u64,
        bytes_retrans: u64,
        dsack_dups: u32,
        reord_seen: u32,
        rcv_ooopack: u32,
        snd_wnd: u32,
        rcv_wnd: u32,
        rehash: u32,
        total_rto: u16,
        total_rto_recoveries: u16,
        total_rto_time: u32,
        received_ce: u32,
        delivered_e1_bytes: u32,
        delivered_e0_bytes: u32,
        delivered_ce_bytes: u32,
        received_e1_bytes: u32,
        received_e0_bytes: u32,
        received_ce_bytes: u32,
        /// Up to 6.19, `accecn_fail_mode: u16, accecn_opt_seen: u16`; from
        /// 7.0, `ecn_mode:2, accecn_opt_seen:2, accecn_fail_mode:4,
        /// options2:24`. Same size, so only the version tells them apart.
        ecn_tail: u32,
    }

    /// The kernel's major version, which `ecn_tail`'s layout depends on.
    fn kernel_major() -> u32 {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|r| r.split('.').next().and_then(|m| m.trim().parse().ok()))
            .unwrap_or(0)
    }

    /// `(ecn_mode, accecn_opt_seen, accecn_fail_mode)`; `ecn_mode` is -1
    /// before 7.0, which does not report it.
    fn ecn_tail(t: &TcpInfo) -> (i32, u32, u32) {
        let x = t.ecn_tail;
        if kernel_major() >= 7 {
            ((x & 3) as i32, (x >> 2) & 3, (x >> 4) & 0xf)
        } else {
            (-1, x >> 16, x & 0xffff)
        }
    }
    const _: () = assert!(size_of::<TcpInfo>() == 280);

    fn errno_name(e: &io::Error) -> String {
        let name = match e.raw_os_error() {
            Some(libc::ECONNRESET) => "ECONNRESET",
            Some(libc::ECONNREFUSED) => "ECONNREFUSED",
            Some(libc::ETIMEDOUT) => "ETIMEDOUT",
            Some(libc::EPIPE) => "EPIPE",
            Some(libc::EAGAIN) => "EAGAIN",
            Some(libc::EHOSTUNREACH) => "EHOSTUNREACH",
            Some(libc::ENOENT) => "ENOENT",
            Some(libc::EINVAL) => "EINVAL",
            Some(n) => return format!("errno{n}"),
            None => return e.kind().to_string().replace(' ', "_"),
        };
        name.to_string()
    }

    fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }

    fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, v: &T) -> io::Result<()> {
        let r = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                v as *const T as *const libc::c_void,
                size_of::<T>() as libc::socklen_t,
            )
        };
        cvt(r).map(|_| ())
    }

    fn set_int(fd: RawFd, level: libc::c_int, name: libc::c_int, v: libc::c_int) -> io::Result<()> {
        setsockopt(fd, level, name, &v)
    }

    fn set_cc(fd: RawFd, cc: &str) -> io::Result<()> {
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_CONGESTION,
                cc.as_ptr() as *const libc::c_void,
                cc.len() as libc::socklen_t,
            )
        };
        cvt(r).map(|_| ())
    }

    fn get_cc(fd: RawFd) -> String {
        let mut buf = [0u8; 16];
        let mut len = buf.len() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_CONGESTION,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if r < 0 {
            return "?".into();
        }
        let n = buf[..len as usize]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(len as usize);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    fn tcp_info(fd: RawFd) -> TcpInfo {
        let mut ti: TcpInfo = unsafe { zeroed() };
        let mut len = size_of::<TcpInfo>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_INFO,
                &mut ti as *mut TcpInfo as *mut libc::c_void,
                &mut len,
            );
        }
        ti
    }

    /// `TCP_INFO` as `k=v` pairs, under the names the harness reads.
    fn format_info(fd: RawFd) -> String {
        let t = tcp_info(fd);
        let o = t.options;
        let mut s = String::new();
        let _ = write!(
            s,
            "cc={} state={} ca_state={} opt_ts={} opt_sack={} opt_wscale={} opt_ecn={} \
             opt_ecn_seen={} opt_syn_data={} opt_tfo_child={} snd_wscale={} rcv_wscale={} \
             fo_client_fail={} rto_us={} snd_mss={} rcv_mss={} advmss={} pmtu={} rtt_us={} \
             rttvar_us={} min_rtt_us={} cwnd={} ssthresh={} total_retrans={} bytes_retrans={} \
             delivery_rate={} pacing_rate={} bytes_acked={} bytes_received={} bytes_sent={} \
             snd_wnd={} rcv_wnd={} rcv_space={} delivered={} delivered_ce={} received_ce={} \
             reord_seen={} dsack_dups={} rcv_ooopack={} total_rto={} segs_out={} segs_in={} \
             ecn_mode={} accecn_fail_mode={} accecn_opt_seen={} busy_us={} rwnd_limited_us={} \
             sndbuf_limited_us={}",
            get_cc(fd),
            t.state,
            t.ca_state,
            o & 1 != 0,
            o & 2 != 0,
            o & 4 != 0,
            o & 8 != 0,
            o & 16 != 0,
            o & 32 != 0,
            o & 128 != 0,
            t.wscale & 0xf,
            t.wscale >> 4,
            (t.flags >> 1) & 3,
            t.rto,
            t.snd_mss,
            t.rcv_mss,
            t.advmss,
            t.pmtu,
            t.rtt,
            t.rttvar,
            t.min_rtt,
            t.snd_cwnd,
            t.snd_ssthresh,
            t.total_retrans,
            t.bytes_retrans,
            t.delivery_rate,
            t.pacing_rate,
            t.bytes_acked,
            t.bytes_received,
            t.bytes_sent,
            t.snd_wnd,
            t.rcv_wnd,
            t.rcv_space,
            t.delivered,
            t.delivered_ce,
            t.received_ce,
            t.reord_seen,
            t.dsack_dups,
            t.rcv_ooopack,
            t.total_rto,
            t.segs_out,
            t.segs_in,
            ecn_tail(&t).0,
            ecn_tail(&t).2,
            ecn_tail(&t).1,
            t.busy_time,
            t.rwnd_limited,
            t.sndbuf_limited,
        );
        s.replace("true", "1").replace("false", "0")
    }

    /// Wait until everything written, the FIN included, is acknowledged,
    /// so the `TCP_INFO` taken after counts the whole transfer.
    fn wait_acked(fd: RawFd, limit: Duration) {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            let t = tcp_info(fd);
            // FIN-WAIT-2, TIME-WAIT or CLOSE: our FIN is acknowledged.
            if t.unacked == 0 && matches!(t.state, 5..=7) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn sock(fd: libc::c_int) -> io::Result<OwnedFd> {
        Ok(unsafe { OwnedFd::from_raw_fd(cvt(fd)?) })
    }

    fn sockaddr(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        let mut sa: libc::sockaddr_in = unsafe { zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from(ip).to_be();
        sa
    }

    fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(n as usize);
        }
    }

    fn write_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = unsafe {
                libc::send(
                    fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    fn send_pattern(fd: RawFd, seed: u64, mut n: u64) -> io::Result<()> {
        let mut p = Pattern::new(seed);
        let mut buf = vec![0u8; CHUNK];
        while n > 0 {
            let k = (n as usize).min(CHUNK);
            p.fill(&mut buf[..k]);
            write_all(fd, &buf[..k])?;
            n -= k as u64;
        }
        Ok(())
    }

    /// Read to EOF, checking the stream. The time is from the first byte.
    fn recv_pattern(fd: RawFd, seed: u64) -> (Verifier, Option<Duration>, Option<io::Error>) {
        let mut v = Verifier::new(seed);
        let mut buf = vec![0u8; CHUNK];
        let mut first = None;
        loop {
            match read_fd(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    first.get_or_insert_with(Instant::now);
                    v.update(&buf[..n]);
                }
                Err(e) => return (v, first.map(|f| f.elapsed()), Some(e)),
            }
        }
        (v, first.map(|f| f.elapsed()), None)
    }

    fn set_timeouts(fd: RawFd, t: Duration) {
        let tv = libc::timeval {
            tv_sec: t.as_secs() as _,
            tv_usec: t.subsec_micros() as _,
        };
        let _ = setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv);
        let _ = setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, &tv);
    }

    fn reset(fd: RawFd) {
        let l = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let _ = setsockopt(fd, libc::SOL_SOCKET, libc::SO_LINGER, &l);
    }

    type Args = HashMap<String, String>;

    fn num(a: &Args, k: &str, d: u64) -> u64 {
        a.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
    }

    struct Queue {
        results: Mutex<VecDeque<String>>,
        cv: Condvar,
    }

    struct Listening {
        fd: Arc<OwnedFd>,
        queue: Arc<Queue>,
    }

    /// One server connection, as `mode` says.
    fn serve_one(fd: OwnedFd, a: &Args) -> String {
        let raw = fd.as_raw_fd();
        let seed = num(a, "seed", 1);
        let send = num(a, "send", 0);
        let mode = a.get("mode").map_or("sink", String::as_str);
        set_timeouts(raw, Duration::from_millis(num(a, "timeout", 120_000)));
        let start = Instant::now();
        let mut out = String::new();
        match mode {
            // Read a byte, then abort: the peer sees a reset.
            "rst" => {
                let mut b = [0u8; 1];
                let r = read_fd(raw, &mut b);
                let info = format_info(raw);
                reset(raw);
                drop(fd);
                let _ = write!(out, "ok={} {info}", r.is_ok() as u8);
            }
            // Send `send` bytes, then read until the peer goes, and say how.
            "hold" => {
                let w = send_pattern(raw, reverse_seed(seed), send);
                let (v, _, err) = recv_pattern(raw, seed);
                let info = format_info(raw);
                let how = match (&w, &err) {
                    (_, Some(e)) => errno_name(e),
                    (Err(e), None) => errno_name(e),
                    _ => "eof".into(),
                };
                let _ = write!(out, "ok=1 rx={} end={how} {info}", v.len);
            }
            _ => {
                let (v, rx_time, err) = recv_pattern(raw, seed);
                let mut ok = err.is_none() && v.bad_at.is_none();
                let werr = if ok {
                    send_pattern(raw, reverse_seed(seed), send).err()
                } else {
                    None
                };
                ok &= werr.is_none();
                unsafe { libc::shutdown(raw, libc::SHUT_WR) };
                wait_acked(raw, Duration::from_secs(30));
                let info = format_info(raw);
                let _ = write!(
                    out,
                    "ok={} rx={} bad_at={} rx_us={} err={} {info}",
                    ok as u8,
                    v.len,
                    v.bad_at.map_or(-1, |b| b as i64),
                    rx_time.map_or(0, |d| d.as_micros()),
                    err.or(werr).as_ref().map_or("none".into(), errno_name),
                );
            }
        }
        let _ = write!(out, " ms={}", start.elapsed().as_millis());
        out
    }

    fn listen(a: &Args, port: u16) -> io::Result<Listening> {
        let fd = sock(unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) })?;
        let raw = fd.as_raw_fd();
        set_int(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        if let Some(cc) = a.get("cc") {
            set_cc(raw, cc)?;
        }
        if let Some(q) = a.get("tfo") {
            set_int(
                raw,
                libc::IPPROTO_TCP,
                TCP_FASTOPEN,
                q.parse().unwrap_or(16),
            )?;
        }
        if let Some(b) = a.get("rcvbuf") {
            set_int(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                b.parse().unwrap_or(0),
            )?;
        }
        if let Some(b) = a.get("sndbuf") {
            set_int(
                raw,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                b.parse().unwrap_or(0),
            )?;
        }
        let sa = sockaddr(Ipv4Addr::UNSPECIFIED, port);
        cvt(unsafe {
            libc::bind(
                raw,
                &sa as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        })?;
        cvt(unsafe { libc::listen(raw, 128) })?;
        let fd = Arc::new(fd);
        let queue = Arc::new(Queue {
            results: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        });
        let (lfd, q, args) = (fd.clone(), queue.clone(), a.clone());
        std::thread::spawn(move || {
            loop {
                let c = unsafe {
                    libc::accept4(
                        lfd.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_CLOEXEC,
                    )
                };
                let Ok(c) = sock(c) else {
                    // Shut down by `unlisten`.
                    return;
                };
                let (q, args) = (q.clone(), args.clone());
                std::thread::spawn(move || {
                    let r = serve_one(c, &args);
                    q.results.lock().unwrap().push_back(r);
                    q.cv.notify_all();
                });
            }
        });
        Ok(Listening { fd, queue })
    }

    /// One client connection. Returns whether it went as it should, and
    /// its report.
    fn client_one(ip: Ipv4Addr, port: u16, a: &Args, seed: u64) -> (bool, String) {
        let send = num(a, "send", 0);
        let recv = num(a, "recv", 0);
        let mode = a.get("mode").map_or("bulk", String::as_str);
        let start = Instant::now();
        let fd = match sock(unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) }) {
            Ok(fd) => fd,
            Err(e) => return (false, format!("ok=0 err={}", errno_name(&e))),
        };
        let raw = fd.as_raw_fd();
        set_timeouts(raw, Duration::from_millis(num(a, "timeout", 120_000)));
        if let Some(cc) = a.get("cc")
            && let Err(e) = set_cc(raw, cc)
        {
            return (false, format!("ok=0 err=cc:{}", errno_name(&e)));
        }
        if num(a, "tfo", 0) != 0 {
            let _ = set_int(raw, libc::IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1);
        }
        let sa = sockaddr(ip, port);
        if let Err(e) = cvt(unsafe {
            libc::connect(
                raw,
                &sa as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }) {
            return (false, format!("ok=0 err=connect:{}", errno_name(&e)));
        }
        let mut out = String::new();
        let ok = match mode {
            // Send, then read until the peer resets us.
            "rst" | "hold" => {
                let w = send_pattern(raw, seed, send);
                let (v, _, err) = recv_pattern(raw, reverse_seed(seed));
                let how = match (&w, &err) {
                    (_, Some(e)) => errno_name(e),
                    (Err(e), None) => errno_name(e),
                    _ => "eof".into(),
                };
                let info = format_info(raw);
                let _ = write!(out, "rx={} end={how} {info}", v.len);
                true
            }
            _ => {
                let werr = send_pattern(raw, seed, send).err();
                unsafe { libc::shutdown(raw, libc::SHUT_WR) };
                let (v, rx_time, err) = recv_pattern(raw, reverse_seed(seed));
                wait_acked(raw, Duration::from_secs(10));
                let ok = werr.is_none() && err.is_none() && v.ok(recv);
                let info = format_info(raw);
                let _ = write!(
                    out,
                    "rx={} bad_at={} rx_us={} err={} {info}",
                    v.len,
                    v.bad_at.map_or(-1, |b| b as i64),
                    rx_time.map_or(0, |d| d.as_micros()),
                    err.or(werr).as_ref().map_or("none".into(), errno_name),
                );
                ok
            }
        };
        let _ = write!(out, " ms={}", start.elapsed().as_millis());
        (ok, format!("ok={} {out}", ok as u8))
    }

    fn connect(words: &[&str], a: &Args) -> Result<String, String> {
        let ip: Ipv4Addr = words
            .first()
            .and_then(|s| s.parse().ok())
            .ok_or("usage: connect <ip> <port>")?;
        let port: u16 = words
            .get(1)
            .and_then(|s| s.parse().ok())
            .ok_or("usage: connect <ip> <port>")?;
        let count = num(a, "count", 1).max(1);
        let seed = num(a, "seed", 1);
        let start = Instant::now();
        let mut good = 0;
        let mut syn_data = String::new();
        let mut last = String::new();
        let mut first_bad = None;
        for i in 0..count {
            let (ok, r) = client_one(ip, port, a, seed.wrapping_add(i));
            good += ok as u64;
            if !syn_data.is_empty() {
                syn_data.push(',');
            }
            syn_data.push(if r.contains("opt_syn_data=1") {
                '1'
            } else {
                '0'
            });
            if !ok && first_bad.is_none() {
                first_bad = Some(r.clone());
            }
            last = r;
        }
        let report = first_bad.unwrap_or(last);
        Ok(format!(
            "good={good} count={count} total_ms={} syn_data_seq={syn_data} {report}",
            start.elapsed().as_millis()
        ))
    }

    fn sysctl(words: &[&str]) -> Result<String, String> {
        let name = words.first().ok_or("usage: sysctl <name> [value]")?;
        let path = format!("/proc/sys/{}", name.replace('.', "/"));
        if let Some(v) = words.get(1) {
            std::fs::write(&path, v.replace(',', " "))
                .map_err(|e| format!("{name}: {}", errno_name(&e)))?;
        }
        // Some entries (route.flush) can be written, not read.
        let v = match std::fs::read_to_string(&path) {
            Ok(v) => v,
            Err(_) if words.len() > 1 => words[1].to_string(),
            Err(e) => return Err(format!("{name}: {}", errno_name(&e))),
        };
        Ok(format!(
            "{name}={}",
            v.split_whitespace().collect::<Vec<_>>().join(",")
        ))
    }

    fn set_mtu(words: &[&str]) -> Result<String, String> {
        let (Some(dev), Some(mtu)) = (words.first(), words.get(1).and_then(|m| m.parse().ok()))
        else {
            return Err("usage: mtu <dev> <mtu>".into());
        };
        let fd = sock(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) })
            .map_err(|e| errno_name(&e))?;
        let mut ifr: libc::ifreq = unsafe { zeroed() };
        for (d, s) in ifr.ifr_name.iter_mut().zip(dev.bytes()) {
            *d = s as libc::c_char;
        }
        ifr.ifr_ifru.ifru_mtu = mtu;
        cvt(unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFMTU as _, &ifr) })
            .map_err(|e| errno_name(&e))?;
        Ok(format!("mtu={mtu}"))
    }

    /// Every non-zero counter of the `Tcp` and `TcpExt` groups.
    fn netstat() -> Result<String, String> {
        let mut out = String::new();
        for file in ["/proc/net/snmp", "/proc/net/netstat"] {
            let text = std::fs::read_to_string(file).map_err(|e| errno_name(&e))?;
            let lines: Vec<&str> = text.lines().collect();
            for pair in lines.chunks(2) {
                let [names, values] = pair else { continue };
                let (Some((g, names)), Some((_, values))) =
                    (names.split_once(": "), values.split_once(": "))
                else {
                    continue;
                };
                if g != "Tcp" && g != "TcpExt" {
                    continue;
                }
                for (n, v) in names.split(' ').zip(values.split(' ')) {
                    if v != "0" {
                        let _ = write!(out, "{g}.{n}={v} ");
                    }
                }
            }
        }
        Ok(out.trim_end().to_string())
    }

    fn parse(line: &str) -> (&str, Vec<&str>, Args) {
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let mut words = Vec::new();
        let mut args = Args::new();
        for w in it {
            match w.split_once('=') {
                Some((k, v)) => {
                    args.insert(k.to_string(), v.to_string());
                }
                None => words.push(w),
            }
        }
        (cmd, words, args)
    }

    /// Put the console in raw mode: no echo, no line editing, no CR/LF
    /// translation, which would each garble the protocol.
    fn raw_mode(fd: RawFd) {
        unsafe {
            let mut t: libc::termios = zeroed();
            if libc::tcgetattr(fd, &mut t) == 0 {
                libc::cfmakeraw(&mut t);
                libc::tcsetattr(fd, libc::TCSANOW, &t);
            }
        }
    }

    pub fn main() {
        let path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "/dev/hvc0".into());
        let mut tries = 0;
        let ctl: File = loop {
            match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => break f,
                // The device appears once virtio_console has probed.
                Err(_) if tries < 50 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => panic!("open {path}: {e}"),
            }
        };
        raw_mode(ctl.as_raw_fd());
        let mut out = ctl.try_clone().unwrap();
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let _ = writeln!(out, "READY kernel={}", release.trim());
        let mut listeners: HashMap<u16, Listening> = HashMap::new();
        for line in BufReader::new(ctl).lines() {
            let Ok(line) = line else { break };
            // A leading `#tag` is echoed in the reply, so the harness can
            // tell it from a late reply to a command it gave up on.
            let line = line.trim();
            let (tag, line) = match line.split_once(' ') {
                Some((t, rest)) if t.starts_with('#') => (t, rest),
                _ => ("", line),
            };
            let (cmd, words, args) = parse(line);
            let r: Result<String, String> = match cmd {
                "" => continue,
                "ping" => Ok("pong".into()),
                "sysctl" => sysctl(&words),
                "mtu" => set_mtu(&words),
                "netstat" => netstat(),
                "listen" => match words.first().and_then(|p| p.parse::<u16>().ok()) {
                    None => Err("usage: listen <port>".into()),
                    Some(port) => {
                        if let Some(old) = listeners.remove(&port) {
                            unsafe { libc::shutdown(old.fd.as_raw_fd(), libc::SHUT_RDWR) };
                        }
                        match listen(&args, port) {
                            Ok(l) => {
                                listeners.insert(port, l);
                                Ok(format!("port={port}"))
                            }
                            Err(e) => Err(errno_name(&e)),
                        }
                    }
                },
                "unlisten" => match words.first().and_then(|p| p.parse::<u16>().ok()) {
                    Some(port) => {
                        if let Some(old) = listeners.remove(&port) {
                            unsafe { libc::shutdown(old.fd.as_raw_fd(), libc::SHUT_RDWR) };
                        }
                        Ok(format!("port={port}"))
                    }
                    None => Err("usage: unlisten <port>".into()),
                },
                "result" => {
                    let port = words.first().and_then(|p| p.parse::<u16>().ok());
                    let wait = Duration::from_millis(
                        words.get(1).and_then(|t| t.parse().ok()).unwrap_or(30_000),
                    );
                    match port.and_then(|p| listeners.get(&p)) {
                        None => Err("no such listener".into()),
                        Some(l) => {
                            let q = &l.queue;
                            let g = q.results.lock().unwrap();
                            let (mut g, _) =
                                q.cv.wait_timeout_while(g, wait, |r| r.is_empty()).unwrap();
                            g.pop_front().ok_or_else(|| "timeout".to_string())
                        }
                    }
                }
                "connect" => connect(&words, &args),
                "quit" => {
                    let _ = writeln!(out, "OK bye");
                    unsafe {
                        libc::sync();
                        libc::reboot(libc::RB_POWER_OFF);
                    }
                    return;
                }
                _ => Err(format!("unknown command {cmd}")),
            };
            let _ = match r {
                Ok(s) => writeln!(out, "OK {tag} {s}"),
                Err(e) => writeln!(out, "ERR {tag} {}", e.replace('\n', " ")),
            };
            let _ = out.flush();
        }
    }
}
