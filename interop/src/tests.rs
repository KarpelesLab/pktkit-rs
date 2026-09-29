//! The matrix. Each test says which way data goes: "vtcp→Linux" is the
//! vclient sending and the guest receiving, whichever end connected.

use crate::xfer::{self, Run, ServerMode};
use crate::{Ctx, Test};
use pktkit::impair::Impairment;
use pktkit::vtcp::{CongestionKind, EcnMode, Tuning};
use std::time::Duration;

const MIB: u64 = 1 << 20;

macro_rules! ensure {
    ($c:expr, $($fmt:tt)*) => {
        if !$c {
            return Err(format!($($fmt)*));
        }
    };
}

pub fn all() -> Vec<Test> {
    macro_rules! t {
        ($name:ident, $quick:expr) => {
            Test {
                name: stringify!($name),
                quick: $quick,
                run: $name,
            }
        };
    }
    vec![
        // Correctness.
        t!(bulk_vtcp_client_upload, true),
        t!(bulk_vtcp_client_download, true),
        t!(bulk_linux_client_upload, true),
        t!(bulk_linux_client_download, true),
        t!(rst_from_linux, true),
        t!(rst_from_vtcp, true),
        t!(refused_both_ways, true),
        t!(short_conns_vtcp_client, true),
        t!(short_conns_linux_client, true),
        t!(slirp_listener_linux_client, true),
        t!(slirp_nat_linux_client, true),
        // Negotiation.
        t!(options_vtcp_client, true),
        t!(options_linux_client, true),
        t!(options_all_off, true),
        t!(timestamps_off, false),
        t!(mss_guest_mtu_1280, true),
        t!(pmtud_icmp_vtcp_sender, true),
        t!(pmtud_icmp_linux_sender, true),
        t!(plpmtud_vtcp_sender, false),
        t!(plpmtud_linux_sender, false),
        t!(ecn_vtcp_client, true),
        t!(ecn_linux_client, true),
        t!(accecn_vtcp_client, true),
        t!(accecn_linux_client, true),
        t!(accecn_linux_client_vtcp_classic, false),
        t!(fastopen_linux_client, true),
        t!(fastopen_vtcp_client, true),
        t!(cc_bbr_vtcp_sender, true),
        t!(cc_bbr_linux_sender, true),
        // Impaired links.
        t!(impaired_delay_50ms_rtt, true),
        t!(impaired_loss_1pct, true),
        t!(impaired_reorder, false),
        t!(impaired_rate_ecn, false),
        t!(impaired_rate_droptail, false),
        t!(ramp_linux_cubic_sender, false),
    ]
}

/// The bulk size: 64 MiB, or 16 in the quick matrix.
fn big(ctx: &Ctx) -> u64 {
    if ctx.quick { 16 * MIB } else { 64 * MIB }
}

fn mbps(v: Option<f64>) -> String {
    v.map_or("-".into(), |m| format!("{m:.0} Mbit/s"))
}

fn expect_ok(r: &Run) -> Result<(), String> {
    ensure!(r.ok(), "transfer failed: {}", r.failure());
    Ok(())
}

fn rates(ctx: &mut Ctx, r: &Run) {
    let note = format!(
        "vtcp→Linux {}, Linux→vtcp {}",
        mbps(r.mbps_vc_to_linux()),
        mbps(r.mbps_linux_to_vc())
    );
    ctx.note(note);
}

// ---------------------------------------------------------------- correctness

fn bulk_vtcp_client_upload(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let n = big(ctx);
    let r = ctx.vc_to_linux(&c, "", n, MIB, false, ctx.limit(n, 20.0))?;
    expect_ok(&r)?;
    ensure!(
        r.linux.num("rx") == n,
        "Linux got {} of {n}",
        r.linux.num("rx")
    );
    rates(ctx, &r);
    ctx.note("half-close: the guest sent 1 MiB after the vclient's FIN");
    Ok(())
}

fn bulk_vtcp_client_download(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let n = big(ctx);
    let r = ctx.vc_to_linux(&c, "", 0, n, false, ctx.limit(n, 20.0))?;
    expect_ok(&r)?;
    rates(ctx, &r);
    Ok(())
}

fn bulk_linux_client_upload(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let n = big(ctx);
    let r = ctx.linux_to_vc(&c, "", n, MIB, ctx.limit(n, 20.0))?;
    expect_ok(&r)?;
    ensure!(r.vc.rx == n, "vclient got {} of {n}", r.vc.rx);
    rates(ctx, &r);
    ctx.note("half-close: the vclient sent 1 MiB after the guest's FIN");
    Ok(())
}

fn bulk_linux_client_download(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let n = big(ctx);
    let r = ctx.linux_to_vc(&c, "", 0, n, ctx.limit(n, 20.0))?;
    expect_ok(&r)?;
    rates(ctx, &r);
    Ok(())
}

/// The guest resets the connection after a byte: the vclient's reads
/// report it.
fn rst_from_linux(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let port = ctx.port();
    ctx.agent(&format!("listen {port} mode=rst"), Duration::from_secs(5))?;
    let vc = xfer::vc_client(&c, port, 1000, 0, 1, false, Duration::from_secs(10));
    let lx = ctx.agent(&format!("result {port} 10000"), Duration::from_secs(15))?;
    let _ = ctx.agent(&format!("unlisten {port}"), Duration::from_secs(5));
    ensure!(lx.flag("ok"), "guest: {}", lx.line);
    ensure!(
        vc.err.as_deref() == Some("ConnectionReset"),
        "vclient saw {:?}, not a reset",
        vc.err
    );
    let info = vc.info()?;
    ensure!(
        info.state == pktkit::vtcp::State::Closed,
        "vclient left in {:?}",
        info.state
    );
    Ok(())
}

/// The vclient drops a connection with data unread (RFC 2525 §2.17): the
/// guest's reads report a reset.
fn rst_from_vtcp(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let port = ctx.port();
    let srv = xfer::vc_server(
        &c,
        port,
        ServerMode::ResetOnData,
        0,
        1,
        1,
        Duration::from_secs(10),
    )
    .map_err(|e| e.to_string())?;
    let lx = ctx.agent(
        &format!(
            "connect {} {port} mode=hold send=1000 timeout=10000",
            xfer::host_ip()
        ),
        Duration::from_secs(20),
    )?;
    let vc = srv.join().map_err(|_| "server panicked")?;
    ensure!(vc.first().is_some_and(|v| v.rx_ok), "vclient: {vc:?}");
    ensure!(
        lx.get("end") == "ECONNRESET",
        "guest saw {}, not a reset",
        lx.get("end")
    );
    Ok(())
}

fn refused_both_ways(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let e = c
        .dial_tcp_timeout(xfer::guest_addr(9), Duration::from_secs(10))
        .err()
        .map(|e| e.kind());
    ensure!(
        e == Some(std::io::ErrorKind::ConnectionRefused),
        "vclient dial to a closed port: {e:?}"
    );
    let lx = ctx.agent(
        &format!("connect {} 9 timeout=10000", xfer::host_ip()),
        Duration::from_secs(20),
    )?;
    ensure!(
        lx.get("err") == "connect:ECONNREFUSED",
        "guest connect to a closed port: {}",
        lx.line
    );
    Ok(())
}

fn short_conns_count(ctx: &Ctx) -> u64 {
    if ctx.quick { 50 } else { 200 }
}

fn short_conns_vtcp_client(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let n = short_conns_count(ctx);
    let port = ctx.port();
    ctx.agent(
        &format!("listen {port} send=2000 seed=5"),
        Duration::from_secs(5),
    )?;
    let start = std::time::Instant::now();
    let mut bad = Vec::new();
    for _ in 0..n {
        let vc = xfer::vc_client(&c, port, 200, 2000, 5, false, Duration::from_secs(10));
        if !vc.ok() {
            bad.push(format!("{:?}", vc.err));
        }
        let lx = ctx.agent(&format!("result {port} 10000"), Duration::from_secs(15))?;
        if !lx.flag("ok") {
            bad.push(lx.line.clone());
        }
        if bad.len() > 3 {
            break;
        }
    }
    let _ = ctx.agent(&format!("unlisten {port}"), Duration::from_secs(5));
    ensure!(bad.is_empty(), "{} failed: {}", bad.len(), bad.join("; "));
    ctx.note(format!("{n} connections in {:.1?}", start.elapsed()));
    Ok(())
}

fn short_conns_linux_client(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let n = short_conns_count(ctx);
    let port = ctx.port();
    let srv = xfer::vc_server(
        &c,
        port,
        ServerMode::Sink,
        2000,
        5,
        n,
        Duration::from_secs(60),
    )
    .map_err(|e| e.to_string())?;
    let lx = ctx.agent(
        &format!(
            "connect {} {port} send=200 recv=2000 seed=5 count={n} timeout=10000",
            xfer::host_ip()
        ),
        Duration::from_secs(90),
    )?;
    let vc = srv.join().map_err(|_| "server panicked")?;
    let vc_bad = vc.iter().filter(|v| !v.ok()).count();
    ensure!(
        lx.num("good") == n && vc_bad == 0 && vc.len() as u64 == n,
        "guest: {} of {n} good ({}); vclient: {} served, {vc_bad} bad",
        lx.num("good"),
        lx.line,
        vc.len()
    );
    ctx.note(format!("{n} connections in {} ms", lx.num("total_ms")));
    Ok(())
}

/// slirp's virtual listener (`Stack::listen`), with Linux connecting: its
/// server side is vtcp too.
fn slirp_listener_linux_client(ctx: &mut Ctx) -> Result<(), String> {
    let st = ctx.net.station.swap_slirp(Tuning::default());
    let n = big(ctx);
    let port = ctx.port();
    let seed = 99;
    let l = st
        .listen("tcp", &format!("{}:{port}", xfer::host_ip()))
        .map_err(|e| format!("slirp listen: {e}"))?;
    let limit = ctx.limit(n, 20.0);
    let srv = xfer::slirp_server(l, MIB, seed, limit);
    let linux = ctx.agent(
        &format!(
            "connect {} {port} send={n} recv={MIB} seed={seed} timeout={}",
            xfer::host_ip(),
            limit.as_millis()
        ),
        limit + Duration::from_secs(15),
    )?;
    let vc = srv.join().map_err(|_| "slirp server panicked")?;
    let r = Run {
        vc,
        linux,
        c2s: n,
        s2c: MIB,
        vc_is_client: false,
    };
    expect_ok(&r)?;
    check_options(ctx, &r, true, true, true)?;
    rates(ctx, &r);
    Ok(())
}

/// slirp's NAT: Linux connects through it to a socket on this host, and
/// slirp relays the stream over a host connection of its own.
fn slirp_nat_linux_client(ctx: &mut Ctx) -> Result<(), String> {
    let Some(ip) = xfer::host_lan_ip() else {
        return Err(format!(
            "{} this host has no address but loopback",
            crate::SKIP
        ));
    };
    let st = ctx.net.station.swap_slirp(Tuning::default());
    let _ = &st;
    let host = std::net::TcpListener::bind((ip, 0)).map_err(|e| e.to_string())?;
    let port = host.local_addr().map_err(|e| e.to_string())?.port();
    let n = big(ctx) / 2;
    let seed = 77;
    let limit = ctx.limit(n, 20.0);
    let srv = xfer::host_server(host, n, seed, limit);
    let lx = ctx.agent(
        &format!(
            "connect {ip} {port} send={n} recv={n} seed={seed} timeout={}",
            limit.as_millis()
        ),
        limit + Duration::from_secs(15),
    )?;
    let host_rx = srv.join().map_err(|_| "host server panicked")??;
    ensure!(lx.flag("ok"), "guest: {}", lx.line);
    ensure!(host_rx == n, "host got {host_rx} of {n}");
    let us = lx.num("rx_us").max(1);
    ctx.note(format!(
        "{n} bytes each way through slirp to {ip}:{port}; slirp→Linux {:.0} Mbit/s; \
         negotiated ts={} sack={} wscale={} ({}/{}) mss {}",
        n as f64 * 8.0 / us as f64,
        lx.get("opt_ts"),
        lx.get("opt_sack"),
        lx.get("opt_wscale"),
        lx.get("snd_wscale"),
        lx.get("rcv_wscale"),
        lx.get("snd_mss"),
    ));
    Ok(())
}

// ---------------------------------------------------------------- negotiation

/// What both ends agreed on, compared: the options, window scale shifts
/// crossed over (one end's send shift is the other's receive shift), the
/// MSS, and windows past 64 KiB once data has flowed.
fn check_options(ctx: &mut Ctx, r: &Run, ts: bool, sack: bool, ws: bool) -> Result<(), String> {
    let vi = r.vc.info()?;
    let lx = &r.linux;
    ensure!(
        vi.timestamps == ts && lx.flag("opt_ts") == ts,
        "timestamps: vtcp {}, Linux {}, expected {ts}",
        vi.timestamps,
        lx.get("opt_ts")
    );
    ensure!(
        vi.sack == sack && lx.flag("opt_sack") == sack,
        "SACK: vtcp {}, Linux {}, expected {sack}",
        vi.sack,
        lx.get("opt_sack")
    );
    ensure!(
        vi.wscale.is_some() == ws && lx.flag("opt_wscale") == ws,
        "window scaling: vtcp {:?}, Linux {}, expected {ws}",
        vi.wscale,
        lx.get("opt_wscale")
    );
    if let Some((snd, rcv)) = vi.wscale {
        ensure!(
            u64::from(snd) == lx.num("rcv_wscale") && u64::from(rcv) == lx.num("snd_wscale"),
            "shifts disagree: vtcp snd {snd} rcv {rcv}, Linux snd {} rcv {}",
            lx.get("snd_wscale"),
            lx.get("rcv_wscale")
        );
    }
    // Linux's MSS excludes the timestamp option; vtcp's does not.
    let opt = if ts { 12 } else { 0 };
    ensure!(
        u64::from(vi.snd_mss) == lx.num("advmss") + opt,
        "MSS: vtcp sends with {}, Linux advertises {} (+{opt} options)",
        vi.snd_mss,
        lx.get("advmss")
    );
    ensure!(
        u64::from(vi.snd_mss) - opt == lx.num("snd_mss"),
        "MSS: Linux sends with {}, vtcp advertised {} (-{opt} options)",
        lx.get("snd_mss"),
        vi.snd_mss
    );
    let (vw, lw) = (vi.snd_wnd as u64, lx.num("snd_wnd"));
    if ws {
        ensure!(
            vw > 65535 && lw > 65535,
            "windows stayed under 64 KiB: vtcp's view {vw}, Linux's {lw}"
        );
    } else {
        ensure!(
            vw <= 65535 && lw <= 65535 && u64::from(vi.rcv_wnd) <= 65535,
            "windows past 64 KiB unscaled: vtcp's view {vw}, Linux's {lw}, vtcp rcv {}",
            vi.rcv_wnd
        );
    }
    ctx.note(format!(
        "ts={ts} sack={sack} wscale={:?} (Linux snd {} rcv {}), mss vtcp {} Linux {}, \
         windows: vtcp sees {vw}, Linux sees {lw}",
        vi.wscale,
        lx.get("snd_wscale"),
        lx.get("rcv_wscale"),
        vi.snd_mss,
        lx.get("snd_mss")
    ));
    Ok(())
}

fn options_vtcp_client(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let r = ctx.vc_to_linux(&c, "", 8 * MIB, 8 * MIB, false, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_options(ctx, &r, true, true, true)
}

fn options_linux_client(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let r = ctx.linux_to_vc(&c, "", 8 * MIB, 8 * MIB, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_options(ctx, &r, true, true, true)
}

/// The guest offers none of SACK, timestamps or window scaling: vtcp
/// must do without, both as client and as server.
fn options_all_off(ctx: &mut Ctx) -> Result<(), String> {
    ctx.sysctl("net.ipv4.tcp_sack", "0")?;
    ctx.sysctl("net.ipv4.tcp_timestamps", "0")?;
    ctx.sysctl("net.ipv4.tcp_window_scaling", "0")?;
    let c = ctx.client(Tuning::default());
    let r = ctx.vc_to_linux(&c, "", 4 * MIB, 4 * MIB, false, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_options(ctx, &r, false, false, false)?;
    let r = ctx.linux_to_vc(&c, "", 4 * MIB, 4 * MIB, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_options(ctx, &r, false, false, false)
}

fn timestamps_off(ctx: &mut Ctx) -> Result<(), String> {
    ctx.sysctl("net.ipv4.tcp_timestamps", "0")?;
    let c = ctx.client(Tuning::default());
    let r = ctx.vc_to_linux(&c, "", 4 * MIB, 4 * MIB, false, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_options(ctx, &r, false, true, true)?;
    let r = ctx.linux_to_vc(&c, "", 4 * MIB, 4 * MIB, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_options(ctx, &r, false, true, true)
}

/// A guest link of MTU 1280: each end sends segments that fit the other's
/// MSS.
fn mss_guest_mtu_1280(ctx: &mut Ctx) -> Result<(), String> {
    ctx.agent("mtu eth0 1280", Duration::from_secs(5))?;
    let c = ctx.client(Tuning::default());
    for vc_client in [true, false] {
        let r = if vc_client {
            ctx.vc_to_linux(&c, "", 4 * MIB, 4 * MIB, false, Duration::from_secs(60))?
        } else {
            ctx.linux_to_vc(&c, "", 4 * MIB, 4 * MIB, Duration::from_secs(60))?
        };
        expect_ok(&r)?;
        let vi = r.vc.info()?;
        ensure!(
            vi.snd_mss == 1240,
            "vtcp sends with MSS {}, not 1240",
            vi.snd_mss
        );
        ensure!(
            r.linux.num("advmss") == 1228 && r.linux.num("snd_mss") == 1228,
            "Linux: advmss {} snd_mss {} (want 1228: its own MTU bounds both)",
            r.linux.get("advmss"),
            r.linux.get("snd_mss")
        );
        ensure!(
            vi.rcv_mss <= 1228,
            "vtcp received segments of {} bytes",
            vi.rcv_mss
        );
    }
    ctx.note("vtcp sends with the guest's MSS 1240; the guest with its own MTU's");
    Ok(())
}

fn clamp(ctx: &mut Ctx, mtu: usize, icmp: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    ctx.net
        .narrow
        .set_clamp(Some(crate::net::Clamp { mtu, icmp }));
    ctx.net.narrow.dropped.store(0, Relaxed);
    ctx.net.narrow.icmp_sent.store(0, Relaxed);
    ctx.net.narrow.fragmented.store(0, Relaxed);
}

fn narrow_counts(ctx: &Ctx) -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        ctx.net.narrow.dropped.load(Relaxed),
        ctx.net.narrow.icmp_sent.load(Relaxed),
    )
}

/// A 1400-byte hop that acts as a router: a segment with DF set is
/// dropped and answered with ICMP, for which vtcp lowers its path MTU; one
/// without is fragmented, and the guest reassembles it.
fn pmtud_icmp_vtcp_sender(ctx: &mut Ctx) -> Result<(), String> {
    clamp(ctx, 1400, true);
    let c = ctx.client(Tuning::default());
    let r = ctx.vc_to_linux(&c, "", 8 * MIB, 0, false, Duration::from_secs(60))?;
    expect_ok(&r)?;
    let vi = r.vc.info()?;
    let (dropped, icmp) = narrow_counts(ctx);
    let frags = ctx
        .net
        .narrow
        .fragmented
        .load(std::sync::atomic::Ordering::Relaxed);
    ensure!(icmp > 0 || frags > 0, "nothing was too big");
    if icmp > 0 {
        ensure!(
            vi.path_mtu == 1400,
            "vtcp path MTU {}, not 1400",
            vi.path_mtu
        );
    }
    ctx.note(format!(
        "vtcp path MTU {}: {icmp} ICMP for {dropped} dropped (DF), {frags} segments \
         fragmented (no DF), {} retransmitted, {:.1?}",
        vi.path_mtu, vi.total_retrans, r.vc.elapsed
    ));
    Ok(())
}

fn pmtud_icmp_linux_sender(ctx: &mut Ctx) -> Result<(), String> {
    clamp(ctx, 1400, true);
    let c = ctx.client(Tuning::default());
    let r = ctx.vc_to_linux(&c, "", 0, 8 * MIB, false, Duration::from_secs(60))?;
    expect_ok(&r)?;
    let (_, icmp) = narrow_counts(ctx);
    ensure!(icmp > 0, "no ICMP sent");
    ensure!(
        r.linux.num("pmtu") == 1400,
        "Linux path MTU {}, not 1400",
        r.linux.get("pmtu")
    );
    ctx.note(format!(
        "Linux pmtu {} snd_mss {} after {icmp} ICMP",
        r.linux.get("pmtu"),
        r.linux.get("snd_mss")
    ));
    Ok(())
}

/// A 1400-byte hop that drops silently: vtcp finds the black hole and
/// probes its way up (RFC 4821).
fn plpmtud_vtcp_sender(ctx: &mut Ctx) -> Result<(), String> {
    clamp(ctx, 1400, false);
    let c = ctx.client(Tuning::default());
    let r = ctx.vc_to_linux(&c, "", 8 * MIB, 0, false, Duration::from_secs(120))?;
    expect_ok(&r)?;
    let vi = r.vc.info()?;
    let (dropped, _) = narrow_counts(ctx);
    ensure!(dropped > 0, "nothing was dropped");
    ensure!(
        vi.path_mtu <= 1400 && vi.path_mtu >= 1064,
        "vtcp path MTU {}",
        vi.path_mtu
    );
    ctx.note(format!(
        "vtcp settled on path MTU {} ({dropped} dropped, {} timeouts) in {:.1?}",
        vi.path_mtu, vi.timeouts, r.vc.elapsed
    ));
    Ok(())
}

fn plpmtud_linux_sender(ctx: &mut Ctx) -> Result<(), String> {
    ctx.sysctl("net.ipv4.tcp_mtu_probing", "1")?;
    clamp(ctx, 1400, false);
    let c = ctx.client(Tuning::default());
    let before = ctx.vm.netstat()?;
    let r = ctx.vc_to_linux(&c, "", 0, 8 * MIB, false, Duration::from_secs(120))?;
    let after = ctx.vm.netstat()?;
    expect_ok(&r)?;
    let (dropped, _) = narrow_counts(ctx);
    ctx.note(format!(
        "Linux pmtu {} snd_mss {} ({dropped} dropped, TCPMTUPSuccess +{}), {:.1?}",
        r.linux.get("pmtu"),
        r.linux.get("snd_mss"),
        after.num("TcpExt.TCPMTUPSuccess") - before.num("TcpExt.TCPMTUPSuccess"),
        r.vc.elapsed
    ));
    Ok(())
}

fn marking() -> Impairment {
    Impairment::default().ecn_mark(0.01).seed(42)
}

/// ECN agreed on by both ends, and working: CE marks each way reached the
/// receiver, were fed back, and the sender answered.
fn check_ecn(ctx: &mut Ctx, r: &Run, accurate: bool) -> Result<(), String> {
    let vi = r.vc.info()?;
    let lx = &r.linux;
    let want = if accurate {
        EcnMode::Accurate
    } else {
        EcnMode::Classic
    };
    ensure!(vi.ecn == want, "vtcp negotiated {:?}, not {want:?}", vi.ecn);
    ensure!(
        lx.flag("opt_ecn"),
        "Linux did not negotiate ECN: {}",
        lx.line
    );
    ensure!(lx.flag("opt_ecn_seen"), "Linux saw no ECT packets");
    ensure!(vi.ce_received > 0, "vtcp received no CE marks");
    // Linux counts AccECN's CE marks in ESTABLISHED alone (only
    // tcp_rcv_established calls tcp_ecn_received_counters, as of 7.1):
    // what vtcp sends a Linux client that has half-closed, in FIN-WAIT-2,
    // draws no feedback, marked or not.
    let fed_back = !accurate || r.vc_is_client;
    if !fed_back {
        ctx.note(
            "vtcp's data reached Linux in FIN-WAIT-2, where Linux counts no CE for AccECN: \
             not checked this way",
        );
    }
    ensure!(
        !fed_back || vi.ecn_reductions > 0,
        "vtcp never reduced for ECN (delivered_ce {})",
        vi.delivered_ce
    );
    // Linux 7.0 on report the mode: 1 classic (RFC 3168), 2 AccECN.
    let mode = lx.get("ecn_mode");
    ensure!(
        mode == "-1" || mode == if accurate { "2" } else { "1" },
        "Linux's ECN mode is {mode}"
    );
    if accurate {
        ensure!(
            lx.num("received_ce") > 0 || lx.num("delivered_ce") > 0,
            "Linux counted no CE with AccECN"
        );
        // The marks vtcp read from Linux's ACE fields are the marks Linux
        // counted receiving, give or take the odd stretch ACK taken to have
        // wrapped the counter. Linux counts those on vtcp's pure ACKs too,
        // which vtcp does not see fed back: slack for them.
        let seg = u64::from(vi.snd_mss - if vi.timestamps { 12 } else { 0 });
        let (read, sent) = (vi.delivered_ce.div_ceil(seg), lx.num("received_ce"));
        ensure!(
            !fed_back || (read > 0 && read <= sent * 3 / 2 + 8 && read * 2 + 8 >= sent),
            "vtcp read {read} CE marks from Linux's ACE fields; Linux counted {sent}"
        );
    }
    ctx.note(format!(
        "{want:?}: vtcp CE rcvd {} reductions {} delivered_ce {}; Linux received_ce {} \
         delivered_ce {} ecn_mode {} accecn_opt_seen {} fail_mode {}",
        vi.ce_received,
        vi.ecn_reductions,
        vi.delivered_ce,
        lx.get("received_ce"),
        lx.get("delivered_ce"),
        lx.get("ecn_mode"),
        lx.get("accecn_opt_seen"),
        lx.get("accecn_fail_mode"),
    ));
    Ok(())
}

fn ecn_vtcp_client(ctx: &mut Ctx) -> Result<(), String> {
    ctx.impair(marking());
    let c = ctx.client(Tuning::default().ecn(EcnMode::Classic));
    let r = ctx.vc_to_linux(&c, "", 8 * MIB, 8 * MIB, false, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_ecn(ctx, &r, false)
}

fn ecn_linux_client(ctx: &mut Ctx) -> Result<(), String> {
    ctx.sysctl("net.ipv4.tcp_ecn", "1")?;
    ctx.impair(marking());
    let c = ctx.client(Tuning::default());
    let r = ctx.linux_to_vc(&c, "", 8 * MIB, 8 * MIB, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_ecn(ctx, &r, false)
}

/// Switch the guest to AccECN, or skip: Linux takes `tcp_ecn = 3` only
/// from 7.0 (6.18 has the code, but caps the sysctl at 2).
fn accecn_on(ctx: &mut Ctx) -> Result<(), String> {
    ctx.sysctl("net.ipv4.tcp_ecn", "3").map_err(|e| {
        if e.contains("EINVAL") {
            format!(
                "{} Linux {} does not take tcp_ecn=3 (AccECN needs 7.0; try --kernel stable)",
                crate::SKIP,
                ctx.vm.kernel
            )
        } else {
            e
        }
    })
}

/// AccECN (RFC 9768), which Linux can do from 7.0 (`tcp_ecn = 3`).
fn accecn_vtcp_client(ctx: &mut Ctx) -> Result<(), String> {
    accecn_on(ctx)?;
    ctx.impair(marking());
    let c = ctx.client(Tuning::default().ecn(EcnMode::Accurate));
    let r = ctx.vc_to_linux(&c, "", 8 * MIB, 8 * MIB, false, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_ecn(ctx, &r, true)
}

fn accecn_linux_client(ctx: &mut Ctx) -> Result<(), String> {
    accecn_on(ctx)?;
    ctx.impair(marking());
    let c = ctx.client(Tuning::default().ecn(EcnMode::Accurate));
    let r = ctx.linux_to_vc(&c, "", 8 * MIB, 8 * MIB, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_ecn(ctx, &r, true)
}

/// A vtcp server that accepts only classic ECN answers an AccECN SYN with
/// a classic SYN-ACK, and the Linux client falls back (RFC 9768 §3.1.2).
fn accecn_linux_client_vtcp_classic(ctx: &mut Ctx) -> Result<(), String> {
    accecn_on(ctx)?;
    ctx.impair(marking());
    let c = ctx.client(Tuning::default().ecn(EcnMode::Passive));
    let r = ctx.linux_to_vc(&c, "", 8 * MIB, 8 * MIB, Duration::from_secs(60))?;
    expect_ok(&r)?;
    check_ecn(ctx, &r, false)
}

/// Linux as the Fast Open client: the first connection asks vtcp for a
/// cookie, the next ones send data in the SYN, which vtcp takes.
fn fastopen_linux_client(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default().fast_open(true));
    let port = ctx.port();
    let srv = xfer::vc_server(
        &c,
        port,
        ServerMode::Sink,
        500,
        11,
        3,
        Duration::from_secs(30),
    )
    .map_err(|e| e.to_string())?;
    let lx = ctx.agent(
        &format!(
            "connect {} {port} send=500 recv=500 seed=11 count=3 tfo=1 timeout=10000",
            xfer::host_ip()
        ),
        Duration::from_secs(40),
    )?;
    let vc = srv.join().map_err(|_| "server panicked")?;
    ensure!(lx.num("good") == 3, "guest: {}", lx.line);
    ensure!(
        vc.len() == 3 && vc.iter().all(|v| v.ok()),
        "vclient: {vc:?}"
    );
    let taken: Vec<bool> = vc
        .iter()
        .map(|v| v.info.as_ref().is_some_and(|i| i.syn_data))
        .collect();
    ensure!(
        lx.get("syn_data_seq") == "0,1,1" && taken == [false, true, true],
        "SYN data: Linux client says {}, vtcp server took {taken:?}",
        lx.get("syn_data_seq")
    );
    ctx.note("cookie on the first connection, data in the SYN on the next two, taken by vtcp");
    Ok(())
}

/// vtcp as the Fast Open client, to Linux's `TCP_FASTOPEN` listener.
fn fastopen_vtcp_client(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default().fast_open(true));
    let before = ctx.vm.netstat()?;
    let mut seen = Vec::new();
    for _ in 0..3 {
        let r = ctx.vc_to_linux(&c, "tfo=16", 500, 500, true, Duration::from_secs(10))?;
        expect_ok(&r)?;
        seen.push((r.vc.info()?.syn_data, r.linux.flag("opt_syn_data")));
    }
    let after = ctx.vm.netstat()?;
    let passive = after.num("TcpExt.TCPFastOpenPassive") - before.num("TcpExt.TCPFastOpenPassive");
    ensure!(
        seen == [(false, false), (true, true), (true, true)] && passive == 2,
        "SYN data (vtcp acked, Linux took) per connection: {seen:?}; TCPFastOpenPassive +{passive}"
    );
    ctx.note(format!(
        "cookie on the first connection, data in the SYN on the next two (TCPFastOpenPassive +{passive})"
    ));
    Ok(())
}

fn cc_bbr_vtcp_sender(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default().congestion(CongestionKind::Bbr));
    let n = big(ctx) / 2;
    let r = ctx.vc_to_linux(&c, "", n, 0, false, ctx.limit(n, 20.0))?;
    expect_ok(&r)?;
    let vi = r.vc.info()?;
    ensure!(vi.congestion == "bbr", "vtcp ran {}", vi.congestion);
    rates(ctx, &r);
    Ok(())
}

fn cc_bbr_linux_sender(ctx: &mut Ctx) -> Result<(), String> {
    let c = ctx.client(Tuning::default());
    let n = big(ctx) / 2;
    let r = ctx.vc_to_linux(&c, "cc=bbr", 0, n, false, ctx.limit(n, 20.0))?;
    expect_ok(&r)?;
    ensure!(
        r.linux.get("cc") == "bbr",
        "Linux ran {}",
        r.linux.get("cc")
    );
    rates(ctx, &r);
    Ok(())
}

// ---------------------------------------------------------------- impaired

/// Four transfers over the impaired link: each way, with CUBIC and with
/// BBR as the sender's controller, the vclient connecting. Reports the
/// throughput each achieved, and the retransmissions.
fn impaired(
    ctx: &mut Ctx,
    imp: Impairment,
    bytes: u64,
    ecn: bool,
    floor_mbps: f64,
) -> Result<(), String> {
    ctx.impair(imp);
    let mut fails = Vec::new();
    for (cc, lx_cc) in [
        (CongestionKind::Cubic, "cubic"),
        (CongestionKind::Bbr, "bbr"),
    ] {
        let mut t = Tuning::default().congestion(cc);
        if ecn {
            t = t.ecn(EcnMode::Classic);
        }
        let c = ctx.client(t);
        let limit = ctx.limit(bytes, floor_mbps);
        let up = ctx.vc_to_linux(&c, &format!("cc={lx_cc}"), bytes, 0, false, limit)?;
        let down = ctx.vc_to_linux(&c, &format!("cc={lx_cc}"), 0, bytes, false, limit)?;
        for (dir, r) in [("vtcp→Linux", &up), ("Linux→vtcp", &down)] {
            if !r.ok() {
                fails.push(format!("{lx_cc} {dir}: {}", r.failure()));
            }
        }
        let vi = up.vc.info().ok();
        ctx.note(format!(
            "{lx_cc:>5}: vtcp→Linux {:>12} (vtcp retrans {}, srtt {:?}{}), Linux→vtcp {:>12} (Linux retrans {}{})",
            mbps(up.mbps_vc_to_linux()),
            vi.map_or(0, |i| i.total_retrans),
            vi.and_then(|i| i.srtt).map(|d| Duration::from_micros(d.as_micros() as u64)),
            vi.filter(|_| ecn).map_or(String::new(), |i| format!(", ECN reductions {}", i.ecn_reductions)),
            mbps(down.mbps_linux_to_vc()),
            down.linux.get("total_retrans"),
            if ecn {
                format!(", delivered_ce {}", down.linux.get("delivered_ce"))
            } else {
                String::new()
            },
        ));
        // Where each sender's time went: a sender short of the path's
        // rate was held back by the receiver's window, or by its own
        // controller.
        let lx = &down.linux;
        ctx.note(format!(
            "       Linux sender: cwnd {} ssthresh {} busy {} ms, rwnd-limited {} ms, rtt {} us; \
             vtcp receiver: recv_buf grew to {}",
            lx.get("cwnd"),
            lx.get("ssthresh"),
            lx.num("busy_us") / 1000,
            lx.num("rwnd_limited_us") / 1000,
            lx.get("rtt_us"),
            down.vc.recv_buf_peak,
        ));
        if let Some(i) = vi {
            ctx.note(format!(
                "       vtcp sender: cwnd {} ssthresh {:?} busy {:?}, rwnd-limited {:?}, \
                 recoveries {} timeouts {} undos {}; Linux receiver rcv_wnd {}",
                i.cwnd,
                i.ssthresh,
                i.busy_time,
                i.rwnd_limited,
                i.recoveries,
                i.timeouts,
                i.undos,
                up.linux.get("rcv_wnd"),
            ));
        }
    }
    ensure!(fails.is_empty(), "{}", fails.join("; "));
    Ok(())
}

fn impaired_delay_50ms_rtt(ctx: &mut Ctx) -> Result<(), String> {
    let n = if ctx.quick { 8 * MIB } else { 16 * MIB };
    ctx.note("25 ms each way");
    // A queue deep enough for the delay line itself: 1024 packets (the
    // default) in 25 ms is only 490 Mbit/s, which a sender here outruns.
    let imp = Impairment::default()
        .delay(Duration::from_millis(25))
        .queue_limit(20_000);
    impaired(ctx, imp, n, false, 5.0)
}

fn impaired_loss_1pct(ctx: &mut Ctx) -> Result<(), String> {
    let n = if ctx.quick { 4 * MIB } else { 8 * MIB };
    // Mathis et al.: rate <= MSS/RTT * C/sqrt(p), C = 1.22 for Reno.
    let bound = 1448.0 * 8.0 / 0.020 * 1.22 / 0.01f64.sqrt() / 1e6;
    ctx.note(format!(
        "1% loss each way (data and ACKs), 10 ms each way; Reno's Mathis bound {bound:.1} Mbit/s"
    ));
    let imp = Impairment::default()
        .delay(Duration::from_millis(10))
        .loss(0.01)
        .seed(7);
    impaired(ctx, imp, n, false, 1.0)
}

fn impaired_reorder(ctx: &mut Ctx) -> Result<(), String> {
    ctx.note("10 ms each way plus up to 5 ms jitter: reordering");
    let imp = Impairment::default()
        .delay(Duration::from_millis(10))
        .jitter(Duration::from_millis(5))
        .seed(9);
    impaired(ctx, imp, 8 * MIB, false, 2.0)
}

fn impaired_rate_ecn(ctx: &mut Ctx) -> Result<(), String> {
    ctx.sysctl("net.ipv4.tcp_ecn", "1")?;
    // Marking past half the base round trip, as a classic AQM would; a
    // step at a millisecond or two, L4S-style, starves a sender that does
    // not pace (Linux's CUBIC without fq), whose every window goes out as
    // a burst and draws a mark each round trip.
    ctx.note("50 Mbit/s, 10 ms each way, CE past 10 ms of queue");
    let imp = Impairment::default()
        .delay(Duration::from_millis(10))
        .rate_bps(50_000_000)
        .ecn_threshold(Duration::from_millis(10));
    impaired(ctx, imp, 16 * MIB, true, 10.0)
}

fn impaired_rate_droptail(ctx: &mut Ctx) -> Result<(), String> {
    ctx.note("50 Mbit/s, 10 ms each way, 100-packet drop-tail queue");
    let imp = Impairment::default()
        .delay(Duration::from_millis(10))
        .rate_bps(50_000_000)
        .queue_limit(100);
    impaired(ctx, imp, 16 * MIB, false, 10.0)
}

/// How a Linux CUBIC sender ramps up towards vtcp over long paths with no
/// loss, next to vtcp's own CUBIC towards Linux: slow start should carry
/// either to the path's rate in a few round trips. HyStart (Linux's
/// `hystart_detect`) ends slow start early on a train of ACKs that comes
/// back too spread out, or on RTT samples that grow within a round, so a
/// receiver whose ACKs come late or in bursts caps its sender here.
fn ramp_linux_cubic_sender(ctx: &mut Ctx) -> Result<(), String> {
    let n = 16 * MIB;
    const KEYS: [&str; 4] = [
        "TcpExt.TCPHystartTrainDetect",
        "TcpExt.TCPHystartTrainCwnd",
        "TcpExt.TCPHystartDelayDetect",
        "TcpExt.TCPHystartDelayCwnd",
    ];
    let mut fails = Vec::new();
    for ms in [5u64, 25, 50] {
        ctx.impair(
            Impairment::default()
                .delay(Duration::from_millis(ms))
                .queue_limit(20_000),
        );
        let c = ctx.client(Tuning::default());
        let limit = ctx.limit(n, 5.0);
        let up = ctx.vc_to_linux(&c, "cc=cubic", n, 0, false, limit)?;
        let before = ctx.vm.netstat()?;
        let down = ctx.vc_to_linux(&c, "cc=cubic", 0, n, false, limit)?;
        let after = ctx.vm.netstat()?;
        for r in [&up, &down] {
            if !r.ok() {
                fails.push(format!("{ms} ms: {}", r.failure()));
            }
        }
        let d: Vec<u64> = KEYS
            .iter()
            .map(|k| after.num(k).saturating_sub(before.num(k)))
            .collect();
        let lx = &down.linux;
        ctx.note(format!(
            "RTT {:>3} ms: Linux→vtcp {:>12} (cwnd {} ssthresh {} rtt {} us, retrans {}), \
             vtcp→Linux {:>12}",
            2 * ms,
            mbps(down.mbps_linux_to_vc()),
            lx.get("cwnd"),
            lx.get("ssthresh"),
            lx.get("rtt_us"),
            lx.get("total_retrans"),
            mbps(up.mbps_vc_to_linux()),
        ));
        ctx.note(format!(
            "            HyStart train {} (cwnd {}), delay {} (cwnd {}); vtcp recv_buf grew to {}",
            d[0], d[1], d[2], d[3], down.vc.recv_buf_peak,
        ));
    }
    ensure!(fails.is_empty(), "{}", fails.join("; "));
    Ok(())
}
