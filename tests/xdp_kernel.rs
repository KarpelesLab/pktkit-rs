//! Tests that need a kernel: the eBPF verifier, real maps, a real interface.
//!
//! All of these are `#[ignore]`d because they need `CAP_BPF` + `CAP_NET_ADMIN`
//! (in practice, root). Run them with:
//!
//! ```sh
//! sudo -E cargo test --features afxdp --test xdp_kernel -- --ignored --test-threads=1
//! ```
//!
//! The unit tests cover encoding and layout; these cover the two things only a
//! kernel can answer — whether the generated program passes the verifier, and
//! whether the trie keys we build actually match the way we expect.
#![cfg(all(feature = "afxdp", target_os = "linux"))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pktkit::afxdp::{Config, Device, ProgramSource, Zerocopy};
use pktkit::xdp::{
    Action, Capture, CaptureConfig, CaptureMaps, MAX_RULES_PER_PREFIX, Map, MatchField, Mode,
    Program, Rule, build_program,
};
use pktkit::{EtherType, Frame, IpPrefix, L2Device, Protocol};

/// True when this process can actually exercise the kernel paths.
///
/// The `#[ignore]`d tests below must not quietly no-op: a test that skips looks
/// exactly like a test that passed. So the only tolerated reason to skip is
/// "not running as root"; once we are root, every failure is a real failure.
fn root() -> bool {
    // SAFETY: geteuid cannot fail and touches no memory we own.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    eprintln!("SKIP: needs root; re-run with sudo -E cargo test ... -- --ignored");
    false
}

/// veth pair + netns, torn down on drop.
struct Veth {
    ns: String,
    host: String,
    peer: String,
}

impl Veth {
    /// Panics rather than skipping: callers have already established that we
    /// are root, so a failure here is iproute2 missing or a real bug.
    fn new(tag: &str) -> Veth {
        let v = Veth {
            ns: format!("pk-{tag}"),
            host: format!("pkh-{tag}"),
            peer: format!("pkp-{tag}"),
        };
        // Clear anything a previously killed run left behind.
        v.teardown();

        assert!(
            ip(&["netns", "add", &v.ns]),
            "ip netns add (iproute2 present?)"
        );
        assert!(
            ip(&[
                "link", "add", &v.host, "type", "veth", "peer", "name", &v.peer, "netns", &v.ns,
            ]),
            "ip link add veth"
        );
        assert!(ip(&["addr", "add", "10.99.0.1/24", "dev", &v.host]));
        assert!(ip(&["link", "set", &v.host, "up"]));
        assert!(v.ip_ns(&["addr", "add", "10.99.0.2/24", "dev", &v.peer]));
        assert!(v.ip_ns(&["link", "set", &v.peer, "up"]));
        v
    }

    fn host_mac(&self) -> String {
        let out = Command::new("cat")
            .arg(format!("/sys/class/net/{}/address", self.host))
            .output()
            .expect("read mac");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// `ip -n <ns> <args>`: an ip(8) subcommand against the peer's namespace.
    fn ip_ns(&self, args: &[&str]) -> bool {
        let mut v = vec!["-n", self.ns.as_str()];
        v.extend_from_slice(args);
        ip(&v)
    }

    /// `ip netns exec <ns> <args>`: an arbitrary command inside the namespace.
    fn exec(&self, args: &[&str]) -> bool {
        let mut v = vec!["netns", "exec", self.ns.as_str()];
        v.extend_from_slice(args);
        ip(&v)
    }

    fn teardown(&self) {
        ip(&["link", "del", &self.host]);
        ip(&["netns", "del", &self.ns]);
    }
}

impl Drop for Veth {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn v4(a: [u8; 4], bits: u8) -> IpPrefix {
    IpPrefix::new(Ipv4Addr::from(a).into(), bits)
}

// --- verifier ---------------------------------------------------------------

/// The one thing no unit test can answer: does the kernel accept what we
/// generate? Every configuration produces a different instruction stream, so
/// every configuration has to be loaded.
#[test]
#[ignore = "needs CAP_BPF"]
fn every_capture_configuration_passes_the_verifier() {
    if !root() {
        return;
    }
    for match_field in [MatchField::Dst, MatchField::Src, MatchField::Either] {
        for arp in [true, false] {
            for default_action in [Action::PASS, Action::DROP] {
                // The rule walk is unrolled per slot, so the widest list is
                // the one most likely to trip an instruction or complexity
                // limit; the narrowest exercises the degenerate loop.
                for max_rules_per_prefix in [1, 8, MAX_RULES_PER_PREFIX] {
                    let cfg = CaptureConfig {
                        match_field,
                        arp,
                        default_action,
                        max_rules_per_prefix,
                        ..Default::default()
                    };
                    let maps = CaptureMaps::create(&cfg).expect("create maps");
                    let insns = build_program(&cfg, &maps).expect("codegen");
                    Program::load(&insns, "pktkit_test").unwrap_or_else(|e| {
                        panic!(
                            "verifier rejected {match_field:?} arp={arp} \
                             rules={max_rules_per_prefix}: {e}"
                        )
                    });
                }
            }
        }
    }
}

// --- maps -------------------------------------------------------------------

/// Proves the `bpf_lpm_trie_key` layout against the kernel's own matcher: a
/// prefix entry has to match every address inside it and nothing outside.
#[test]
#[ignore = "needs CAP_BPF"]
fn lpm_trie_matches_by_longest_prefix() {
    if !root() {
        return;
    }
    let map = Map::lpm_trie(4, 4, 64).expect("create trie");
    let one = 1u32.to_ne_bytes();
    let two = 2u32.to_ne_bytes();

    map.update(
        pktkit::xdp::lpm_key(v4([10, 0, 0, 0], 8)).as_bytes(),
        &one,
        pktkit::xdp::UpdateFlags::ANY,
    )
    .unwrap();
    map.update(
        pktkit::xdp::lpm_key(v4([10, 1, 2, 0], 24)).as_bytes(),
        &two,
        pktkit::xdp::UpdateFlags::ANY,
    )
    .unwrap();

    let lookup = |a: [u8; 4]| -> Option<u32> {
        let mut out = [0u8; 4];
        map.lookup(pktkit::xdp::lpm_key(v4(a, 32)).as_bytes(), &mut out)
            .unwrap()
            .then(|| u32::from_ne_bytes(out))
    };

    // Inside the /8 only.
    assert_eq!(lookup([10, 5, 5, 5]), Some(1));
    // Inside both: the longer prefix wins.
    assert_eq!(lookup([10, 1, 2, 9]), Some(2));
    // Outside everything.
    assert_eq!(lookup([192, 0, 2, 1]), None);

    // Removing the /24 falls back to the /8 rather than to nothing.
    assert!(
        map.delete(pktkit::xdp::lpm_key(v4([10, 1, 2, 0], 24)).as_bytes())
            .unwrap()
    );
    assert_eq!(lookup([10, 1, 2, 9]), Some(1));
}

#[test]
#[ignore = "needs CAP_BPF"]
fn ipv6_prefixes_round_trip_through_the_trie() {
    if !root() {
        return;
    }
    let map = Map::lpm_trie(16, 4, 64).expect("create trie");
    let net: Ipv6Addr = "2001:db8:1::".parse().unwrap();
    map.update(
        pktkit::xdp::lpm_key(IpPrefix::new(net.into(), 48)).as_bytes(),
        &1u32.to_ne_bytes(),
        pktkit::xdp::UpdateFlags::ANY,
    )
    .unwrap();

    let hit: Ipv6Addr = "2001:db8:1::dead".parse().unwrap();
    let miss: Ipv6Addr = "2001:db8:2::dead".parse().unwrap();
    let mut out = [0u8; 4];
    assert!(
        map.lookup(
            pktkit::xdp::lpm_key(IpPrefix::new(hit.into(), 128)).as_bytes(),
            &mut out
        )
        .unwrap()
    );
    assert!(
        !map.lookup(
            pktkit::xdp::lpm_key(IpPrefix::new(miss.into(), 128)).as_bytes(),
            &mut out
        )
        .unwrap()
    );
}

// --- attach -----------------------------------------------------------------

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn capture_attaches_and_tracks_its_set() {
    if !root() {
        return;
    }
    let veth = Veth::new("attach");
    let ifindex = ifindex(&veth.host);

    let cap = Capture::attach(ifindex, CaptureConfig::default(), Mode::AUTO)
        .expect("attach capture program");
    eprintln!("attached in {:?} mode", cap.mode());

    let p = v4([10, 99, 0, 5], 32);
    cap.add(p).unwrap();
    assert!(
        cap.contains(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 5)))
            .unwrap()
    );
    assert!(
        !cap.contains(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 6)))
            .unwrap()
    );

    // A /24 covers every address inside it.
    cap.add(v4([10, 50, 0, 0], 24)).unwrap();
    assert!(
        cap.contains(IpAddr::V4(Ipv4Addr::new(10, 50, 0, 200)))
            .unwrap()
    );

    assert!(cap.remove(p).unwrap());
    assert!(
        !cap.contains(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 5)))
            .unwrap()
    );
}

/// The interface-sharing invariant, against a live attachment: a refusal has to
/// leave the kernel-side set untouched, not merely return an error.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn a_live_capture_refuses_to_take_the_whole_interface() {
    if !root() {
        return;
    }
    let veth = Veth::new("whole");
    let cap =
        Capture::attach(ifindex(&veth.host), CaptureConfig::default(), Mode::AUTO).expect("attach");

    // A default route in either family.
    assert!(cap.add(v4([0, 0, 0, 0], 0)).is_err());
    assert!(
        cap.add(IpPrefix::new("::".parse::<Ipv6Addr>().unwrap().into(), 0))
            .is_err()
    );

    // Two halves that individually clear the floor.
    cap.add(v4([0, 0, 0, 0], 1)).unwrap();
    assert!(cap.add(v4([128, 0, 0, 0], 1)).is_err());

    // The refused half is genuinely absent from the trie, not just unrecorded:
    // an address inside it must still miss.
    assert!(
        !cap.contains(IpAddr::V4(Ipv4Addr::new(200, 0, 0, 1)))
            .unwrap()
    );
    // While the half that was accepted matches.
    assert!(
        cap.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .unwrap()
    );
    assert_eq!(cap.prefixes(), vec![v4([0, 0, 0, 0], 1)]);
}

/// A tighter floor has to be enforced against the kernel-side set too.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn a_configured_floor_is_enforced_on_a_live_capture() {
    if !root() {
        return;
    }
    let veth = Veth::new("floor");
    let cfg = CaptureConfig {
        min_prefix_v4: 24,
        ..Default::default()
    };
    let cap = Capture::attach(ifindex(&veth.host), cfg, Mode::AUTO).expect("attach");

    cap.add(v4([10, 1, 2, 0], 24)).unwrap();
    assert!(cap.add(v4([10, 0, 0, 0], 8)).is_err());
    assert!(
        cap.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 9)))
            .unwrap()
    );
    // Nothing from the refused /8 leaked in.
    assert!(
        !cap.contains(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)))
            .unwrap()
    );
}

/// Rules accumulate per prefix in the kernel-side value, and go away one at a
/// time or all at once.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn rules_are_tracked_per_prefix() {
    if !root() {
        return;
    }
    let veth = Veth::new("rules");
    let cap =
        Capture::attach(ifindex(&veth.host), CaptureConfig::default(), Mode::AUTO).expect("attach");

    let p = v4([10, 99, 0, 5], 32);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 5));
    let wg = Rule::Port(Protocol::UDP, 51820);
    let gre = Rule::Proto(Protocol::GRE);

    cap.add_rule(p, wg).unwrap();
    cap.add_rule(p, gre).unwrap();
    // Idempotent per rule.
    cap.add_rule(p, gre).unwrap();
    assert_eq!(cap.rules(p), vec![wg, gre]);
    // What the kernel holds is what we recorded.
    assert_eq!(cap.rules_for(addr).unwrap(), vec![wg, gre]);
    assert_eq!(cap.prefixes(), vec![p]);

    // A port rule on anything but TCP/UDP never reaches the map.
    assert!(cap.add_rule(p, Rule::Port(Protocol::GRE, 1)).is_err());
    assert_eq!(cap.rules_for(addr).unwrap().len(), 2);

    assert!(cap.remove_rule(p, wg).unwrap());
    assert!(!cap.remove_rule(p, wg).unwrap());
    assert_eq!(cap.rules_for(addr).unwrap(), vec![gre]);

    // The last rule takes the prefix with it.
    assert!(cap.remove_rule(p, gre).unwrap());
    assert!(!cap.contains(addr).unwrap());
    assert!(cap.prefixes().is_empty());

    // The per-prefix cap is enforced before the map is touched.
    let cfg = CaptureConfig {
        max_rules_per_prefix: 2,
        ..Default::default()
    };
    drop(cap);
    let cap = Capture::attach(ifindex(&veth.host), cfg, Mode::AUTO).expect("attach");
    cap.add_rule(p, Rule::Port(Protocol::TCP, 1)).unwrap();
    cap.add_rule(p, Rule::Port(Protocol::TCP, 2)).unwrap();
    assert!(cap.add_rule(p, Rule::Port(Protocol::TCP, 3)).is_err());
    assert_eq!(cap.rules_for(addr).unwrap().len(), 2);
}

/// Neighbor discovery is only diverted for an address that is wholly ours.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn a_narrow_v6_rule_leaves_the_solicited_node_group_alone() {
    if !root() {
        return;
    }
    let veth = Veth::new("nd2");
    let cap =
        Capture::attach(ifindex(&veth.host), CaptureConfig::default(), Mode::AUTO).expect("attach");

    let addr: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
    let p = IpPrefix::new(addr.into(), 128);
    let sn = IpAddr::V6(pktkit::xdp::solicited_node_multicast(addr));

    cap.add_rule(p, Rule::Port(Protocol::UDP, 53)).unwrap();
    assert!(!cap.contains(sn).unwrap());
    // Widening to the whole address brings the group in...
    cap.add_rule(p, Rule::Any).unwrap();
    assert!(cap.contains(sn).unwrap());
    // ...and narrowing again takes it back out, leaving the port rule.
    assert!(cap.remove_rule(p, Rule::Any).unwrap());
    assert!(!cap.contains(sn).unwrap());
    assert!(cap.contains(IpAddr::V6(addr)).unwrap());
}

/// A `/128` has to bring its solicited-node multicast address with it, or
/// nothing on the network can resolve it.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn adding_a_v6_host_captures_its_solicited_node_group() {
    if !root() {
        return;
    }
    let veth = Veth::new("nd");
    let cap =
        Capture::attach(ifindex(&veth.host), CaptureConfig::default(), Mode::AUTO).expect("attach");

    let addr: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
    cap.add(IpPrefix::new(addr.into(), 128)).unwrap();

    let sn = pktkit::xdp::solicited_node_multicast(addr);
    assert_eq!(sn, "ff02::1:ffad:beef".parse::<Ipv6Addr>().unwrap());
    assert!(cap.contains(IpAddr::V6(sn)).unwrap());

    // And it goes away with the address it was derived from.
    cap.remove(IpPrefix::new(addr.into(), 128)).unwrap();
    assert!(!cap.contains(IpAddr::V6(sn)).unwrap());
}

// --- datapath ---------------------------------------------------------------

/// End to end: a captured address is delivered to userspace, and an address
/// that was never added is not.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn only_captured_addresses_reach_the_device() {
    if !root() {
        return;
    }
    let veth = Veth::new("data");

    // 10.99.0.5 and .6 belong to nobody: the host will not answer for them, so
    // whatever arrives for them arrives only because we captured it. Static
    // neighbour entries stand in for the ARP exchange.
    let mac = veth.host_mac();
    for last in ["5", "6"] {
        assert!(veth.ip_ns(&[
            "neigh",
            "add",
            &format!("10.99.0.{last}"),
            "lladdr",
            &mac,
            "dev",
            &veth.peer,
        ]));
    }

    let dev = Device::open(Config {
        interface: veth.host.clone(),
        // veth cannot do zero-copy; this test is about the filtering.
        zerocopy: Zerocopy::Off,
        program: ProgramSource::Capture(CaptureConfig::default()),
        ..Default::default()
    })
    .expect("open AF_XDP on veth");
    eprintln!("mode={:?} queues={:?}", dev.mode(), dev.queue_ids());

    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let n = Arc::new(AtomicUsize::new(0));
    {
        let seen = seen.clone();
        let n = n.clone();
        dev.set_handler(Arc::new(move |f: &Frame| {
            seen.lock().unwrap().push(f.as_bytes().to_vec());
            n.fetch_add(1, Ordering::Release);
            Ok(())
        }));
    }

    dev.capture_add(v4([10, 99, 0, 5], 32)).unwrap();

    // Captured: must arrive.
    veth.exec(&["ping", "-c", "2", "-W", "1", "10.99.0.5"]);
    wait_for(&n, 1, Duration::from_secs(3));

    let captured = seen.lock().unwrap().clone();
    assert!(!captured.is_empty(), "captured address delivered nothing");
    assert!(
        captured.iter().any(|f| ipv4_dst(f) == Some([10, 99, 0, 5])),
        "no frame addressed to the captured IP"
    );

    // Not captured: must not arrive.
    let before = n.load(Ordering::Acquire);
    veth.exec(&["ping", "-c", "2", "-W", "1", "10.99.0.6"]);
    std::thread::sleep(Duration::from_millis(500));
    let after = seen.lock().unwrap().clone();
    assert!(
        !after[before..]
            .iter()
            .any(|f| ipv4_dst(f) == Some([10, 99, 0, 6])),
        "an address that was never captured was delivered anyway"
    );

    dev.close().unwrap();
}

/// Traffic the device did not ask for still has to reach the host stack —
/// otherwise attaching to a live NIC takes it down.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn uncaptured_traffic_still_reaches_the_host_stack() {
    if !root() {
        return;
    }
    let veth = Veth::new("pass");

    let dev = Device::open(Config {
        interface: veth.host.clone(),
        zerocopy: Zerocopy::Off,
        ..Default::default()
    })
    .expect("open AF_XDP on veth");
    // Capture something unrelated, so the program is doing real work.
    dev.capture_add(v4([10, 99, 0, 5], 32)).unwrap();

    // 10.99.0.1 is the host's own address on this link and was never captured,
    // so the kernel must still answer it.
    assert!(
        veth.exec(&["ping", "-c", "2", "-W", "2", "10.99.0.1"]),
        "attaching the capture program broke the host stack"
    );

    dev.close().unwrap();
}

/// The point of a port rule: one service on the host's own address is
/// captured, and everything else on that address — ARP included — stays with
/// the host stack.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn a_port_rule_shares_the_address_with_the_host_stack() {
    if !root() {
        return;
    }
    let veth = Veth::new("port");

    let dev = Device::open(Config {
        interface: veth.host.clone(),
        zerocopy: Zerocopy::Off,
        ..Default::default()
    })
    .expect("open AF_XDP on veth");

    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let n = Arc::new(AtomicUsize::new(0));
    {
        let seen = seen.clone();
        let n = n.clone();
        dev.set_handler(Arc::new(move |f: &Frame| {
            seen.lock().unwrap().push(f.as_bytes().to_vec());
            n.fetch_add(1, Ordering::Release);
            Ok(())
        }));
    }

    // 10.99.0.1 is the host's address on this link. Take only UDP 5555 on it.
    dev.capture_add_rule(v4([10, 99, 0, 1], 32), Rule::Port(Protocol::UDP, 5555))
        .unwrap();

    // The host still answers ARP and ICMP for the address.
    assert!(
        veth.exec(&["ping", "-c", "2", "-W", "2", "10.99.0.1"]),
        "a port rule took the whole address away from the host"
    );
    assert!(
        !seen.lock().unwrap().iter().any(|f| ipv4_dst(f).is_some()),
        "ICMP to a port-captured address was diverted"
    );

    // The captured port arrives. bash's /dev/udp is the least that can send
    // a datagram from inside the namespace.
    veth.exec(&["bash", "-c", "echo hi >/dev/udp/10.99.0.1/5555"]);
    wait_for(&n, 1, Duration::from_secs(3));
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|f| udp_dst_port(f) == Some(5555)),
        "the captured port was not delivered"
    );

    // A neighbouring port does not.
    let before = seen.lock().unwrap().len();
    veth.exec(&["bash", "-c", "echo hi >/dev/udp/10.99.0.1/5556"]);
    std::thread::sleep(Duration::from_millis(500));
    let after = seen.lock().unwrap().clone();
    assert!(
        !after[before..]
            .iter()
            .any(|f| udp_dst_port(f) == Some(5556)),
        "a port that was never captured was delivered"
    );

    dev.close().unwrap();
}

fn wait_for(n: &AtomicUsize, target: usize, timeout: Duration) {
    let start = Instant::now();
    while n.load(Ordering::Acquire) < target && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Destination address of an IPv4 frame, if it is one.
fn ipv4_dst(frame: &[u8]) -> Option<[u8; 4]> {
    if frame.len() < 34 {
        return None;
    }
    let et = EtherType(u16::from_be_bytes([frame[12], frame[13]]));
    if et != EtherType::IPV4 {
        return None;
    }
    Some([frame[30], frame[31], frame[32], frame[33]])
}

/// Destination port of an IPv4 UDP frame, if it is one.
fn udp_dst_port(frame: &[u8]) -> Option<u16> {
    ipv4_dst(frame)?;
    if frame[23] != Protocol::UDP.as_u8() {
        return None;
    }
    let l4 = 14 + usize::from(frame[14] & 0x0f) * 4;
    frame
        .get(l4 + 2..l4 + 4)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn ifindex(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .expect("read ifindex")
        .trim()
        .parse()
        .expect("parse ifindex")
}
