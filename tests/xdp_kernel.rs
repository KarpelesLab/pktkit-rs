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
use std::sync::{Arc, Mutex, MutexGuard};
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

/// Every veth pair puts 10.99.0.1/24 on its host end, and the host ends all
/// live in the root namespace. Two pairs alive at once give the host two
/// routes to the same subnet, and a reply then leaves through whichever veth
/// the route lookup finds first — so anything that expects an answer fails at
/// random. Holding this for the life of a [`Veth`] runs those tests one at a
/// time, whatever `--test-threads` says.
static ADDRESS_PLAN: Mutex<()> = Mutex::new(());

/// Locally administered, unicast. See [`Veth::new`] for why they are fixed.
const HOST_MAC: &str = "02:70:6b:00:00:01";
const PEER_MAC: &str = "02:70:6b:00:00:02";

/// veth pair + netns, torn down on drop.
struct Veth {
    ns: String,
    host: String,
    peer: String,
    /// Released after `Drop::drop` has torn the pair down.
    _plan: MutexGuard<'static, ()>,
}

impl Veth {
    /// Panics rather than skipping: callers have already established that we
    /// are root, so a failure here is iproute2 missing or a real bug.
    fn new(tag: &str) -> Veth {
        let v = Veth {
            // A test that panicked poisons the lock without leaving anything
            // behind that the teardown below does not clear.
            _plan: ADDRESS_PLAN.lock().unwrap_or_else(|e| e.into_inner()),
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
        // Both ends get an address we chose. Left to the kernel they get a
        // random one, and udev then swaps in its "persistent" address a moment
        // after the link appears — asynchronously, so sometimes after the
        // peer has already resolved the old one. From then on the peer sends
        // to a MAC the host end no longer has, and the host drops every frame
        // as addressed to someone else. An address set explicitly is left
        // alone.
        assert!(
            ip(&[
                "link", "add", &v.host, "address", HOST_MAC, "type", "veth", "peer", "name",
                &v.peer, "address", PEER_MAC, "netns", &v.ns,
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

    /// Ping the host end from inside the namespace.
    fn ping_host(&self) -> bool {
        self.exec(&["ping", "-c", "2", "-W", "2", "10.99.0.1"])
    }

    /// Establish that the host answers at all before XDP is involved, so a
    /// later failure can be laid at the program's door and not at a firewall's.
    fn assert_baseline(&self) {
        assert!(
            self.ping_host(),
            "the host does not answer ping on a plain veth, with no XDP program \
             attached: this environment (firewall? rp_filter?) cannot run the test"
        );
    }

    /// Frames the peer end has received, from its own interface counters.
    fn peer_rx_packets(&self) -> u64 {
        let path = format!("/sys/class/net/{}/statistics/rx_packets", self.peer);
        let out = Command::new("ip")
            .args(["netns", "exec", &self.ns, "cat", &path])
            .output()
            .expect("read peer counters");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("rx_packets is a number")
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
                    let cfg = CaptureConfig::default()
                        .match_field(match_field)
                        .arp(arp)
                        .default_action(default_action)
                        .max_rules_per_prefix(max_rules_per_prefix);
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
    let cfg = CaptureConfig::default().min_prefix_v4(24);
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
    let cfg = CaptureConfig::default().max_rules_per_prefix(2);
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

    let dev = Device::open(
        Config::new(veth.host.clone())
            // veth cannot do zero-copy; this test is about the filtering.
            .zerocopy(Zerocopy::Off)
            .program(ProgramSource::Capture(CaptureConfig::default())),
    )
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
    veth.assert_baseline();

    let dev = Device::open(Config::new(veth.host.clone()).zerocopy(Zerocopy::Off))
        .expect("open AF_XDP on veth");
    // Capture something unrelated, so the program is doing real work.
    dev.capture_add(v4([10, 99, 0, 5], 32)).unwrap();

    // 10.99.0.1 is the host's own address on this link and was never captured,
    // so the kernel must still answer it.
    if !veth.ping_host() {
        panic!(
            "attaching the capture program broke the host stack: {}",
            why_no_answer(&veth, dev)
        );
    }

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
    veth.assert_baseline();

    let dev = Device::open(Config::new(veth.host.clone()).zerocopy(Zerocopy::Off))
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
    if !veth.ping_host() {
        panic!(
            "a port rule took the whole address away from the host: {}",
            why_no_answer(&veth, dev)
        );
    }
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

/// An Ethernet + IPv4 frame with `ihl` header words and the given
/// flags/fragment word, carrying `sport`/`dport` where TCP and UDP keep them.
fn l4_frame(proto: Protocol, dst: [u8; 4], ihl: u8, frag: u16, sport: u16, dport: u16) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
    let mut h = vec![0u8; usize::from(ihl) * 4];
    h[0] = 0x40 | ihl;
    let total = (h.len() + 20) as u16;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[6..8].copy_from_slice(&frag.to_be_bytes());
    h[8] = 64;
    h[9] = proto.as_u8();
    h[12..16].copy_from_slice(&[10, 99, 0, 2]);
    h[16..20].copy_from_slice(&dst);
    f.extend_from_slice(&h);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&[0u8; 16]);
    f
}

/// Output of a command, or why there is none, on one line.
fn output_of(cmd: &str, args: &[&str]) -> String {
    match Command::new(cmd).args(args).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" | "),
        Err(e) => format!("({cmd}: {e})"),
    }
}

/// `InEchos` and `OutEchoReps` from the root namespace's ICMP counters: did
/// the stack see an echo request, and did it answer.
fn icmp_echo_counters() -> (u64, u64) {
    let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    let mut lines = snmp.lines().filter(|l| l.starts_with("Icmp:"));
    let (Some(names), Some(values)) = (lines.next(), lines.next()) else {
        return (0, 0);
    };
    let field = |want: &str| {
        names
            .split_whitespace()
            .zip(values.split_whitespace())
            .find(|(n, _)| *n == want)
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0)
    };
    (field("InEchos"), field("OutEchoReps"))
}

/// Everything that tells "the program dropped it" from "the stack lost it",
/// for the message of a ping that went unanswered after the baseline passed.
///
/// Takes the device because the last two probes need it gone: whether the
/// host answers again once the program is detached, and whether it answers
/// behind a generic-mode attachment where it did not behind a native one.
fn why_no_answer(veth: &Veth, dev: Device) -> String {
    let verdict = |frame: &[u8]| {
        dev.capture()
            .map(|c| c.test_run(frame, 1).map(|r| r.action))
    };
    let mut echo = l4_frame(Protocol::ICMP, [10, 99, 0, 1], 5, 0, 0x0800, 0);
    echo.truncate(14 + 20 + 8);
    // who-has 10.99.0.1 tell 10.99.0.2
    let mut arp = vec![0xffu8; 6];
    arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x08, 0x06]);
    arp.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 10, 99, 0, 2]);
    arp.extend_from_slice(&[0, 0, 0, 0, 0, 0, 10, 99, 0, 1]);
    let verdicts = format!("echo={:?} arp={:?}", verdict(&echo), verdict(&arp));

    let host_stat = |name: &str| -> u64 {
        std::fs::read_to_string(format!("/sys/class/net/{}/statistics/{name}", veth.host))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };

    // One more ping, a second later, with the counters read either side of
    // it: requests arriving (rx), the stack seeing them (InEchos), the stack
    // answering (OutEchoReps), the answers leaving by this veth (tx).
    std::thread::sleep(Duration::from_secs(1));
    let (rx0, tx0) = (host_stat("rx_packets"), host_stat("tx_packets"));
    let (in0, out0) = icmp_echo_counters();
    let retry = veth.ping_host();
    let (in1, out1) = icmp_echo_counters();
    let during = format!(
        "answered={retry} veth rx+{} tx+{} rx_dropped={} stack InEchos+{} OutEchoReps+{}",
        host_stat("rx_packets") - rx0,
        host_stat("tx_packets") - tx0,
        host_stat("rx_dropped"),
        in1 - in0,
        out1 - out0,
    );

    // If these disagree with what the peer has cached below, the host end
    // changed its address under the test.
    let host_mac = veth.host_mac();
    let neigh_host = output_of("ip", &["neigh", "show", "dev", &veth.host]);
    let neigh_peer = output_of("ip", &["-n", &veth.ns, "neigh", "show"]);
    let routes = output_of("ip", &["route", "show", "10.99.0.0/24"]);
    let queue_stats = output_of("ethtool", &["-S", &veth.host]);
    let mode = dev.mode();
    let xsk = dev
        .statistics()
        .map(|s| (s.rx_dropped, s.rx_invalid_descs, s.rx_ring_full));

    // Detached: does the host come back by itself?
    let _ = dev.close();
    drop(dev);
    std::thread::sleep(Duration::from_millis(1500));
    let detached = veth.ping_host();

    // And behind the generic hook, which shares nothing with veth's own
    // NAPI receive path?
    let generic = match Device::open(
        Config::new(veth.host.clone())
            .zerocopy(Zerocopy::Off)
            .mode(Mode::GENERIC),
    ) {
        Ok(d) => {
            let answered = veth.ping_host();
            let _ = d.close();
            format!("{answered}")
        }
        Err(e) => format!("(open: {e})"),
    };

    format!(
        "\n  mode={mode:?} verdicts: {verdicts}\n  second ping: {during}\n  \
         xsk stats={xsk:?}\n  host mac now: {host_mac} (created as {HOST_MAC})\n  \
         host neigh: {neigh_host}\n  peer neigh: {neigh_peer}\n  \
         routes: {routes}\n  ethtool -S: {queue_stats}\n  \
         answers once detached={detached}\n  answers behind generic mode={generic}"
    )
}

/// The unit tests execute the generated program in an interpreter. This runs
/// the same kind of frames through the JITed program in the kernel, against
/// real maps, so the two cannot quietly disagree.
///
/// No socket is bound, so a hit falls back to the verdict in the redirect
/// flags, `XDP_PASS`; the default action is set to `XDP_DROP` to keep a miss
/// distinguishable from it.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn the_kernel_gives_the_verdicts_the_interpreter_does() {
    if !root() {
        return;
    }
    const HIT: Action = Action::PASS;
    const MISS: Action = Action::DROP;
    let veth = Veth::new("verdict");
    let cap = Capture::attach(
        ifindex(&veth.host),
        CaptureConfig::default().default_action(MISS),
        Mode::AUTO,
    )
    .expect("attach");

    let shared = [10, 99, 0, 1];
    let owned = [10, 99, 0, 5];
    cap.add_rule(v4(shared, 32), Rule::Port(Protocol::UDP, 5555))
        .unwrap();
    cap.add_rule(v4(owned, 32), Rule::Port(Protocol::TCP, 1))
        .unwrap();
    // Added second, walked first.
    cap.add(v4(owned, 32)).unwrap();

    let udp = Protocol::UDP;
    let tcp = Protocol::TCP;
    let mut truncated = l4_frame(udp, shared, 5, 0, 9, 5555);
    truncated.truncate(14 + 20 + 3);
    let cases: Vec<(&str, Vec<u8>, Action)> = vec![
        ("captured port", l4_frame(udp, shared, 5, 0, 9, 5555), HIT),
        (
            "neighbouring port",
            l4_frame(udp, shared, 5, 0, 9, 5556),
            MISS,
        ),
        (
            "the peer's port, not ours",
            l4_frame(udp, shared, 5, 0, 5555, 9),
            MISS,
        ),
        (
            "right port, wrong protocol",
            l4_frame(tcp, shared, 5, 0, 9, 5555),
            MISS,
        ),
        (
            "behind ip options",
            l4_frame(udp, shared, 7, 0, 9, 5555),
            HIT,
        ),
        (
            "behind the longest header",
            l4_frame(udp, shared, 15, 0, 9, 5555),
            HIT,
        ),
        (
            "first fragment",
            l4_frame(udp, shared, 5, 0x2000, 9, 5555),
            HIT,
        ),
        (
            "later fragment",
            l4_frame(udp, shared, 5, 185, 9, 5555),
            MISS,
        ),
        ("truncated transport header", truncated, MISS),
        ("whole address, udp", l4_frame(udp, owned, 5, 0, 9, 9), HIT),
        (
            "whole address, later fragment",
            l4_frame(tcp, owned, 5, 185, 9, 9),
            HIT,
        ),
        (
            "someone else",
            l4_frame(udp, [10, 99, 0, 9], 5, 0, 9, 5555),
            MISS,
        ),
    ];
    // Every case is run before anything is asserted, so one report shows the
    // whole picture instead of the first disagreement.
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(what, frame, want)| match cap.test_run(frame, 1) {
            Ok(got) if got.action == *want => None,
            Ok(got) => Some(format!("{what}: {:?}, wanted {want:?}", got.action)),
            Err(e) => Some(format!("{what} ({} bytes): {e}", frame.len())),
        })
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// With a socket bound to the queue, a hit is `XDP_REDIRECT` rather than the
/// fallback verdict.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn a_bound_socket_turns_a_hit_into_a_redirect() {
    if !root() {
        return;
    }
    let veth = Veth::new("redir");
    let dev = Device::open(Config::new(veth.host.clone()).zerocopy(Zerocopy::Off))
        .expect("open AF_XDP on veth");
    let cap = dev.capture().expect("capture program");
    cap.add(v4([10, 99, 0, 5], 32)).unwrap();

    let miss = l4_frame(Protocol::UDP, [10, 99, 0, 9], 5, 0, 9, 9);
    let hit = l4_frame(Protocol::UDP, [10, 99, 0, 5], 5, 0, 9, 9);
    // The miss goes first: it never reaches the redirect helper, so if only
    // the hit fails, the helper or the populated XSKMAP is what the test run
    // objects to, and not the bound socket as such.
    let miss = cap.test_run(&miss, 1);
    let hit = cap.test_run(&hit, 1);
    assert_eq!(
        (
            miss.as_ref().map(|r| r.action).map_err(|e| e.to_string()),
            hit.as_ref().map(|r| r.action).map_err(|e| e.to_string()),
        ),
        (Ok(Action::PASS), Ok(Action::REDIRECT)),
        "queues={:?} mode={:?}",
        dev.queue_ids(),
        dev.mode()
    );

    dev.close().unwrap();
}

/// Not a pass/fail test: prints what the program costs per packet, which is
/// the number every optimisation of the codegen has to move. Run with
/// `--ignored --nocapture cost`.
///
/// The miss columns matter most — that is the host's own traffic — and how the
/// near miss grows with the size of the set is what says whether the LPM trie
/// is worth fronting with a hash for host entries. Measured on Linux 6.18,
/// x86-64, native-mode veth, it is not: from 1 to 2048 captured hosts a miss
/// stayed at 6 ns and a near miss at 7-8 ns (8 and 9-10 ns under `Either`).
/// Only a whole-address hit deepens with the set, 9 ns to 46 ns, and that
/// packet goes on to an AF_XDP delivery costing many times as much.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn what_the_capture_program_costs_per_packet() {
    if !root() {
        return;
    }
    const REPEAT: u32 = 2_000_000;
    let veth = Veth::new("cost");
    let miss = l4_frame(Protocol::UDP, [10, 99, 0, 9], 5, 0, 9, 53);
    // A neighbour of the captured hosts, which is what the host's own traffic
    // usually is. It shares most of its bits with the set, so the trie walks
    // about as deep for it as for a hit — unlike the far miss above, which
    // falls out at the first node whatever the set holds.
    let near_miss = l4_frame(Protocol::UDP, [10, 200, 255, 255], 5, 0, 9, 53);
    let any_hit = l4_frame(Protocol::UDP, [10, 200, 0, 0], 5, 0, 9, 53);
    let port_hit = l4_frame(Protocol::UDP, [10, 201, 0, 0], 5, 0, 9, 53);

    for match_field in [MatchField::Dst, MatchField::Either] {
        let cap = Capture::attach(
            ifindex(&veth.host),
            CaptureConfig::default()
                .match_field(match_field)
                .max_prefixes(4096),
            Mode::AUTO,
        )
        .expect("attach");
        cap.add_rule(v4([10, 201, 0, 0], 32), Rule::Port(Protocol::UDP, 53))
            .unwrap();

        let mut held = 0u32;
        for target in [1u32, 16, 256, 2048] {
            while held < target {
                let [_, _, c, d] = held.to_be_bytes();
                cap.add(v4([10, 200, c, d], 32)).unwrap();
                held += 1;
            }
            let m = cap.test_run(&miss, REPEAT).expect("test run");
            let n = cap.test_run(&near_miss, REPEAT).expect("test run");
            assert_eq!(n.action, Action::PASS);
            let a = cap.test_run(&any_hit, REPEAT).expect("test run");
            let p = cap.test_run(&port_hit, REPEAT).expect("test run");
            assert_eq!(m.action, Action::PASS);
            eprintln!(
                "{match_field:?} {held:>5} hosts: miss {:>3} ns  near-miss {:>3} ns  \
                 any-hit {:>3} ns  port-hit {:>3} ns",
                m.duration_ns, n.duration_ns, a.duration_ns, p.duration_ns
            );
        }
    }
}

/// A burst goes out whole through `send_batch`, which takes what it has
/// buffers for and says so.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN"]
fn a_batch_is_transmitted_in_full() {
    if !root() {
        return;
    }
    const FRAMES: usize = 5000;
    // Half of these are the TX pool. Keeping it far below the kernel's input
    // backlog (`netdev_max_backlog`, 1000 by default) makes the burst pace
    // itself: a buffer only comes back once the peer has consumed the frame,
    // so the veth can never be handed more than it can queue. A full-sized
    // pool loses a third of a 5000-frame burst there, which says nothing
    // about `send_batch`.
    const POOL: u32 = 128;
    let veth = Veth::new("batch");
    let dev = Device::open(
        Config::new(veth.host.clone())
            .zerocopy(Zerocopy::Off)
            .num_frames(POOL),
    )
    .expect("open AF_XDP on veth");

    // Broadcast, in an EtherType reserved for local experiments, so nothing
    // on either side answers it.
    let mut frame = vec![0xffu8; 6];
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x88, 0xb5]);
    frame.extend_from_slice(&[0u8; 50]);
    let one = Frame::from_slice(&frame);
    let burst: Vec<&Frame> = vec![one; FRAMES];

    // An oversized frame fails the call before anything is queued.
    let huge = vec![0u8; 8192];
    assert!(dev.send_batch(&[one, Frame::from_slice(&huge)]).is_err());

    let before = veth.peer_rx_packets();
    // A runt is taken and dropped without stalling what follows it.
    let runt = Frame::from_slice(&frame[..10]);
    assert_eq!(dev.send_batch(&[runt, one]).unwrap(), 2);

    // More than the pool holds: part of it is taken, and the count is honest.
    let first = dev.send_batch(&burst).expect("send_batch");
    assert!(
        first > 0 && first <= (POOL / 2) as usize,
        "{first} frames taken from a pool of {}",
        POOL / 2
    );

    let mut sent = first;
    let deadline = Instant::now() + Duration::from_secs(20);
    while sent < FRAMES && Instant::now() < deadline {
        let n = dev.send_batch(&burst[sent..]).expect("send_batch");
        sent += n;
        if n == 0 {
            // Out of buffers until the kernel completes some.
            std::thread::sleep(Duration::from_micros(200));
        }
    }
    assert_eq!(sent, FRAMES, "the device stopped taking frames");

    // The runt never went out; the frame offered alongside it did.
    let want = FRAMES as u64 + 1;
    let deadline = Instant::now() + Duration::from_secs(5);
    while veth.peer_rx_packets() - before < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let arrived = veth.peer_rx_packets() - before;
    let stats = dev.statistics().expect("statistics");
    assert!(
        arrived >= want,
        "{arrived} of {want} batched frames reached the peer (tx_invalid_descs={})",
        stats.tx_invalid_descs
    );
    assert_eq!(stats.tx_invalid_descs, 0);

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
