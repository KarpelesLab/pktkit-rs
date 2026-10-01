# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); this crate follows
semantic versioning once it reaches 1.0.

## [Unreleased]

## [0.1.11](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.10...v0.1.11) - 2026-10-01

### Added

- *(xdp)* pinned attachments survive a restart without a link reset

### Fixed

- *(slirp)* Fast Open cookies are per namespace
- *(vclient)* SYN data the engine drops is not charged to the listener
- *(vclient)* close() wakes threads blocked on the connection
- *(slirp)* each namespace grows its buffers from a share of its own
- *(vtcp)* idle connections give their buffer growth back
- *(vtcp)* a pipeACK sample covers one round trip
- *(vtcp)* CUBIC leaves idle time off its curve
- *(vtcp)* BBR conserves packets in fast recovery
- *(vtcp)* CUBIC undo judges against the window it cut
- *(vtcp)* HyStart++ runs against peers without timestamps
- *(vtcp)* ignore D-SACK blocks that reach past SND.NXT
- *(vtcp)* a Packet Too Big resends only what does not fit
- *(vtcp)* SYN data sent again after the handshake is a retransmission to ECN
- *(vtcp)* AccECN handshake code only on the ACK of the SYN-ACK alone
- *(vtcp)* in SYN-RECEIVED, take only a SYN restating the IRS as resent
- *(vtcp)* take ECN signals only from segments whose ACK checks out
- *(vtcp)* undoing a loss response keeps the losses it did not refute
- *(vtcp)* SACKs split the scoreboard only at whole MSS

### Other

- *(xdp)* fix two kernel tests' assumptions, now that CI runs them
- run the root-only XDP tests against the runner's kernel
- Fast Open cookies can be forged on wasm32-unknown-unknown
- *(vtcp)* a scaled window's edge may come back by less than a unit

## [0.1.10](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.9...v0.1.10) - 2026-09-29

### Added

- *(vtcp)* TcpInfo reports what the handshake agreed on
- *(vtcp)* TcpInfo, a snapshot of a connection's internals

### Fixed

- *(interop)* measure slow start over long paths; report the grown buffer
- *(impair, vtcp)* timer threads wake on time on macOS
- *(interop)* the guest never outlives the harness
- *(vtcp)* AccECN no longer reads Linux's thinned ACKs as all CE
- *(vtcp)* no reset from an abort once both ends have closed
- *(vtcp)* no_window_scaling leaves the option out
- *(vclient,slirp)* stop waking blocked handles for every segment

### Other

- take wall-clock bounds out of the default suite
- run the interop suite against Linux under KVM
- *(interop)* vtcp against a real Linux TCP, in QEMU

## [0.1.9](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.8...v0.1.9) - 2026-09-29

### Added

- *(vtcp)* a black hole's timeouts cost no window, nor its stragglers
- *(slirp)* Stack::set_tcp, and Fast Open for bridges and listeners
- *(vclient)* TCP tuning passthrough, Fast Open dials and listeners
- *(vtcp)* TCP Fast Open (RFC 7413)
- *(vtcp)* PLPMTUD, black-hole detection and MTU probing (RFC 4821)
- *(impair)* mark ECN-capable packets CE
- *(vtcp)* BBR's response to ECN
- *(vclient, slirp)* carry ECN codepoints between IP and vtcp
- *(vtcp)* ECN, classic (RFC 3168) and accurate (RFC 9768)
- *(vtcp)* BBR (draft-ietf-ccwg-bbr) on delivery rate estimation
- *(vtcp)* pace sending, on by default
- *(vtcp)* validate the congestion window (RFC 7661), restart it after idle
- *(vtcp)* CUBIC (RFC 9438) with HyStart++ (RFC 9406), now the default
- *(vtcp)* undo spurious loss responses (RFC 3708, 3522, 5682, 4015)
- *(vtcp)* Proportional Rate Reduction in fast recovery (RFC 6937)
- *(vtcp)* RACK-TLP loss detection (RFC 8985)
- *(vtcp)* report data received twice with D-SACK (RFC 2883)
- *(vtcp)* offer TCP timestamps by default
- *(vtcp)* delay ACKs as RFC 9293 and RFC 5681 allow, with Linux's quick-ACK mode
- *(vtcp)* count bytes acknowledged, not ACKs, to grow cwnd (RFC 3465)
- *(vtcp)* sample the RTT from every ACK with timestamps, and floor the RTO as Linux
- *(vtcp)* report when the next timer is due
- *(vtcp)* auto-tune send and receive buffers as Linux does

### Fixed

- *(nat, vclient, slirp)* keep CE marks through fragment reassembly
- *(vtcp)* let BBR's Startup see a plateau through reordering
- *(vtcp)* pace by a precise round trip, and keep a paced window growing
- *(vtcp)* bound out-of-order data by memory, not by a count of holes
- *(vtcp)* have Eifel judge the ACK of the retransmission itself
- *(nat)* run the UPnP control connections' TCP timers
- *(vtcp)* renege on SACKs less, and act on a renege at once
- *(vtcp)* keep TSvals running on across connections to the same host
- *(slirp)* run TCP timers when they are due, not every 100 ms
- *(vclient)* run TCP timers when they are due, not every 100 ms
- *(nat)* keep UPnP control connection buffers fixed
- *(slirp)* let bridge buffers grow past their 256 KiB start

### Other

- stop two timing tests failing on loaded CI runners
- *(fuzz)* the vtcp conversation covers PLPMTUD and Fast Open
- *(vtcp)* tail loss probe test no longer races the real clock
- what the vtcp engine does, PLPMTUD and Fast Open among it
- *(vtcp)* keep RACK's per-ACK scan short
- *(vtcp)* list delayed ACKs and byte counting among the RFCs
- *(vtcp)* build TCP options in place, and stop copying each payload twice
- *(vtcp)* read the clock once per call, not at every step
- *(readme)* drive vclient's timers when Client::next_timer says

## [0.1.8](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.7...v0.1.8) - 2026-09-28

### Added

- *(ovpn)* show on_auth the client certificate
- *(wg)* per-peer allowed IPs on the Adapter
- *(vtcp)* let the Nagle algorithm be turned off
- *(nat)* translate hosts on networks routed behind the inside
- *(ovpn)* negotiate the data cipher with NCP clients
- *(ovpn)* renegotiate data-channel keys (soft reset)
- *(wg)* run the protocol timers, so tunnels rekey and stay up
- *(vtcp)* SACK-based loss recovery, and four SACK blocks without timestamps

### Fixed

- *(fuzz)* let the l2adapter target run the adapter's timers
- *(accept)* take the errno test's values from transient's own cfg
- *(vclient)* randomize DNS query-name case (0x20) and check it
- *(dhcp)* hear only the lease's server while renewing
- *(dhcp)* draw client transaction IDs from a keyed hash
- *(rand)* add xorshift64*'s missing multiply, and a keyed source
- *(l3hub)* offer strict reverse-path source checking per port
- *(l2adapter)* don't let unsolicited ARP move the gateway's entry
- *(dhcp)* tie server leases to the station that asks for them
- *(l2hub)* add port security against MAC takeover and table filling
- *(l2hub)* stop double-tagged frames hopping VLANs
- *(nat)* give portless SIP Via and Contact addresses the mapped port
- *(nat)* keep free unprivileged source ports, and alias displaced mappings
- *(nat)* pick NAT64 IPv4 IDs per flow from a keyed hash
- *(nat)* bound the listeners IRC DCC offers open, and let them lapse
- *(nat)* do not forward to loopback, reserved, link-local or broadcast
- *(nat)* scope UPnP listings to the asking namespace, and check sources first
- *(nat)* drop outside packets with forged sources (RFC 2827, 3704)
- *(nat)* cap what one inside namespace holds, whatever addresses it uses
- *(nat)* reassemble each direction and namespace apart
- *(ovpn)* wipe key-exchange secrets and the password after use
- *(ovpn)* hold tap clients to their own MAC, ARP and NDP claims
- *(ovpn)* rate-limit renegotiations a client starts
- *(ovpn)* pin a session's identity across renegotiations
- *(ovpn)* make room in a full table instead of refusing newcomers
- *(ovpn)* keep the stateless-answer budget per source
- *(slirp)* tell accepted streams' peers apart by namespace
- *(slirp)* answer SYNs past a listener's backlog with SYN cookies
- *(slirp)* share a listener's half-open slots between namespaces
- *(vtcp)* check the IRS on a simultaneous open's SYN-ACK
- *(wg)* keep a removed peer's replay state for when it returns
- *(wg)* bound session state per peer, not by one shared cap
- *(wg)* only drop peers taken from on_unknown_peer by themselves
- *(core)* export the IpPrefix and MacAddr parse errors
- *(wg)* tear down a peer's endpoint and device when the handler drops it
- *(nat)* match a PPTP call reply only to a live call of its host
- *(nat)* charge ALG media ports against the host only once mapped
- *(nat)* free a lapsed expectation's port when a mapping needs one
- *(nat)* drop NAT64 packets from sources no inside host can have
- *(nat)* count NAT64 hosts per /64 for the per-host caps
- *(nat)* preserve only source ports within the dynamic pool
- *(nat)* let a host forward the port its own mapping holds
- *(vclient)* widen wall-clock test bounds a loaded machine could miss
- *(slirp)* widen wall-clock test bounds a loaded machine could miss
- *(vclient)* put read_response's doc comment back on it
- *(vtcp)* refuse a Packet Too Big quoting SND.NXT
- *(slirp)* hold a handshake back while the accept queue is full
- *(vclient)* drop a SYN while the listener's accept queue is full
- *(vclient)* charge data on a SYN-cookie ACK to the unaccepted budget
- *(slirp)* keep a listener's waiting list bounded
- *(l2adapter)* a closed adapter's timers do nothing, however driven
- *(l2adapter)* report off-link IPv6 with no router as no route
- *(l2adapter)* learn the DHCP server's MAC only from a reply the client took
- *(l2adapter)* stop the neighbour-timer thread on close
- *(arp)* refuse a packet that cannot fit before shedding its queue
- *(dhcp)* keep a provisional lease provisional until a real renewal
- *(accept)* retry the network errors accept(2) says to, and poll WouldBlock
- *(qemu)* keep accepting when one peer's socket cannot be set up
- *(ovpn)* keep timing-sensitive tests from failing on a loaded machine
- *(wg)* charge an accepted unknown peer's initiation to the rate limiter once
- *(wg)* stop expired peers from locking newcomers out of the unknown-peer table
- *(ovpn)* make connect_freq off by default and per source
- *(ovpn)* count only unauthenticated TCP connections against the per-source cap
- *(ovpn)* queue a removed session's on_disconnect before its successor's on_connect
- *(vclient)* report a UDP peer's port unreachable as ConnectionRefused
- *(slirp)* stop the bridge re-imposing Nagle on the host's writes
- *(slirp)* take path MTU discovery from the guest side
- *(ovpn)* refuse a TCP connection accepted while close() runs
- *(vclient)* discover the path MTU instead of stalling on it
- *(vclient)* hold handshakes back while the accept queue is full
- *(vclient)* send each connection's segments in the order they were made
- *(slirp)* refuse TCP through a shut-down stack with a RST
- *(slirp)* report refused UDP datagrams to the guest as port unreachable
- *(slirp)* pass a server's reset on to the guest instead of a FIN
- *(slirp)* let connections wait for a full accept queue, not reset them
- *(slirp)* send each connection's segments in the order vtcp made them
- *(slirp)* give every IPv4 TCP segment its own IP ID
- *(nat)* take a quota with compare_exchange, not fetch_update
- *(nat)* keep UPnP descriptions short and list mappings by index
- *(nat)* cap the media ports a SIP message and host may open
- *(nat)* cap pending expectations per inside host
- *(nat)* keep the host's port, or its range and parity, when mapping
- *(nat)* cap tracked remotes and mappings per host, and check sources
- *(nat)* answer pings to NAT44's public address from outside
- *(nat)* fragment large NAT64 packets IPv4 lets be fragmented
- *(nat)* spend a hop of what NAT44 forwards, and answer TTL expiry
- *(nat)* send NAT64 ICMP errors when the IPv4 source cannot be embedded
- *(dhcp)* lease addresses to unknown clients only provisionally
- *(arp)* cap bytes awaiting resolution, and always admit the router
- *(arp)* evict a full neighbour cache in batches, never the router
- *(accept)* build the transient-error test on fullrust
- *(ovpn)* report the adapter's TCP address
- *(slirp)* stop waking every blocked flow thread ten times a second
- *(slirp)* share every flow cap out between namespaces
- *(slirp)* start an outbound bridge's pumps only once the guest ACKs
- *(ovpn)* bound how long and how many TCP connections one source holds
- *(ovpn)* drop control packets too big for a control channel buffer
- *(ovpn)* keep one source from filling and holding the peer table
- *(ovpn)* do no TLS work for a session until its reset is ACKed
- take capped slots without fetch_update
- *(qemu)* keep accepting through EMFILE, and bound a listener's peers
- *(vclient)* keep an HTTP response body's capacity within its limit
- *(vclient)* cap compression pointers followed reading a DNS name
- *(vclient)* charge queued UDP datagrams for their overhead, cap the queue
- *(vclient)* cap connections in TIME-WAIT at 8192
- *(vclient)* bound the data a listener's unaccepted connections hold
- *(vclient)* answer SYN floods with cookies and expire SYN-RECEIVED at 63 s
- *(vclient)* count a listener's half-open connections instead of scanning
- *(l2adapter)* send DHCP unicasts to the MAC the server answered from
- *(arp)* let traffic drive due retransmissions and probes
- *(dhcp)* announce a newly bound address with ARP (RFC 5227 §2.3)
- *(l2adapter)* send DHCP renewals and releases to a resolved MAC
- *(l2adapter)* drop off-link IPv6 traffic when there is no router
- *(arp,ndp)* detect neighbours that stop answering or change MAC (NUD)
- *(l2adapter)* retry unanswered ARP/NS and report failed resolution
- *(dhcp)* let a client renew the address a decline was about
- *(l2adapter)* never cache a neighbour claiming one of our own addresses
- *(arp)* drop the oldest queued packet, not the newest, when a queue fills
- *(wg)* cap the peers accept_unknown_peer adds
- *(wg)* rate-limit handshakes per source address under load
- *(wg)* limit a peer's initiations to 50 a second, whiten timestamps
- *(wg)* stop using a received cookie 5 s before its secret rotates
- *(wg)* retry an unanswered handshake as many times as the kernel
- *(wg)* stop a keepalive due with no session retrying handshakes forever
- *(slirp)* never reset a connection its listener has just accepted
- *(slirp)* keep one guest from holding every outbound dial
- *(slirp)* never strand a pump blocked on a bridge's real socket
- *(slirp)* contain a handler panic instead of losing the thread it ran on
- *(ovpn)* let no callback run once Server::close() has returned
- *(ovpn)* take an adapter peer's key before connecting its device
- *(ovpn)* keep a key's on_connect and on_disconnect in order
- *(vtcp)* stop a released connection probing a zero window forever
- *(vtcp)* give buffer memory back when idle and after close
- *(defrag)* bound the bytes held across datagrams in progress
- *(pool)* drop oversized buffers instead of pooling them
- *(wg)* run every peer's cleanup on close, even if one panics
- *(wg)* let a dropped adapter stop serving instead of leaking
- *(wg)* stop holding a lock through the adapter's connector and handlers
- *(wg)* keep the server read loop alive through a panicking callback
- *(nat)* stop holding the parent lock through translation and delivery
- *(afpacket)* contain a panicking handler on the reader thread
- *(tuntap)* contain a panicking handler on the reader thread
- *(qemu)* keep the reader alive and done signalled across a handler panic
- *(vclient)* record a timeout before a reader can see the closed connection
- *(vclient)* check for shutdown under the table lock when opening
- *(vclient)* contain a panicking L3 handler instead of losing the tick thread
- *(vtcp)* count SACKed ranges, not only bytes, when picking a lost hole
- *(vtcp)* keep RFC 6582's recover until an ACK passes it after an RTO
- *(vtcp)* stop timing out a zero-window peer that answers every probe
- *(vtcp)* keep a zero-window probe from blinding the peer to our ACKs
- *(ovpn)* export AuthHash, the type of Options::auth
- *(ovpn)* replace the module docs' pointer to TODO markers that don't exist
- *(ovpn)* use OpenVPN 2.6's control-channel windows (6 sent, 12 received)
- *(ovpn)* pass connect_freq_initial and max_auth_threads through AdapterConfig
- *(ovpn)* make AuthInfo non-exhaustive and document its fields
- *(ovpn)* make Options non-exhaustive and parse return crate::Result
- *(ovpn)* set PeerOutput::authenticated in every output
- *(ovpn)* build a new peer outside the peer table's write lock
- *(ovpn)* validate a client's soft reset before starting the new key
- *(ovpn)* accept tun packets from a client's iroutes
- *(ovpn)* stop servicing the lame-duck key's control channel
- *(ovpn)* send no TLS on a key until the client ACKs our reset
- *(ovpn)* call connector handlers and cleanups with no adapter lock held
- *(dhcp)* [**breaking**] make wire::Parsed #[non_exhaustive]
- *(dhcp)* key leases by client identifier, else htype and chaddr
- *(dhcp)* name the server in the ACK to an INFORM
- *(nat)* cap the ports the H.323 ALG opens per segment and per host
- *(sip)* find Content-Length and Content-Type by header name
- *(upnp)* serve the description documents a UPnP client fetches
- *(upnp)* cap control connections per client
- *(upnp)* bound by default what one LAN host can take through UPnP
- *(upnp)* tie ownership to the forward UPnP added, not its target
- *(upnp)* let a client renew its mapping when at the caps
- *(nat)* drop the TFTP ALG's expectation that could never match
- *(nat)* open an active FTP data port to the FTP server only
- *(stats, wg)* [**breaking**] make crate-built result structs #[non_exhaustive]
- *(impair)* give each direction its own queue_limit
- *(afxdp)* correct the mmap_ring comment on ring strides
- *(tuntap)* name the macOS utun by the unit the kernel assigned
- *(tuntap)* close the device when its reader hits a fatal error
- *(afxdp)* keep the RX thread alive when the handler panics
- *(xdp)* detach every occupied mode, not the kernel's default one
- *(sys)* build tuntap and afpacket on musl
- *(slirp)* take a half-open slot without fetch_update
- *(dhcp)* deliver client callbacks in state order, dropping stale ones
- *(nat)* open an existing mapping to any remote only for the ALG's window
- *(nat)* don't let an idle but unswept mapping hold a port
- *(nat)* only let a later fragment out behind its translated first one
- *(nat)* send a forwarded host's outbound traffic from its forwarded port
- *(ovpn)* send the server's own peer info, not the client's
- *(ovpn)* prune dead peers from the auth run queue
- *(ovpn)* keep the lame-duck key's control channel running
- *(ovpn)* don't let a fallback AES-GCM key run past its usage limit
- *(ovpn)* drop tun packets whose source is not the client's address
- *(ovpn)* keep control packets within OpenVPN's 1250-byte tls-mtu
- *(ovpn)* hold a new session untrusted until it proves reachability
- *(ovpn)* don't panic on long timers, and survive a panicking peer
- *(ovpn)* bound the control channel's send window
- *(vtcp)* let SACK evidence start loss recovery (RFC 6675)
- *(vtcp)* resend everything a timeout marks lost, go-back-N
- *(vtcp)* keep handshake timeouts out of congestion control
- *(vtcp)* don't let a lost SYN disable fast retransmit
- *(vtcp)* let sender SWS avoidance send half the peer's max window
- *(vtcp)* take the ACK of a data segment sent into our zero window
- *(vtcp)* skip PAWS once TS.Recent is 24 days stale
- *(vtcp)* count only validated segments as signs of life
- *(l2hub)* let a raised forward depth hold through L3Hub and connect_*
- *(l3hub)* deliver to the host that owns the address, default the rest
- *(wg)* draw local indexes unique across a MultiHandler
- *(wg)* let an expired peer be authorized again, and stop accept recursion
- *(vclient)* let listeners follow the client's address when it changes
- *(vclient)* accept bare LF line ends in HTTP responses, refuse bare CR
- *(vclient)* keep the HTTP request's framing the library's own
- *(vclient)* take only DNS answers to the question that was asked
- *(vclient)* treat a timeout too long for an Instant as no deadline
- *(vclient)* close the client's stacks when the last reference drops
- *(qemu)* flush queued frames on close instead of cutting them off
- *(slirp)* send the window update as soon as a read reopens it
- *(afpacket)* re-bind when the interface is deleted and comes back
- *(afxdp)* kick TX on every send when bound without NEED_WAKEUP
- *(slirp)* treat a timeout too long for an Instant as no deadline
- *(slirp)* refuse listen and listen6 on a stack that is shut down
- *(slirp)* filter and dial the canonical destination address
- *(vclient)* pick ephemeral ports by RFC 6056, not in sequence
- *(vclient)* verify inbound TCP and UDP checksums
- *(vclient)* return 0 at once from a TcpConn read into an empty buffer
- *(vclient)* refuse DNS names with empty labels or over 255 octets
- *(vclient)* accept a listener's SYNs only for its own address
- *(vclient)* send one Host header when the caller sets its own
- *(vclient)* unfold obs-fold lines and reject malformed HTTP fields
- *(vclient)* accept obs-text in HTTP field values and reason phrases
- *(vclient)* bound the memory an HTTP response can take
- *(vclient)* bound the HTTP request send by the request's deadline
- *(checksum)* add incremental_update_udp, which never writes zero
- *(packet)* sum a UDP checksum over the UDP Length, not the IP payload
- *(impair)* check the link is open and its queue empty before the fast path
- *(dhcp)* accept a DHCPRELEASE only for the address and server it names
- *(dhcp)* never offer an address off the server's subnet
- *(l2adapter)* hand only unfragmented UDP to the DHCP client
- *(connect)* bound recursion and break the reference cycle in connect_l2/l3
- *(l3hub)* match the sender's own network before routing elsewhere
- *(dhcp)* never decline an address on a conflict from an earlier check
- *(dhcp)* give the lease up when the client is stopped or restarted
- *(arp)* cap how many destinations may await resolution
- *(l2adapter)* keep a full neighbour cache from locking out real neighbours
- *(nat)* keep the inside network's directed broadcast inside
- *(slirp)* let the application restrict which host destinations guests reach
- *(slirp)* give outbound bridges 256 KiB buffers, not 1 MiB
- *(slirp)* cap half-open connections per listener
- *(slirp)* verify TCP and UDP checksums from the guest
- *(slirp)* return at once from a read into an empty buffer
- *(slirp)* check a listener's closed flag under its queue lock
- *(slirp)* never answer a stray RST with a RST
- *(slirp)* open connections only on a bare SYN
- *(slirp)* close every listener when the stack shuts down
- *(nat)* SIP ALG delimits TCP messages by Content-Length
- *(nat)* expire idle mappings without relying on sweep()
- *(nat)* SIP ALG translates only c= lines naming the inside host
- *(nat)* don't let unsolicited inbound traffic keep mappings alive
- *(nat)* keep traffic addressed to the NAT itself from leaving upstream
- *(tuntap)* size read buffers for the largest frame, drop truncated ones
- *(syscall,tuntap)* open device sockets close-on-exec
- *(afxdp)* reap TX completions before reporting backpressure
- *(afxdp)* keep kicking TX while the kernel answers EAGAIN
- *(qemu)* queue outbound frames instead of blocking on the socket
- *(afpacket)* keep the reader alive across an interface going down
- *(wg)* wire a peer's device outside the adapter's peers lock
- *(wg)* never hand out a local index that is already in use
- *(wg)* keep the answered keypair when crossing handshakes complete
- *(wg)* keep removed and expired peers from coming back
- *(vtcp)* apply PAWS and track TS.Recent in CLOSE-WAIT, CLOSING, LAST-ACK
- *(vtcp)* count keepalive idle time from the last segment received
- *(vtcp)* let timestamps decide TIME-WAIT reuse, as RFC 6191 asks
- *(vtcp)* keep keepalive running through FIN-WAIT-1 and FIN-WAIT-2
- *(vtcp)* count the FIN-WAIT-2 timeout from the release too
- *(vtcp)* do not reset from TIME-WAIT when released with unread data
- *(vtcp)* use SACK to repair holes during RTO recovery
- *(ovpn)* contain a panic in on_connect, on_data or on_disconnect
- *(ovpn)* bound the threads calling on_auth, and never panic spawning
- *(ovpn)* pair on_connect and on_disconnect when removal races a verdict
- *(ovpn)* let a stuck on_auth hold its peer only weakly
- *(ovpn)* refund a stateless answer only once the echo got a peer
- *(impair)* wait_idle from a handler returns instead of timing out
- *(l3hub)* flood broadcast and multicast without touching the TTL
- *(dhcp)* start each address check with no conflict remembered
- *(vclient)* bound DNS-over-TCP by the query deadline, keep Set-Cookie apart, tighten defrag repeats
- *(slirp)* close a bridge's host socket once it reaches TIME-WAIT
- *(time)* clamp a huge host clock reading instead of panicking
- *(packet)* use the Routing header's final destination in the pseudo-header
- *(l2adapter)* drop the gateway and ARP state that came with a lost lease
- *(l2hub)* learn no group source MACs, and cap addresses moving ports
- *(dhcp)* address server replies per RFC 2131 §4.1 (giaddr, BROADCAST)
- *(dhcp)* split long options per RFC 3396 and parse option overload
- *(dhcp)* saturate an oversized server lease time instead of panicking
- *(dhcp)* validate offers and ACKs, and time leases per RFC 2131 §4.4
- *(dhcp)* probe a newly leased address with ARP and decline a conflict
- *(icmp)* send no error when the IPv6 header chain cannot be walked
- *(l2adapter)* resolve IPv4 link-local destinations on-link
- *(l2adapter)* ignore frames tagged for another VLAN
- *(pcap)* count a record as torn until its write returns
- *(impair)* make wait_idle wait for the delivery in progress
- *(impair)* keep the release thread alive when a handler panics
- *(impair)* make poll not wait on the release thread's delivery
- *(dhcp)* accept a DHCPDECLINE only for an address we gave that client
- *(l2adapter)* learn from a Neighbor Solicitation only when it targets us
- *(l3hub)* decrement TTL and bound forwarding depth
- *(vclient,slirp)* release a connection when its handle is dropped
- *(slirp)* send a detached peer its RSTs before dropping its side
- *(slirp)* fragment echo replies to reassembled pings to fit the link
- *(vclient)* refuse oversized UDP datagrams, number IPv4 datagrams
- *(vclient)* remove only the connection checked, never its successor
- *(vclient)* reset segments for no connection, cap half-open accepts
- *(vclient)* try each resolved address in the client's family for HTTP
- *(vclient)* refuse CR/LF in HTTP request targets and header fields
- *(slirp)* hold back client segments until the dialed SYN is accepted
- *(vclient)* retry truncated DNS answers over TCP
- *(vclient)* validate Content-Length as RFC 9112 §6.3 requires
- *(vclient)* reassemble inbound IP fragments before demultiplexing
- *(vclient)* fail writes after our own close with BrokenPipe
- *(slirp)* recognise a repeated fragment after its neighbour arrived
- *(slirp)* stop TIME-WAIT bridges from holding live connection slots
- *(slirp)* close the whole TCP bridge when the virtual side aborts
- *(vclient)* bound chunk sizes in the chunked body decoder
- *(slirp)* reassemble IPv6 datagrams once, drop nested Fragment headers
- *(ovpn)* make PeerOutput #[non_exhaustive]
- *(ovpn)* answer a UDP client's first packet statelessly
- *(ovpn)* run on_auth on its own thread, without the peer's lock
- *(ovpn)* never block the server's shared threads on a TCP write
- *(ovpn)* give a new TCP connection its own peer entry
- *(ovpn)* do not time out idle TCP clients when keepalive is off
- *(ovpn)* validate a new session's hard reset before installing it
- *(ovpn)* apply ACKs before refusing an out-of-window control packet
- *(ovpn)* retransmit control packets for as long as the key lives
- *(vtcp)* reset a released connection when data arrives or is left unread
- *(wg)* release callback locks before calling the callbacks
- *(wg)* don't hold staged packets for peers that can't handshake
- *(wg)* end our handshake attempt when the peer's is confirmed
- *(wg)* claim a timer-driven initiation when it is decided
- *(wg)* don't hold the handler list's lock while a handler runs
- *(wg)* keep staged packets when the current keypair is unusable
- *(wg)* don't take a peer's endpoint from a cookie reply
- *(vtcp)* throttle the ACKs owed to PAWS-rejected segments
- *(vtcp)* throttle challenge ACKs for segments carrying a payload
- *(vtcp)* cancel a pending Early Retransmit when the window closes
- *(vtcp)* apply the FIN-WAIT-2 timeout only to released connections
- *(vtcp)* leave room for TCP options within the MSS
- *(vtcp)* don't enter fast recovery during RTO recovery
- *(vtcp)* don't resend a hole already retransmitted on a SACK partial ACK
- *(xdp)* offloaded XDP cannot do zero-copy AF_XDP
- *(xdp)* let a narrower capture prefix add to a broader one
- *(xdp)* keep the capture record until the kernel delete succeeds
- *(xdp)* detach a netlink attachment only while it is still ours
- *(xdp)* refuse Mode::HARDWARE with a clear error
- *(tuntap)* refuse interface names that do not fit IFNAMSIZ
- *(afxdp)* stop diverting traffic when the device is closed
- *(xdp)* pass no redirect flags on kernels before 5.3
- *(afpacket)* never deliver a truncated frame
- *(afpacket)* put back the VLAN tag the kernel strips
- *(afxdp)* read the pre-5.4 XDP_MMAP_OFFSETS layout correctly
- *(nat)* drop NAT64 fragments that reach past the IPv4 size limit
- *(nat)* refuse IPv4 packets with an unexpired source route in NAT64
- *(nat)* answer pings from inside to the NAT's public address
- *(nat)* only translate inbound traffic addressed to the NAT
- *(nat)* never resize a TCP payload the NAT cannot adjust for
- *(nat)* apply TCP sequence adjustment to first fragments
- *(nat)* answer IPv6 packets too large for IPv4 with Packet Too Big
- *(nat)* carry the traffic class across NAT64 translation
- *(nat)* expire stale reassemblies as fragments arrive
- *(nat)* refuse a second port forward to the same inside endpoint
- *(nat)* keep a forward's session when the same forward is renewed
- *(ovpn)* support auth SHA384/SHA512, and tolerate digests AEAD never uses
- *(nat)* translate ICMPv6 errors from the NAT64 inside to ICMPv4
- *(nat)* translate ICMP errors sent from the inside
- *(nat)* re-fragment reassembled datagrams to their fragment size
- *(nat)* give SIP media an even RTP port with RTCP on the next
- *(ovpn)* release the listening ports when Server::close returns
- *(ovpn)* renegotiate AES-GCM keys at OpenVPN's AEAD usage limit
- *(ovpn)* refuse a client with no usable data cipher instead of guessing
- *(ovpn)* fire on_disconnect only for peers that fired on_connect
- *(ovpn)* let AdapterConfig set the server's limits and timers
- *(ovpn)* reject data packet id 0 in the replay window
- *(vtcp)* hold TIME-WAIT for 60 s, and let a newer SYN take the 4-tuple over
- *(nat)* check the IHL in UPnP's public local-packet entry point
- *(nat)* translate IP fragments one at a time instead of as whole datagrams
- *(nat)* translate ICMPv4 errors to ICMPv6 as RFC 7915 specifies
- *(nat)* map IPv4 hosts into the configured NAT64 prefix (RFC 6052)
- *(nat)* hairpin inside-to-inside traffic sent to the public address
- *(nat)* adjust TCP sequence numbers after an ALG resizes a payload
- *(nat)* validate inbound ICMP errors and fix the quoted packet's checksums
- *(nat)* track TCP sessions per remote and meet RFC idle timeouts
- *(nat)* route SSDP discovery from the inside only
- *(nat)* UPnP clients may only delete the mappings they created
- *(nat)* bound expectation, fragment and UPnP control state
- *(nat)* keep expectations, forwards and dynamic ports from colliding
- *(nat)* SIP ALG rewrites whole addresses, not substrings
- *(nat)* only open FTP and IRC data ports for the host that asked
- *(nat)* pick inbound ALG helpers by the remote's service port
- *(nat)* never emit a zero UDP checksum after rewriting a datagram
- *(nat)* bound the UPnP control request's Content-Length
- *(nat)* drop IPv4 fragments that reach past the datagram end
- *(nat)* compute full transport checksums correctly in NAT64 and the ALGs
- *(ovpn)* refuse unauthenticated data channels and check CBC padding
- *(ovpn)* stop requiring the client's options string to round-trip
- *(ovpn)* accept empty strings in the key-method-2 message
- *(ovpn)* put the packet id before the compression byte in CBC packets
- *(ovpn)* check the TLS config up front and keep the UDP loop alive
- *(ovpn)* refuse TCP packets too large for the 16-bit frame length
- *(ovpn)* make close() and drop actually stop the TCP side
- *(ovpn)* answer a rejected client with AUTH_FAILED, close dropped TCP peers
- *(ovpn)* fire on_connect once per session, outside the peer lock
- *(ovpn)* bound the peer table and time out idle and stalled peers
- *(ovpn)* route control packets by session id and validate ACKs
- *(ovpn)* drop malformed datagrams instead of tearing down the peer
- *(ovpn)* refuse to send once the data-channel packet id is spent
- *(slirp)* never panic when out of threads, and bound what a guest can spawn
- *(slirp)* report a reset as an error, and bound blocking writes
- *(vclient)* bound the UDP receive queue
- *(vclient)* accept DNS answers only from the server, to the question
- *(vclient)* bound HTTP requests with a timeout
- *(vclient)* parse HTTP responses incrementally and reject short bodies
- *(vclient)* parse IPv6 and other URL forms, and send a correct Host
- *(vclient)* report a reset connection as an error, not end of stream
- *(vclient)* make Client::close close what the client has open
- *(vclient)* never hand out an ephemeral port still in use
- *(vclient)* closing a listener removes only its own registration
- *(vclient)* reset inbound connections no listener can take
- *(vclient)* count any completed handshake as a successful dial
- *(slirp)* relay zero-length UDP datagrams, and honour the UDP length
- *(slirp)* answer ICMPv6 echo only for the stack's own address
- *(slirp)* send a computed UDP checksum of zero as 0xFFFF
- *(slirp)* relay UDP replies of any size, fragmented for the link
- *(slirp)* reassemble IP fragments instead of misreading them
- *(slirp)* keep UDP flows alive across ICMP unreachable errors
- *(slirp)* unregister listeners when they are closed or dropped
- *(slirp)* bound the threads that virtual-network packets can create
- *(slirp)* stop flows keeping a dropped stack alive
- *(slirp)* let shutdown close a bridge whose writer is blocked
- *(slirp)* dial outbound TCP off the packet path
- *(fragment)* refuse to re-fragment past the largest fragment offset
- *(checksum)* sum in 64 bits so large buffers cannot overflow
- *(icmp)* send the multicast-exempt ICMPv6 errors, add a rate limiter
- *(l2hub)* put priority-tagged frames in the port's VLAN
- *(pool)* stop exposing uninitialised memory, and bound the default pool
- *(l2adapter)* learn ARP entries by RFC 826's merge rule
- *(l2adapter)* validate NDP messages and honour the Override flag
- *(l2adapter)* keep link-local IPv6 on-link, and broadcast to the subnet
- *(packet)* reject IPv4 headers shorter than 20 bytes
- *(accept)* let serve() detach devices whose peer hangs up
- *(l3hub)* route by longest prefix, and drop traffic from detached ports
- *(packet)* write a zero UDP checksum as 0xFFFF
- *(l2hub)* reclaim expired MAC entries, and filter frames for the ingress port
- *(l2adapter)* bound and expire the NDP queue, flush it on any learning
- *(dhcp)* retransmit, renew, rebind and expire leases in the client
- *(dhcp)* never lease the server, router, network or broadcast address
- *(dhcp)* answer DHCPREQUEST per client state, with NAKs
- *(dhcp)* expire leases and offers, and never hand out a held address
- *(xdp)* encode BPF instructions in host byte order
- *(pcap)* write each record in one piece and stop after a torn one
- *(impair)* claim the wrapped device's traffic only once a handler is set
- *(impair)* keep release order when poll runs beside the release thread
- *(impair)* no overflow panics on huge delays; duplicates obey queue_limit
- *(impair)* do not join the release thread from itself
- *(afxdp)* size the XSKMAP for every queue Device::open binds
- *(xdp)* capture neighbor solicitations by target, not by group
- *(tuntap)* give the TAP's userspace end a MAC of its own
- *(tuntap)* close the device on close/drop, and wait for a handler
- *(afpacket)* keep the socket fd open until the reader thread is done
- *(afpacket)* open the socket with protocol 0 and bind with ETH_P_ALL
- *(xdp)* refuse element access the kernel would size past our buffer
- *(afxdp)* make ring produce/consume take &mut self
- *(afxdp)* give ETHTOOL_GRXRINGS the whole struct ethtool_rxnfc
- *(xdp)* compile xdp and afxdp only on 64-bit targets
- *(vtcp)* throttle challenge ACKs, check RSTs against the advertised window
- *(vtcp)* seed MAX.SND.WND for SYN-cookie connections
- *(vtcp)* delay Early Retransmit by a quarter RTT to ride out reordering
- *(vtcp)* hold SYN payload until the connection is established
- *(vtcp)* time out FIN-WAIT-2 when the peer goes quiet
- *(vtcp)* monotonic timestamps, and a SYN-ACK that answers the SYN's options
- *(vtcp)* do not cancel the persist timer when rearming keepalive
- *(vtcp)* negotiate the MSS per RFC 9293 on every open path
- *(vtcp)* grow cwnd only when it is in use, and cut from the flight size
- *(vtcp)* resend the same persist probe byte, and ignore zero-window ACKs for loss
- *(vtcp)* bind SYN cookies to both addresses and the peer's MSS
- *(vtcp)* derive ISNs per RFC 6528 from a keyed hash and a 4 µs clock
- *(vtcp)* drop segments whose ACK is ahead of SND.NXT or far behind SND.UNA
- *(wg)* engage the cookie defence, and finish accepting unknown peers
- *(wg)* refuse small-order keys, bind cookies to the port, keep replay state
- *(wg)* hold unconfirmed keypairs as next, and keep the index table bounded
- *(wg)* stop leaking a keypair on every send, and wipe keys when freed
- *(wg)* update the replay window only after a packet authenticates
- *(qemu)* hold frames until a handler is set, and close the socket on close
- *(vtcp)* keep ACKs coming after a loss in a small window
- *(vtcp)* do not scale the window of a received SYN or SYN-ACK
- *(vtcp)* retransmit the next hole on a partial ACK
- *(vtcp)* make the SACK scoreboard safe, then enable SACK by default
- *(vtcp)* report the newest SACK block first
- *(vtcp)* merge adjacent out-of-order ranges instead of dropping them

### Other

- *(slirp)* time the Nagle check where the segments leave the stack
- cargo fmt
- wait out transient handles instead of counting them at once
- *(wg)* wait for the adapter to record both peers' devices
- *(fuzz)* the l2 target drives the adapter's timers too
- *(readme)* show a WireGuard peer's allowed IPs
- *(xdp)* [**breaking**] keep xdp internals private
- *(afxdp)* [**breaking**] keep afxdp internals private
- *(tuntap)* document the undocumented `name` methods
- *(l2adapter)* [**breaking**] keep arp and ndp internals private
- *(dhcp)* [**breaking**] keep dhcp internals private
- *(ovpn)* [**breaking**] keep ovpn internals private
- *(wg)* [**breaking**] keep wg internals private
- *(nat)* [**breaking**] keep nat internals private
- *(core)* document the remaining public constants and fields
- *(stats)* [**breaking**] keep the hub counter block private
- *(vclient)* document the remaining public Response fields
- *(vtcp)* [**breaking**] keep vtcp internals private
- *(wg)* don't count a give-up whose retry falls after the run
- fix two CI flakes, in ovpn on_connect counts and the Nagle check
- *(nat)* widen wall-clock bounds to 2 s, scaling the work to match
- give the write-after-close checks room on a loaded machine
- *(dhcp)* keep a two-second margin on the client's "not yet" checks
- *(nat)* parse UPnP requests as they arrive, over small buffers
- *(nat)* sweep the PPTP call table on an interval, not per request
- *(nat)* bound defrag memory and stop rescanning per fragment
- *(nat)* refuse a new flow on a full port pool in constant time
- *(dhcp)* index leases by address instead of rebuilding a set per packet
- *(slirp)* retry the port-unreachable test when its port is taken
- *(dhcp)* say how long the client really holds an offer
- *(ovpn)* keep the real peer's socket open in the rate-limit tests
- *(defrag)* cap fragments held per datagram
- *(vtcp)* add a harsher end-to-end fuzz run over a lossy link
- document the public functions that had no docs
- *(wg)* document peer expiry, add_peer refresh, and dynamic multi-handler
- *(l3hub)* describe what the default route receives
- *(vtcp)* list the RFCs the engine implements, fix abort and tick docs
- *(l2adapter)* say that DHCP replaces a static IPv4 gateway
- *(dhcp)* make the client's callback ordering and restart exact
- *(slirp)* document listener limits, dest-filter pre-checks, stream drop
- *(vclient)* document drop teardown and dial_tcp's fixed timeout
- *(vclient)* say that DNS goes out the host's sockets
- bring the README up to date
- *(vtcp)* make buffer work per segment proportional to the segment
- build the DHCP server config with setters, as the conventions ask
- *(wg)* correct two stale TODO comments in the handshake
- *(fuzz)* fuzz sequences of packets, and the stateful parsers
- *(xdp)* clobber the call registers with fill, not an index loop
- *(qemu)* use a match for the listener's address, not let-else
- *(vtcp)* do not link the private secret module from public docs
- *(fuzz)* stop tracking build output, and ignore fuzz run state
- name purecrypto, not the RustCrypto crates it replaced
- tidy the wasm timer list
- drop agent worktrees committed by mistake

## [0.1.7](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.6...v0.1.7) - 2026-09-27

### Added

- run on wasm32-unknown-unknown and wasm32-wasip1

## [0.1.6](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.5...v0.1.6) - 2026-09-27

### Fixed

- *(vtcp)* end ACK storms while closing, and fix window handling on ACKs
- *(vtcp)* stop shrinking the receive window, fix handshake and zero-window stalls
- *(vtcp)* send queued data before the FIN, and recover stalled closes

### Other

- cap loss bursts in the lossy-link fuzz test

## [0.1.5](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.4...v0.1.5) - 2026-09-23

### Other

- wait for the echo on a channel instead of sleeping
- Make config structs #[non_exhaustive], with chainable setters
- report an over-long interface name as not found
- xdp, afxdp: build for fullrust, the libc-free Linux target

## [0.1.4](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.3...v0.1.4) - 2026-09-19

### Other

- per-prefix capture rules for a protocol or a TCP/UDP port
### Changed (breaking)

- **purecrypto 0.9, MSRV 1.89.** purecrypto 0.9 needs Rust 1.89, so the
  crate's minimum moves with it; a dependency-free build is held to the same
  floor so there is one number to remember.

### Added — XDP capture

- **Per-prefix rules: protocol and port capture.** `xdp::Rule` selects, on a
  captured prefix, everything (`Any`), one IP protocol (`Proto`), or one TCP
  or UDP port (`Port`). `Capture::add_rule` / `remove_rule` /
  `rules` / `rules_for` and the `Device::capture_add_rule` /
  `capture_remove_rule` wrappers manage them; `Capture::add` is now
  `add_rule(prefix, Rule::Any)`. The rule list lives in the trie value, so
  the program checks it after an address hit without another lookup. The port
  compared is the captured endpoint's: destination on a destination hit,
  source on a source hit. A prefix with only narrow rules is assumed to be
  shared with the host stack, which keeps its ARP and neighbor discovery.
- `CaptureConfig::max_rules_per_prefix` (default 8, at most
  `MAX_RULES_PER_PREFIX`) sizes the trie value and the unrolled rule walk.
- IPv4 ports are read behind options (`ihl` is honoured) and never from a
  non-first fragment. IPv6 extension headers are not walked: a port rule needs
  TCP/UDP directly after the fixed header.
- An eBPF interpreter in the unit tests executes the generated program
  against synthetic IPv4, IPv6 and ARP frames and simulated maps, so the
  codegen's verdicts are checked without root. The kernel tests in
  `tests/xdp_kernel.rs` load every rule-cap variant through the verifier and
  exercise a port rule on the host's own address end to end.
- `Program::test_run` / `Capture::test_run` run the loaded program in the
  kernel against a supplied frame (`BPF_PROG_TEST_RUN`) and return the verdict
  and the mean cost per run. The kernel tests use it to check the JITed
  program's verdicts against the interpreter's, and
  `what_the_capture_program_costs_per_packet` prints nanoseconds per packet
  for a far miss, a near miss and both kinds of hit as the set grows from 1 to
  2048 hosts.

### Added — AF_XDP

- `Device::send_batch` transmits a burst with one TX ring update and at most
  one wakeup syscall, where `send` pays for both per frame. It returns how
  many frames were taken, so a caller can offer the rest again once the kernel
  has completed some.
- `Config::rx_spin` makes an RX thread re-check an empty ring a number of
  times before blocking in `poll()`. Off by default.
- `Config::rx_cpus` pins RX thread `i` to `rx_cpus[i]`. A CPU that does not
  exist fails `Device::open`. Off by default.

### Fixed — AF_XDP

- **`Device::open` failed with `EINVAL` on every interface.** All four ring
  mappings were sized for 16-byte descriptors, but the FILL and COMPLETION
  rings hold 8-byte addresses, and the kernel refuses a mapping longer than
  the ring it allocated. Each ring is now mapped at its own element size, and
  every setup step names itself in its error instead of surfacing a bare
  errno.

### Changed — XDP capture

- The capture program no longer parses the transport header on a miss. The
  protocol and port are read after an address hit, into registers rather
  than stack slots, and not at all when the prefix holds a `Rule::Any`, which
  is now always encoded first. An IPv4 packet that matches nothing executes 23
  instructions where it executed 43. `Capture::rules_for` reports rules in
  that walked order; `Capture::rules` still reports insertion order.

- The `LPM_TRIE` value is now `max_rules_per_prefix * 4` bytes of packed
  rules rather than a `u32` flag. Anything reading `CaptureMaps` directly, or
  passing its own maps to `build_program`, has to match. The
  `afxdp::ProgramSource::External` path is unaffected.

## [0.1.3](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.2...v0.1.3) - 2026-09-01

### Other

- release-plz authenticates with the org PAT, like every other crate
- VLAN access and trunk ports
- O(1) unicast forwarding, per-port limits, loop bounding
- fix the L2Hub benchmark, which measured nothing
- fix two toolchain-drift lint failures; cover the TLS version range
- move all crypto to purecrypto, dropping rustls
- move all crypto to purecrypto
- edition 2024, MSRV 1.88
- fix the four failing jobs, drop two unused dependencies
- fuzzing, benchmarks, and a dependency audit
- AF_PACKET, cross-platform builds, and the rest of the counters
- observability, capture, and link impairment
- complete the wire type layer through L4
- a capture can never widen into the whole interface
- keep an explicitly captured solicited-node group
- document the xdp feature and the afxdp breaking changes
- kernel-side integration tests behind --ignored
- address-scoped capture, zero-copy, and a per-queue datapath

### Added — L2Hub

- **VLAN port modes.** `PortMode::Access { vlan }` is an edge port belonging to
  one VLAN that never sees a tag; `PortMode::Trunk { allowed, native }` carries
  several, tagged, with the native VLAN untagged. Flooding reaches only ports
  carrying the frame's VLAN, and a learned address is a hit only on the VLAN it
  was learned on. Set with `set_port_mode`; ports start
  `PortMode::transparent()`, which passes every VLAN through with tags
  untouched, so an unconfigured switch behaves exactly as before.
- `VlanSet`, a 4096-bit set of VLAN ids. The bitmap is boxed so "every VLAN" —
  much the commonest setting — costs a discriminant rather than 512 bytes.
- `set_port_mac_limit` to lift the learning cap on uplinks, `loop_drops()` and
  `set_max_forward_depth` for looped topologies, `port_mode` to read a port's
  configuration back.

### Changed (breaking)

- **All cryptography now comes from [`purecrypto`](https://crates.io/crates/purecrypto).**
  `curve25519-dalek`, `chacha20poly1305`, `blake2`, `aes`, `aes-gcm`, `cbc`,
  `sha1`, `sha2`, `hmac`, `zeroize`, `rand_core`, `getrandom`, `rustls`,
  `rustls-rustcrypto`, `rsa` and `rustls-pemfile` are all gone. The crate's
  entire dependency tree is now `libc` and `purecrypto`, with **no transitive
  dependencies at all** — down from around forty packages.
- `ovpn::ServerConfig::tls_config` and `ovpn::AdapterConfig::tls_config` are
  now `Arc<purecrypto::tls::Config>` instead of `Arc<rustls::ServerConfig>`.
  The config must carry an identity *and* an explicit `.rng(...)` entropy
  source: purecrypto's TLS core is sans-I/O, so it takes entropy as an input
  rather than reaching for a global.
- `ovpn::install_crypto_provider` and `ovpn::crypto_provider` are removed.
  They existed only to manage rustls's process-wide provider, which
  purecrypto has no equivalent of.
- **Edition 2024, MSRV 1.88**, which is what purecrypto requires.

### Added

- Known-answer tests for the WireGuard primitives: X25519 against RFC 7748
  §5.2 and §6.1, BLAKE2s-256 against RFC 7693, MixHash against `h || data`,
  the MAC1/cookie keys against `Blake2s256(label || Spub)`, and the
  data-channel nonce layout. Every previous test here was a self-consistency
  round-trip, which passes just as happily against a subtly wrong primitive
  and only fails when talking to a real peer.

### Removed

- The hand-rolled MD5 and HMAC in `ovpn/prf.rs` — about 250 lines of
  hand-written crypto — now that `purecrypto` supplies both. MD5 was only
  hand-written because none of the RustCrypto crates the `ovpn` feature
  pulled in happened to provide it.
- The `unsafe` block-slice transmute in `ovpn/data.rs`: purecrypto's CBC
  takes `&mut [u8]`, so there is nothing to reinterpret.

### Fixed

- All six `cargo-deny` advisories, by removing the dependencies that carried
  them rather than by annotating around them: four in an outdated
  `rustls-webpki` (RUSTSEC-2026-0049/0098/0099/0104), the `rsa` Marvin timing
  sidechannel (RUSTSEC-2023-0071), and unmaintained `paste`
  (RUSTSEC-2024-0436). `rustls-pemfile` (RUSTSEC-2025-0134) went earlier, as
  a declared-but-unused dependency.
- `aead_seal_in_place` no longer allocates. purecrypto's AEAD uses a detached
  tag, so the plaintext is encrypted directly in the caller's buffer instead
  of via a temporary `Vec`.

### Added — packet toolkit

- **L4 wire types** (`l4` module, re-exported at the root): `TcpSegment`,
  `UdpDatagram` and `IcmpMessage` as `#[repr(transparent)]` views, plus
  `TcpFlags` and the `FiveTuple` that identifies a flow. Reachable straight
  from a packet with `Packet::tcp()`, `udp()`, `icmp()` and `five_tuple()`.
- **The rest of both IP headers on `Packet`**: identification, flags, fragment
  offset, DSCP/ECN, options, traffic class, flow label, and setters for all of
  them. `set_hop_limit` / `decrement_hop_limit` update the IPv4 header checksum
  incrementally and report expiry instead of wrapping to 255.
- **Checksums**: `verify_ipv4_checksum`, `recompute_ipv4_checksum`,
  `verify_transport_checksum`, `recompute_transport_checksum`,
  `recompute_checksums`, a standalone `transport_checksum`, and
  `incremental_update` (RFC 1624) for cheap address and port rewrites.
- **`build` module**: `build_ipv4`, `build_ipv6`, `build_ip`, `build_udp`,
  `build_tcp`, `build_icmpv4`, `build_icmpv6` — every length and checksum
  filled in — plus `push_vlan` / `pop_vlan`.
- **`icmp` module**: `time_exceeded`, `packet_too_big`, `port_unreachable`,
  `no_route`, `admin_prohibited` and the general `error`, each returning a
  complete IP packet. `may_reply` implements the RFC 1812 / RFC 4443 rules on
  when a reply is forbidden — never to another error, a later fragment, or
  anything broadcast or multicast — which is what keeps an error storm from
  starting.
- **`fragment` module**: IPv4 egress fragmentation that honours the option copy
  bit, preserves offsets when re-fragmenting a fragment, and reports
  `DontFragment` / `NotFragmentable` so the caller knows to send an ICMP error
  instead.
- **`DeviceStats` and `HubStats`**: rx/tx/drop counters on devices, and
  received/forwarded/flooded/dropped on hubs. Devices opt in through a
  defaulted `L2Device::stats` / `L3Device::stats`, so existing implementors are
  unaffected. Wired into pipes, hubs, TUN/TAP, AF_PACKET, taps and impaired
  links.
- **`pcap` feature**: `PcapWriter` plus `TapL2` / `TapL3`, which wrap any device
  and mirror both directions into a file Wireshark or `tcpdump -r` opens. A
  write failure counts an error rather than taking the link down. No
  dependencies.
- **`impair` feature**: `ImpairL2` / `ImpairL3` apply delay, jitter, loss,
  duplication, corruption and a rate limit in both directions, released from a
  delay queue in deadline order so jitter reorders traffic the way a real link
  does. Seeding the RNG makes a run reproducible. No dependencies.
- **`afpacket` feature**: an L2 device bound to an existing interface via an
  `AF_PACKET` socket, with optional promiscuous mode and an inbound-only
  filter. Needs no eBPF and creates no interface, which makes it the simplest
  way to put a real NIC in a topology.
- **Fuzzing**: `cargo-fuzz` targets in `fuzz/` covering the packet and L4
  accessors, ICMP generation, fragmentation, DHCP, DNS, vTCP, OpenVPN control,
  WireGuard, defrag and the NAT with every ALG registered. `tests/robustness.rs`
  runs the same bodies on stable in ordinary CI, over mutated, random and
  exhaustively-truncated input.
- **Benchmarks**: `benches/hot_path.rs`, harness-free and dependency-free,
  covering accessors, checksums, hub forwarding and the per-packet work a
  forwarder does.
- **CI**: `cargo-deny` (advisories, licences, and a ban on vendored C crypto
  backends), an MSRV check, a Windows build, docs for individual feature
  subsets, a benchmark run, and a rotating-seed robustness sweep.
- Ergonomics: `Deref`, `AsRef<[u8]>`, `PartialEq`, `Eq` and `Hash` on `Frame`
  and `Packet`; `to_vec()` on both; `vlan_pcp`, `vlan_dei` and `vlan_tci` on
  `Frame`.

### Fixed

- **IPv6 extension headers are no longer mistaken for transport protocols.**
  `Packet::ip_protocol()` returned the raw next-header field, so a hop-by-hop,
  routing or fragment header reported itself as the upper-layer protocol, and
  `payload()` started 40 bytes in regardless. Both now walk the chain. The walk
  is bounded, so a crafted chain cannot spin, and it refuses to point at a
  transport header that a later fragment does not carry.
  `ipv6_next_header()` still returns the literal field.
- **`full` builds on every platform.** It pulls in `xdp` and `afxdp`, which
  were not gated on `target_os`, so enabling it anywhere but Linux failed to
  compile. Those modules are now Linux-only, and `tuntap` gained an
  `Unsupported` stub in place of its `compile_error!`.
- Intra-doc links that resolved only under `--all-features` are fixed, so
  `cargo doc` is clean for any feature subset.
- A panic in `set_hop_limit` on a truncated IPv4 header, found by the new
  randomized sweep on its first run.

### Changed

- `L2Hub` learns per (VLAN, MAC) rather than per MAC, so one address appearing
  on two VLANs is no longer read as a station flapping between ports. Flooding
  still reaches every port; ports carry no VLAN membership to filter on.
- `PipeL2::inject` / `PipeL3::inject` count as received rather than
  transmitted. Delivery is unchanged.
- The `namespace` module is now `accept` — it is about accept loops and has
  nothing to do with network namespaces. Private, so no API change.
- `slirp`'s IPv6 extension-header walker delegates to the crate's canonical one
  instead of keeping a second, less careful copy.

### Added — XDP and AF_XDP

- **`xdp` feature**: the in-kernel half of packet capture, split out of
  `afxdp`. eBPF instruction encoding with a label-patching assembler
  (`xdp::insn`), map create/lookup/update/delete with `LPM_TRIE` and `XSKMAP`
  helpers (`xdp::Map`), program loading that surfaces the verifier log
  (`xdp::Program`), and attachment that prefers the native driver hook, falls
  back to rtnetlink and detaches on drop (`xdp::Link`).
- **`xdp::Capture`**: an XDP program that redirects only the IP prefixes in its
  set and passes everything else to the host stack. The set lives in two
  `LPM_TRIE` maps, so `add`/`remove` take effect with no reload and matching is
  longest-prefix. Matches destination, source or either address; captures ARP
  for the v4 set so a captured address stays resolvable; and inserts the
  solicited-node multicast address alongside an IPv6 `/128` so neighbour
  discovery arrives.
- **Working zero-copy**: `Mode::AUTO` attaches native-first, the bind tries
  `XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP` before copy mode, and `XDP_OPTIONS` is
  read back so `Device::zerocopy()` reports what the kernel did rather than what
  was asked for. `Zerocopy::Require` refuses to start on the slow path.
- **One socket, UMEM and poll thread per RX queue.** Queues are discovered via
  `ETHTOOL_GCHANNELS`/`GRXRINGS`. Each sending thread sticks to one queue so it
  cannot reorder its own frames.
- Optional kernel-side busy polling (`SO_PREFER_BUSY_POLL`, `SO_BUSY_POLL`,
  `SO_BUSY_POLL_BUDGET`) and optional huge-page UMEM.
- **A capture can never widen into the whole interface.** `Capture::add`
  refuses a `/0` in either family, refuses anything shorter than
  `CaptureConfig::min_prefix_v4` / `min_prefix_v6` (both default to 1, i.e.
  reject only the catch-all), and refuses any addition that would leave the set
  covering an entire address family — a per-prefix floor alone does not catch
  two `/1`s. Both checks run before anything is written to a map, so a refused
  call leaves the capture set unchanged. `CaptureConfig::validate` additionally
  rejects a zero or over-wide floor and a `default_action` that is not `PASS` or
  `DROP`.
- `tests/xdp_kernel.rs`: `#[ignore]`d tests covering verifier acceptance for
  every program configuration, LPM trie semantics against the real kernel, the
  veth datapath, and that a refused over-broad prefix leaves the kernel-side
  trie untouched.

### Fixed

- `bpf_redirect_map` now passes `XDP_PASS` as its miss verdict. With `flags = 0`
  a frame arriving on a queue with no registered socket returned `XDP_ABORTED`
  and was dropped, rather than falling through to the host stack.
- The RX path handed each frame to the handler through a freshly allocated
  `Vec`. `L2Handler` takes `&Frame`, so the borrow cannot outlive the call and
  the UMEM chunk is not recycled until after the batch — the copy was never
  needed.
- TX no longer drains the completion ring on every send, and skips the `sendto`
  wakeup unless the ring asks for one.
- `send` used to silently truncate a frame larger than the UMEM chunk; it now
  returns `InvalidInput`.
- Dropping a `Device` now stops its poll threads. They hold their own `Arc`s, so
  previously they spun until the process exited.

### Changed (breaking)

- `afxdp::bpf` is removed. Use `pktkit::xdp`, which covers everything it did
  plus maps, attach modes and the verifier log.
- `afxdp::Config::queue_id: u32` becomes `queue_ids: Vec<u32>`; empty means
  every RX queue.
- `afxdp::Config::copy: bool` becomes `zerocopy: Zerocopy`.
- `afxdp::Config` gains `mode`, `program`, `busy_poll` and `huge_pages`.
- An `afxdp::Device` now captures **nothing** until `Device::capture_add` names
  an address, where it previously redirected every packet on the interface.
  Attaching to a live NIC no longer takes the host's own traffic with it.

## [0.1.2](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.1...v0.1.2) - 2026-05-25

### Other

- de-flake the outbound-vtcp large-transfer test
- drive outbound TCP NAT with vtcp::Conn (parity with Go)
- server-side Listen (inbound virtual TCP accept)

## [0.1.1](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.0...v0.1.1) - 2026-05-25

### Other

- slirp v6 accept, ovpn retransmit/peer-info, nat UPnP TCP, vclient UDP, wg multi-handler

## [0.1.0] — unreleased

First release: a feature-gated Rust port of the Go
[pktkit](https://github.com/KarpelesLab/pktkit) toolkit.

### Core (always compiled, zero dependencies)

- Zero-copy `Frame` and `Packet` (`#[repr(transparent)]` over `[u8]`).
- `MacAddr`, `EtherType`, `Protocol`, `IpPrefix` value types.
- `L2Device` / `L3Device` traits and `L2Acceptor` / `L2Connector` /
  `L3Connector` connector traits, with a synchronous callback model.
- `L2Hub` (MAC-learning switch with aging) and `L3Hub` (prefix-routing hub).
- `PipeL2` / `PipeL3` in-memory devices, `connect_l2` / `connect_l3`, `serve`.
- `BufferPool`, RFC 1071 `checksum` + pseudo-header checksum.

### Opt-in features

- `l2adapter` — ARP, NDP, gateway routing, DHCP-driven `L2Adapter`.
- `dhcp` — DHCP wire codec, client state machine, and full `Server`.
- `qemu` — QEMU socket netdev protocol (TCP + Unix listener/dialer).
- `tuntap` — TUN/TAP on Linux (`/dev/net/tun`) and TUN on macOS (`utun`).
- `afxdp` — Linux AF_XDP zero-copy sockets (UMEM rings, eBPF redirect).
- `vtcp` — RFC-9293 TCP engine (SACK, window scaling, timestamps, NewReno +
  HighSpeed, SYN cookies).
- `slirp` — userspace NAT stack (`L3Device` + `L3Connector`) with inbound
  virtual TCP accept.
- `vclient` — DNS resolver, TCP dial over `vtcp`, minimal HTTP/1.1 client.
- `nat` — packet-level IPv4 NAT, NAT64, defrag, and FTP/TFTP/IRC/SIP/H.323/
  PPTP ALGs + UPnP IGD.
- `wg` — WireGuard (Noise IKpsk2 handshake, ChaCha20-Poly1305 transport,
  replay window, cookie-reply DoS mitigation, per-peer L3 isolation).
- `ovpn` — OpenVPN server (rustls TLS 1.2 control channel, AES-GCM/CBC data
  channel, PRF key derivation, UDP/TCP servers, L3/L2 adapter).
- `full` — enables all of the above.

### Dependencies

The default build pulls in **zero** third-party crates. `libc` is used only by
`tuntap`/`afxdp`; RustCrypto primitive crates only by `wg`/`ovpn`; and `rustls`
(an explicit, opt-in exception) only by `ovpn`'s control channel — configured
with the pure-Rust `rustls-rustcrypto` provider, so there is no vendored
C/assembly (`ring`/`aws-lc-rs`) and no compile-time build script. The whole
crate cross-compiles.

### Known gaps

Tracked with `// TODO(<feature>)` markers in the source:

- `ovpn`: tls-crypt/tls-auth, control retransmit timers, fuller PUSH_REPLY.
- `afxdp`: datapath needs root + a NIC to exercise (pure logic is unit-tested).
- `tuntap`: macOS `utun` is type-checked, not yet run on a macOS host.
- `slirp`: inbound virtual TCP accept is IPv4-only.
- `nat`: UPnP's live TCP control endpoint awaits the virtual TCP listener wiring.
