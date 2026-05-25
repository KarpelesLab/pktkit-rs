# Design rules for the pktkit-rs port

Read this before touching any feature module. The Go upstream
(`../pktkit/`) is the source of truth for behaviour. Your job is to map
its idioms into Rust idioms without bloating the dependency footprint.

## Crate shape

- One crate, `pktkit`. Every subpackage from Go is a Cargo *feature*, not a
  separate crate. The default build pulls in zero dependencies.
- Each feature module lives at `src/<feature>.rs` (single file) or
  `src/<feature>/mod.rs` + submodules.
- Feature is declared in `Cargo.toml`. Crypto features pull in vetted
  RustCrypto crates; nothing else is acceptable except `libc` (for OS FFI).
- Pub re-exports for the feature go in `src/lib.rs` under the `#[cfg(feature = "...")]` block.

## Type conventions

- Wire types are `#[repr(transparent)] pub struct Foo([u8]);` with
  `Foo::from_slice(&[u8]) -> &Foo` and `from_mut(&mut [u8]) -> &mut Foo`.
  Accessors are `&self`. See `Frame` / `Packet`.
- Owned buffers are `Vec<u8>`. Borrow as `&Foo` to use accessors.
- IP types come from `std::net` (`Ipv4Addr`, `Ipv6Addr`, `IpAddr`). Use
  `crate::IpPrefix` for CIDR. MAC is `crate::MacAddr` (6-byte newtype).
- Wrap raw u8/u16 enums as `#[repr(transparent)] pub struct Foo(pub u16)`
  with `pub const VARIANT: Foo = Foo(0x1234)` — extensible without
  exhaustiveness pain. See `EtherType` / `Protocol`.

## Concurrency

- No async. Devices are `Send + Sync` with synchronous callbacks.
- Handler storage: `Arc<Mutex<Option<HandlerType>>>` so background reader
  threads can clone-and-call without holding the lock.
- Background work uses `std::thread::spawn`. Stop it via an `AtomicBool`
  or by closing the underlying I/O.

## Devices

- `L2Device` / `L3Device` are object-safe. Implementors live in
  `Arc<Self>` typically — `pub fn new(...) -> Arc<Self>`.
- Hub-style attachers (`L2Hub`, `L3Hub`) take `D: L2Device + 'static`.
- Adapters that own L3 → L2 wiring set the L3 device's handler in their
  constructor (via `Arc::downgrade(&self)` to avoid a cycle).

## Error handling

- Use `crate::Result<T> = std::io::Result<T>` throughout. Map other
  errors with `io::Error::new(io::ErrorKind::InvalidData, ...)`.

## Testing

- Put `#[cfg(test)] mod tests` at the bottom of each file or in
  `src/<feature>/tests.rs`.
- Avoid OS-touching tests that need elevated privileges (TUN/TAP, raw
  sockets). Unit-test wire codecs and state machines on synthetic data.
- For network tests use loopback + ephemeral port (`127.0.0.1:0`).

## Style

- Comments explain *why*, not *what*. Match the surrounding density.
- `#[derive(Debug)]` on every public struct, or a manual `impl Debug`
  when the type contains non-`Debug` fields (Mutex<Box<dyn Write>>, etc.).
- Hot-path functions: `#[inline]` on tiny accessors.
- Re-export module-level types through `pub use` in `lib.rs` only when
  it makes the call site cleaner; the rest stays inside the module.

## Translating Go idioms

| Go                                | Rust                                                |
| --------------------------------- | --------------------------------------------------- |
| `[]byte`                          | `&[u8]` or `Vec<u8>`; `&Foo` for typed wrappers     |
| `sync.Mutex`                      | `std::sync::Mutex`                                  |
| `sync/atomic`                     | `std::sync::atomic`                                 |
| `atomic.Pointer[func(...)]`       | `Arc<Mutex<Option<Handler>>>` (close enough)        |
| `chan struct{}`                   | `Arc<(Mutex<bool>, Condvar)>` or `AtomicBool`       |
| `time.Duration`                   | `std::time::Duration`                               |
| `time.Now()`                      | `std::time::Instant::now()`                         |
| `crypto/rand.Read`                | `getrandom` or `rand_core::OsRng` (gated features)  |
| `math/rand.Uint32`                | `crate::rand::u32()` (non-crypto)                   |
| `net.IP`                          | `std::net::IpAddr`                                  |
| `netip.Prefix`                    | `crate::IpPrefix`                                   |
| `net.HardwareAddr`                | `crate::MacAddr`                                    |
| `error`                           | `crate::Result<T>` aka `std::io::Result<T>`         |
| `go func() { ... }`               | `std::thread::spawn(move \|\| { ... })`             |
| `defer x.Close()`                 | RAII via Drop                                       |
| `interface{}`                     | `&dyn Any` or a trait + `dyn Trait`                 |
| `sync.Pool`                       | `crate::BufferPool`                                 |

## What NOT to port literally

- Go's per-CPU pools — `BufferPool` is enough.
- Go's `sync.Pool` finalizers — Rust's Drop handles cleanup deterministically.
- `unsafe` pointer aliasing for noescape — use Rust's borrow checker;
  the optimiser usually does the right thing.
- Test helpers that mock the entire net stack — favour smaller targeted
  unit tests over end-to-end harnesses.

## Per-feature notes

- **vtcp**: massive state machine. Aim for RFC-correct behaviour on the
  happy path; CUBIC and SACK can land in a follow-up commit.
- **slirp**: each peer's TCP/UDP connections backed by `std::net::TcpStream`
  / `UdpSocket` from real OS sockets.
- **vclient**: layer on top of vtcp + UDP; HTTP client is `std::net`-based
  with a hand-rolled HTTP/1.1 parser.
- **nat**: connection-tracking table keyed by 5-tuple. ALGs are independent
  stateless transforms applied at packet boundaries.
- **wg**: Noise IK handshake — use `x25519-dalek`, `chacha20poly1305`,
  `blake2`, `hmac`, `sha2`. Don't roll your own primitives.
- **ovpn**: hardest. Has a full TLS 1.2 handshake. If you have to choose
  between completeness and a working subset, ship the subset and document
  what isn't there.
