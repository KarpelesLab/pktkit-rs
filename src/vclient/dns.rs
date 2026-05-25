//! Stub DNS resolver. Public type so `Client::resolve` compiles; the actual
//! query/parser is `// TODO(vclient): port from Go upstream`.

use std::io;
use std::net::{IpAddr, SocketAddr};

/// Configure a [`Resolver`].
#[derive(Debug, Clone, Default)]
pub struct ResolverConfig {
    /// DNS servers to query (UDP/53 by default).
    pub servers: Vec<SocketAddr>,
}

/// A DNS resolver. **TODO(vclient):** wires through to a `UdpSocket` and
/// parses RFC 1035 responses; currently returns `Unsupported`.
#[derive(Debug, Clone, Default)]
pub struct Resolver {
    cfg: ResolverConfig,
}

impl Resolver {
    pub fn new(cfg: ResolverConfig) -> Resolver {
        Resolver { cfg }
    }

    /// Resolve `name` to one or more IP addresses.
    pub fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
        let _ = &self.cfg;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TODO(vclient): DNS resolver not yet ported",
        ))
    }
}
