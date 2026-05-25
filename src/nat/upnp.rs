//! UPnP IGD scaffolding.
//!
//! TODO(nat): the Go upstream spins up a SOAP server on a vclient TCP listener
//! and answers SSDP M-SEARCH multicast. Both depend on the vclient feature
//! (virtual TCP + HTTP) and a hand-rolled SSDP/SOAP implementation. This
//! module ships only the configuration struct so callers can keep their
//! existing wiring shape; the actual server is intentionally not wired up.

use crate::nat::helper::{Helper, LocalHelper};
use crate::nat::nat::Nat;
use crate::Packet;
use std::time::Duration;

/// Configuration knobs for the UPnP IGD helper.
#[derive(Debug, Clone)]
pub struct UPnPConfig {
    /// TCP port for the SOAP control server (default 5000).
    pub control_port: u16,
    /// Allowed outside port ranges `(low, high)` inclusive. Empty = allow all.
    pub allowed_ports: Vec<(u16, u16)>,
    /// Maximum total port forwards (0 = unlimited).
    pub max_mappings: usize,
    /// Maximum port forwards per inside IP (0 = unlimited).
    pub max_per_client: usize,
    /// Maximum lease duration (`None` = permanent allowed).
    pub lease_duration: Option<Duration>,
}

impl Default for UPnPConfig {
    fn default() -> Self {
        UPnPConfig {
            control_port: 5000,
            allowed_ports: Vec::new(),
            max_mappings: 0,
            max_per_client: 0,
            lease_duration: None,
        }
    }
}

/// A no-op placeholder UPnP helper. Register it via
/// [`Nat::add_local_helper`](crate::nat::Nat::add_local_helper); it currently
/// never consumes traffic.
#[derive(Debug)]
pub struct UPnPHelper {
    cfg: UPnPConfig,
}

impl UPnPHelper {
    pub fn new(cfg: UPnPConfig) -> UPnPHelper {
        UPnPHelper { cfg }
    }

    pub fn config(&self) -> &UPnPConfig {
        &self.cfg
    }
}

impl Helper for UPnPHelper {
    fn name(&self) -> &str {
        "upnp"
    }
}

impl LocalHelper for UPnPHelper {
    fn handle_local(&self, _nat: &Nat, _pkt: &Packet) -> bool {
        // TODO(nat): SSDP M-SEARCH responder + SOAP control server (needs
        // virtual TCP + a small HTTP parser, see Go upstream upnp.go).
        false
    }
}
