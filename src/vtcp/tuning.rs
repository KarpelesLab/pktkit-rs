//! The TCP settings a driver's embedder may choose for the connections it
//! opens and accepts (`vclient::ClientConfig::tcp`, `slirp::Stack::set_tcp`),
//! the rest of [`ConnConfig`] being the driver's to fill in.

use super::conn::{CongestionKind, ConnConfig, DEFAULT_RECV_BUF_MAX, DEFAULT_SEND_BUF_MAX};
use super::ecn::EcnMode;
use super::plpmtud::MtuProbing;

/// TCP settings for the connections a `vclient::Client` or a `slirp::Stack`
/// opens and accepts. Each is the [`ConnConfig`] field of the same name,
/// and defaults as it does.
///
/// Build one from `Tuning::default()` with the chainable setters:
/// `Tuning::default().congestion(CongestionKind::Bbr).fast_open(true)`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Tuning {
    /// The congestion controller ([`ConnConfig::congestion`]). CUBIC by
    /// default; BBR for long, lossy paths.
    pub congestion: CongestionKind,
    /// Explicit Congestion Notification ([`ConnConfig::ecn`]). By default
    /// a peer's request is accepted, and none made.
    pub ecn: EcnMode,
    /// Pace sending ([`ConnConfig::pacing`]). On by default.
    pub pacing: bool,
    /// The most buffer auto-tuning grows a connection's send buffer to
    /// ([`ConnConfig::send_buf_max`]). 16 MiB by default.
    pub send_buf_max: usize,
    /// The most buffer auto-tuning grows a connection's receive buffer to,
    /// which also sets the window scale offered ([`ConnConfig::recv_buf_max`]).
    /// 16 MiB by default.
    pub recv_buf_max: usize,
    /// TCP Fast Open (RFC 7413; [`ConnConfig::fast_open`]): take data in a
    /// SYN that brings a valid cookie, before the handshake completes. For
    /// a `vclient::Client`, also send it: `Client::dial_tcp_with_data` puts
    /// the first data in the SYN once the server has given a cookie. Off by
    /// default: SYN data may be delivered twice (RFC 7413 §6), so only
    /// requests safe to repeat belong in it. On `wasm32-unknown-unknown`
    /// cookies can be forged (see [`ConnConfig::fast_open`]): leave it off
    /// there when peers may be hostile.
    pub fast_open: bool,
    /// Packetization Layer Path MTU Discovery ([`ConnConfig::mtu_probing`]).
    /// Once full-sized segments keep timing out, by default.
    pub mtu_probing: MtuProbing,
}

setters! {
    Tuning {
        set congestion: CongestionKind;
        set ecn: EcnMode;
        set pacing: bool;
        set send_buf_max: usize;
        set recv_buf_max: usize;
        set fast_open: bool;
        set mtu_probing: MtuProbing;
    }
}

impl Default for Tuning {
    fn default() -> Self {
        let c = ConnConfig::default();
        debug_assert_eq!(
            (c.send_buf_max, c.recv_buf_max),
            (DEFAULT_SEND_BUF_MAX, DEFAULT_RECV_BUF_MAX)
        );
        Self {
            congestion: c.congestion,
            ecn: c.ecn,
            pacing: c.pacing,
            send_buf_max: c.send_buf_max,
            recv_buf_max: c.recv_buf_max,
            fast_open: c.fast_open,
            mtu_probing: c.mtu_probing,
        }
    }
}

impl Tuning {
    /// `cfg` with these settings in place of its own.
    #[cfg_attr(not(any(feature = "vclient", feature = "slirp")), allow(dead_code))]
    pub(crate) fn apply(&self, cfg: ConnConfig) -> ConnConfig {
        cfg.congestion(self.congestion)
            .ecn(self.ecn)
            .pacing(self.pacing)
            .send_buf_max(self.send_buf_max)
            .recv_buf_max(self.recv_buf_max)
            .fast_open(self.fast_open)
            .mtu_probing(self.mtu_probing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conn_configs() {
        let c = Tuning::default().apply(ConnConfig::default());
        let d = ConnConfig::default();
        assert_eq!(format!("{c:?}"), format!("{d:?}"));
        let t = Tuning::default()
            .congestion(CongestionKind::Bbr)
            .ecn(EcnMode::Accurate)
            .pacing(false)
            .send_buf_max(1)
            .recv_buf_max(2)
            .fast_open(true)
            .mtu_probing(MtuProbing::Always);
        let c = t.apply(ConnConfig::default().mss(1000));
        assert_eq!(c.congestion, CongestionKind::Bbr);
        assert_eq!(c.ecn, EcnMode::Accurate);
        assert!(!c.pacing && c.fast_open);
        assert_eq!((c.send_buf_max, c.recv_buf_max), (1, 2));
        assert_eq!(c.mtu_probing, MtuProbing::Always);
        assert_eq!(c.mss, 1000);
    }
}
