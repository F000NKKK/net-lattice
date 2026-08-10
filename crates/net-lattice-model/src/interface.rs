use std::fmt;

use net_lattice_core::{Error, Id, Result};

use crate::mac::MacAddress;

/// Identifies an [`Interface`].
///
/// # Construction convention: OS ifindex widened, never hash-synthesized
///
/// Unlike route, neighbor, and address identity (which are hash-synthesized
/// or natural-key comparisons over multiple fields), every `InterfaceId` in
/// practice is constructed directly from the platform's native `u32`
/// interface index (`ifindex` on Linux, the equivalent index on Windows and
/// Darwin) widened to `u64` — e.g. `InterfaceId::new(u64::from(ifindex))`.
/// This construction path is identical across all three backend
/// implementations (`net-lattice-backend-linux`, `-windows`, `-darwin`); no
/// backend ever derives an `InterfaceId` from a hash or any other source.
///
/// [`crate::diff::Diff::compute`] relies on this convention: it
/// cross-references a raw `interface_index: u32` field captured on a
/// snapshot entry (e.g. a neighbor or address's observed `interface_index`)
/// against a typed `InterfaceId` by widening rather than by narrowing the
/// `InterfaceId` back down — `InterfaceId::new(u64::from(entry.interface_index))`
/// — rather than truncating an existing `InterfaceId`'s `u64` value down to
/// `u32` for comparison. This is a deliberate style choice (both directions
/// are equivalent given the construction convention above), not a
/// correctness requirement: no current code ever constructs an `InterfaceId`
/// with a value outside `u32`'s range, so no information loss is possible
/// either way today. Any future caller minting an `InterfaceId` manually
/// should preserve the same convention to keep this comparison meaningful.
pub type InterfaceId = Id<Interface>;

/// The kind of a network interface.
///
/// Platforms expose different classifications (Linux `ARPHRD_*`, Windows
/// `IfType`, BSD/macOS `IFT_*`); this enum carries the subset that maps
/// cleanly across all of them. It is `#[non_exhaustive]` so adding
/// platform-specific kinds later is not a breaking change — see
/// ARCHITECTURE.md's note on model extensibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InterfaceKind {
    /// Ethernet and other IEEE 802 MAC-layer interfaces.
    Ethernet,
    /// Wi-Fi / 802.11 wireless.
    Wireless,
    /// Loopback (`lo` / `Loopback Pseudo-Interface`).
    Loopback,
    /// Point-to-point tunnels and virtual links without a broadcast domain.
    PointToPoint,
    /// A bridge or other software switch aggregating member interfaces.
    Bridge,
    /// Anything not yet classified — the raw OS-supplied type code, when
    /// available, is carried alongside for diagnostics.
    Other(u32),
}

impl fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterfaceKind::Ethernet => write!(f, "ethernet"),
            InterfaceKind::Wireless => write!(f, "wireless"),
            InterfaceKind::Loopback => write!(f, "loopback"),
            InterfaceKind::PointToPoint => write!(f, "point-to-point"),
            InterfaceKind::Bridge => write!(f, "bridge"),
            InterfaceKind::Other(code) => write!(f, "other({code})"),
        }
    }
}

/// The administrative state of an interface, as configured by the operator.
///
/// Distinct from [`OperationalState`]: an interface can be administratively
/// up but operationally down (cable unplugged), or administratively down
/// (and therefore always operationally down).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AdminState {
    Up,
    Down,
    /// The platform does not expose a separate administrative state (e.g.
    /// BSD/macOS route-socket interfaces report a single combined state).
    Unknown,
}

/// The administrative state requested for an interface configuration patch.
///
/// This is intentionally separate from observed [`AdminState`]. In
/// particular, [`AdminState::Unknown`] reports an observation limitation and
/// is never valid caller intent. A successful configuration operation returns
/// a fresh observed [`Interface`] instead of converting this value back into
/// [`AdminState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DesiredAdminState {
    /// Request that the interface be administratively enabled.
    Up,
    /// Request that the interface be administratively disabled.
    Down,
}

/// A partial desired configuration for one network interface.
///
/// `InterfaceConfig` describes only the settings requested by a caller; it
/// is not an observed [`Interface`] and does not require callers to supply
/// names, hardware attributes, or operational state. At least one setting
/// must be requested. Zero is never a valid MTU, while every other MTU range
/// remains platform- and interface-specific and is validated by the backend.
///
/// Build a patch with [`InterfaceConfig::new`], then submit it through the
/// facade's interface-configuration API or as
/// [`crate::Mutation::SetInterfaceConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceConfig {
    interface_id: InterfaceId,
    admin_state: Option<DesiredAdminState>,
    mtu: Option<u32>,
}

impl InterfaceConfig {
    /// Creates a patch for `interface_id`.
    ///
    /// Returns [`Error::InvalidState`] when no setting is requested or when
    /// `mtu` is zero. Platform-specific MTU constraints are checked by the
    /// backend at submission time.
    pub fn new(
        interface_id: InterfaceId,
        admin_state: Option<DesiredAdminState>,
        mtu: Option<u32>,
    ) -> Result<Self> {
        if admin_state.is_none() && mtu.is_none() || mtu == Some(0) {
            return Err(Error::InvalidState);
        }

        Ok(Self {
            interface_id,
            admin_state,
            mtu,
        })
    }

    /// Returns the interface targeted by this patch.
    pub const fn interface_id(&self) -> InterfaceId {
        self.interface_id
    }

    /// Returns the requested administrative state, if any.
    pub const fn admin_state(&self) -> Option<DesiredAdminState> {
        self.admin_state
    }

    /// Returns the requested MTU, if any.
    pub const fn mtu(&self) -> Option<u32> {
        self.mtu
    }
}

/// The operational state of an interface, as observed from the link layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OperationalState {
    Up,
    Down,
    /// The interface is up but has no carrier / lower-layer connectivity.
    NoCarrier,
    /// The platform does not expose a separate operational state.
    Unknown,
}

/// A network interface.
///
/// `#[non_exhaustive]`: platforms carry different interface fields (Linux
/// exposes `carrier`, `txqueuelen`, `type`; Windows exposes `MediaType`,
/// `OperationalStatus`; BSD/macOS expose a combined flags word). Marking
/// this non-exhaustive now means adding platform-specific fields later is
/// not a breaking change for consumers who construct an `Interface` via
/// [`Interface::new`] rather than a struct literal — see ARCHITECTURE.md's
/// note on model extensibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Interface {
    pub id: InterfaceId,
    /// The OS-level interface index (`ifindex` on Linux, `InterfaceIndex` on
    /// Windows, `if_index` on BSD/macOS). This is the same raw value
    /// `Route::interface_index` carries — kept here as the canonical home
    /// now that the `interface` domain exists (Stage 0.4).
    pub index: u32,
    pub name: String,
    pub kind: InterfaceKind,
    pub mac: Option<MacAddress>,
    pub mtu: Option<u32>,
    pub admin_state: AdminState,
    pub operational_state: OperationalState,
}

impl Interface {
    /// Creates an interface with no MAC address, MTU, admin state, or
    /// operational state set (the latter two default to `Unknown`).
    pub fn new(id: InterfaceId, index: u32, name: impl Into<String>, kind: InterfaceKind) -> Self {
        Self {
            id,
            index,
            name: name.into(),
            kind,
            mac: None,
            mtu: None,
            admin_state: AdminState::Unknown,
            operational_state: OperationalState::Unknown,
        }
    }

    /// Sets the hardware (link-layer) address.
    pub fn with_mac(mut self, mac: MacAddress) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Sets the maximum transmission unit.
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Sets the observed administrative state.
    pub fn with_admin_state(mut self, state: AdminState) -> Self {
        self.admin_state = state;
        self
    }

    /// Sets the observed operational (link-layer) state.
    pub fn with_operational_state(mut self, state: OperationalState) -> Self {
        self.operational_state = state;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_interface_has_no_optional_fields() {
        let iface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet);
        assert!(iface.mac.is_none());
        assert!(iface.mtu.is_none());
        assert_eq!(iface.admin_state, AdminState::Unknown);
        assert_eq!(iface.operational_state, OperationalState::Unknown);
    }

    #[test]
    fn builder_methods_set_optional_fields() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let iface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet)
            .with_mac(mac)
            .with_mtu(1500)
            .with_admin_state(AdminState::Up)
            .with_operational_state(OperationalState::Up);
        assert_eq!(iface.mac, Some(mac));
        assert_eq!(iface.mtu, Some(1500));
        assert_eq!(iface.admin_state, AdminState::Up);
        assert_eq!(iface.operational_state, OperationalState::Up);
    }

    #[test]
    fn kind_displays() {
        assert_eq!(InterfaceKind::Ethernet.to_string(), "ethernet");
        assert_eq!(InterfaceKind::Wireless.to_string(), "wireless");
        assert_eq!(InterfaceKind::Loopback.to_string(), "loopback");
        assert_eq!(InterfaceKind::PointToPoint.to_string(), "point-to-point");
        assert_eq!(InterfaceKind::Bridge.to_string(), "bridge");
        assert_eq!(InterfaceKind::Other(42).to_string(), "other(42)");
    }

    #[test]
    fn interface_config_preserves_only_requested_settings() {
        let config =
            InterfaceConfig::new(InterfaceId::new(7), Some(DesiredAdminState::Up), Some(1500))
                .expect("valid partial patch");

        assert_eq!(config.interface_id(), InterfaceId::new(7));
        assert_eq!(config.admin_state(), Some(DesiredAdminState::Up));
        assert_eq!(config.mtu(), Some(1500));
    }

    #[test]
    fn interface_config_allows_each_setting_independently() {
        let admin_only =
            InterfaceConfig::new(InterfaceId::new(7), Some(DesiredAdminState::Down), None)
                .expect("admin-only patch");
        let mtu_only =
            InterfaceConfig::new(InterfaceId::new(7), None, Some(9000)).expect("mtu-only patch");

        assert_eq!(admin_only.mtu(), None);
        assert_eq!(mtu_only.admin_state(), None);
    }

    #[test]
    fn interface_config_rejects_empty_or_zero_mtu_patches() {
        assert!(matches!(
            InterfaceConfig::new(InterfaceId::new(7), None, None),
            Err(Error::InvalidState)
        ));
        assert!(matches!(
            InterfaceConfig::new(InterfaceId::new(7), None, Some(0)),
            Err(Error::InvalidState)
        ));
    }
}
