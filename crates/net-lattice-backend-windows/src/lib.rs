//! Windows backend for Net Lattice: implements `net-lattice-platform`'s provider
//! traits via the Windows IP Helper API.
//!
//! Only ever compiled for `target_os = "windows"` — its dependencies
//! (`windows`, Windows-only) are gated the same way in `Cargo.toml`. See
//! ARCHITECTURE.md for how this crate binds `net-lattice-platform`'s generic
//! `RouteProvider::Route` associated type to the concrete
//! `net_lattice_model::route::Route`.

#![cfg(target_os = "windows")]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread;
use std::time::Duration;

use net_lattice_core::{Error, Id, PlatformErrorCode, Result};
use net_lattice_model::dns::{DnsConfig, NewDnsConfig};
use net_lattice_model::event::{ChangeKind, Event, EventDomain, EventFilter};
use net_lattice_model::ifaddr::{InterfaceAddress, InterfaceAddressId, NewInterfaceAddress};
use net_lattice_model::interface::{
    AdminState, DesiredAdminState, Interface, InterfaceConfig, InterfaceKind, OperationalState,
};
use net_lattice_model::mac::MacAddress;
use net_lattice_model::neighbor::{NeighborEntry, NeighborId, NeighborState, StaticNeighbor};
use net_lattice_model::route::{Route, RouteConfig, RouteId};
use net_lattice_model::{IpAddress, Network};
use net_lattice_platform::{
    Addition, AdditionProvider, AddressMutator, AddressProvider, Capability, CapabilityProvider,
    DnsMutator, DnsProvider, EventProvider, EventReceiver, EventSender, InterfaceMutator,
    InterfaceProvider, NeighborMutator, NeighborProvider, RouteMutator, RouteProvider,
};
#[cfg(feature = "async")]
use net_lattice_platform::{TokioEventProvider, TokioEventReceiver, TokioEventSender};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED, ERROR_OBJECT_ALREADY_EXISTS, HANDLE,
    WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateIpNetEntry2,
    CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST, DNS_SETTINGS, DNS_SETTINGS_VERSION1,
    DeleteIpForwardEntry2, DeleteIpNetEntry2, DeleteUnicastIpAddressEntry, FreeMibTable,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, GetIfEntry, GetIfEntry2, GetIfTable2,
    GetIpForwardTable2, GetIpInterfaceEntry, GetIpNetEntry2, GetIpNetTable2,
    GetUnicastIpAddressEntry, GetUnicastIpAddressTable, IP_ADAPTER_ADDRESSES_LH,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IF_ADMIN_STATUS_DOWN,
    MIB_IF_ADMIN_STATUS_UP, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IFROW, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, MibAddInstance,
    MibDeleteInstance, MibInitialNotification, NotifyIpInterfaceChange, NotifyRouteChange2,
    NotifyUnicastIpAddressChange, SetDnsSettings, SetIfEntry, SetInterfaceDnsSettings,
    SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::{
    IfOperStatusDormant, IfOperStatusDown, IfOperStatusLowerLayerDown, IfOperStatusUp,
    NET_IF_ADMIN_STATUS_UP, NET_LUID_LH,
};
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0,
    NL_NEIGHBOR_STATE, NlnsDelay, NlnsIncomplete, NlnsPermanent, NlnsProbe, NlnsReachable,
    NlnsStale, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};
use windows::core::{GUID, PWSTR};

const AF_UNSPEC: ADDRESS_FAMILY = ADDRESS_FAMILY(0);

// IANA `ifType` values (RFC 2863), not exposed as named constants by the
// `windows` crate's `MIB_IF_ROW2::Type` binding.
const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_IEEE80211: u32 = 71;
const IF_TYPE_L2_VLAN: u32 = 135;
const IF_TYPE_BRIDGE: u32 = 209;

/// The Windows IP Helper API-backed implementation of Net Lattice's provider
/// traits.
pub struct WindowsBackend {
    runtime: tokio::runtime::Runtime,
}

impl WindowsBackend {
    /// Creates a Windows IP Helper backend and initializes its internal runtime.
    pub fn new() -> Result<Self> {
        let runtime =
            tokio::runtime::Runtime::new().map_err(|err| Error::Platform(io_error_code(&err)))?;
        Ok(Self { runtime })
    }
}

/// IP Helper provides notifications for routes, IP interfaces, and unicast
/// addresses, but has no native neighbor-table change registration. Reject a
/// selected neighbor domain before allocating callback state or registering
/// any native subscription.
fn supports_event_filter(filter: &EventFilter) -> bool {
    !filter.selects_domain(EventDomain::Neighbor)
}

fn io_error_code(err: &std::io::Error) -> PlatformErrorCode {
    PlatformErrorCode::Windows(err.raw_os_error().unwrap_or(0) as u32)
}

/// Placeholder identity scheme: a route has no kernel-assigned numeric ID,
/// so this hashes its defining fields. See ARCHITECTURE.md's open Object
/// Identity question — this is not a long-term answer, only enough to give
/// `Stage 0.2` a `RouteId` to work with.
///
/// Hashes destination, gateway, and outgoing interface together so that
/// two routes to the same destination that differ only in gateway or
/// interface (a common case with multiple default routes, or ECMP-like
/// setups) don't collide on the same `RouteId`.
fn synthesize_route_id(
    destination: &Network,
    gateway: &Option<IpAddress>,
    interface_index: Option<u32>,
) -> RouteId {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    destination.hash(&mut hasher);
    gateway.hash(&mut hasher);
    interface_index.hash(&mut hasher);
    RouteId::new(hasher.finish())
}

fn std_ip_to_ip_address(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(addr) => IpAddress::from(net_lattice_ip::Ipv4Address::from(addr)),
        IpAddr::V6(addr) => IpAddress::from(net_lattice_ip::Ipv6Address::from(addr)),
    }
}

fn ip_address_to_std(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::V4(addr) => IpAddr::V4(addr.into()),
        IpAddress::V6(addr) => IpAddr::V6(addr.into()),
    }
}

fn nul_terminated_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn config_list(config: &[impl std::fmt::Display]) -> String {
    config
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn adapter_guid(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Result<GUID> {
    let adapter_name =
        unsafe { adapter.AdapterName.to_string() }.map_err(|_| Error::InvalidState)?;
    GUID::try_from(adapter_name.trim_matches(|character| character == '{' || character == '}'))
        .map_err(|_| Error::InvalidState)
}

fn network_to_std(network: Network) -> (IpAddr, u8) {
    match network {
        Network::V4(net) => (IpAddr::V4(net.address().into()), net.prefix().value()),
        Network::V6(net) => (IpAddr::V6(net.address().into()), net.prefix().value()),
    }
}

fn validate_route_family(route: &RouteConfig) -> Result<()> {
    if let Some(gateway) = route.gateway {
        let destination_is_v4 = matches!(route.destination, Network::V4(_));
        let gateway_is_v4 = matches!(gateway, IpAddress::V4(_));
        if destination_is_v4 != gateway_is_v4 {
            return Err(Error::InvalidState);
        }
    }
    Ok(())
}

/// Reads the address out of a `SOCKADDR_INET` union, dispatching on its
/// `si_family` tag. Returns `None` for `AF_UNSPEC` (used by `NextHop` to mean
/// "no gateway, on-link route").
///
/// # Safety
/// `addr` must be a validly initialized `SOCKADDR_INET` (true for anything
/// returned by `GetIpForwardTable2`/`GetIfTable2`).
unsafe fn sockaddr_inet_to_ip(addr: &SOCKADDR_INET) -> Option<IpAddr> {
    match unsafe { addr.si_family } {
        AF_INET => {
            let sin = unsafe { addr.Ipv4 };
            let b = unsafe { sin.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                b.s_b1, b.s_b2, b.s_b3, b.s_b4,
            )))
        }
        AF_INET6 => {
            let sin6 = unsafe { addr.Ipv6 };
            let bytes = unsafe { sin6.sin6_addr.u.Byte };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Builds a `SOCKADDR_INET` for `addr`, tagged with the matching address
/// family. All other fields (port, flow info, scope) are zeroed — routing
/// tables don't use them.
fn ip_to_sockaddr_inet(addr: IpAddr) -> SOCKADDR_INET {
    match addr {
        IpAddr::V4(addr) => {
            let [b1, b2, b3, b4] = addr.octets();
            let in_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_un_b: IN_ADDR_0_0 {
                        s_b1: b1,
                        s_b2: b2,
                        s_b3: b3,
                        s_b4: b4,
                    },
                },
            };
            SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: in_addr,
                    sin_zero: [0; 8],
                },
            }
        }
        IpAddr::V6(addr) => {
            let in6_addr = IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: addr.octets(),
                },
            };
            SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: in6_addr,
                    Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
                },
            }
        }
    }
}

/// Resolves a change-notification row's interface index through its
/// `InterfaceLuid`, falling back to the row's own `InterfaceIndex` only if
/// the LUID cannot be resolved.
///
/// `NotifyRouteChange2` and `NotifyUnicastIpAddressChange` both document
/// that the `MIB_IPFORWARD_ROW2`/`MIB_UNICASTIPADDRESS_ROW` passed to their
/// callback "contains incomplete data" — only enough to call
/// `GetIpForwardEntry2`/`GetUnicastIpAddressEntry` and look the complete
/// entry back up (Microsoft Learn,
/// `nf-netioapi-notifyroutechange2`/`nf-netioapi-notifyunicastipaddresschange`).
/// Both lookup functions accept either `InterfaceLuid` or `InterfaceIndex`
/// as the interface key, but only `InterfaceLuid` is documented as always
/// populated on the notification row; `InterfaceIndex` may be left at its
/// zero default. Hashing a zero/stale `InterfaceIndex` into
/// `synthesize_route_id`/`synthesize_interface_address_id` would then
/// disagree with the id a full `GetIpForwardTable2`/
/// `GetUnicastIpAddressTable` read computes for the same entry.
///
/// `ConvertInterfaceLuidToIndex` is a lightweight local lookup keyed only on
/// the interface itself, so — unlike a full `GetIpForwardEntry2`/
/// `GetUnicastIpAddressEntry` re-query — it stays available even after the
/// notified route or address entry itself has already been deleted (a
/// `MibDeleteInstance` notification's route/address no longer exists, but
/// its owning interface still does).
fn resolve_notification_interface_index(luid: NET_LUID_LH, fallback: u32) -> u32 {
    let mut index = 0u32;
    let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if status.0 == 0 && index != 0 {
        index
    } else {
        fallback
    }
}

/// Builds the row an ordinary `GetIpForwardTable2` read would have produced
/// for the same route, from a possibly-incomplete change-notification row.
///
/// Per Microsoft's documented remarks for `NotifyRouteChange2`
/// (`nf-netioapi-notifyroutechange2`), an application "should allocate a
/// `MIB_IPFORWARD_ROW2` structure and initialize it with the
/// `DestinationPrefix`, `NextHop`, `InterfaceLuid` and `InterfaceIndex`
/// members" from the notification row — those four fields are the
/// documented-reliable subset, present on every notification including
/// `MibDeleteInstance` (the row is "incomplete" only with respect to
/// everything else, e.g. `Metric`, `Protocol`, `Age`). `InterfaceIndex` can
/// still be resolved through `InterfaceLuid` for extra safety (a `Luid`
/// never changes for a given adapter, unlike `InterfaceIndex`, which
/// Microsoft documents as non-persistent across adapter disable/enable), but
/// no caching is needed: both fields are already reliable on any
/// notification kind, per the same documented guarantee that applies to
/// `DestinationPrefix`/`NextHop`.
fn corrected_route_notification_row(row: &MIB_IPFORWARD_ROW2) -> MIB_IPFORWARD_ROW2 {
    let mut corrected = *row;
    corrected.InterfaceIndex =
        resolve_notification_interface_index(row.InterfaceLuid, row.InterfaceIndex);
    corrected
}

fn row_to_route(row: &MIB_IPFORWARD_ROW2) -> Result<Option<Route>> {
    let Some(destination_addr) = (unsafe { sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix) })
    else {
        return Ok(None);
    };
    let prefix_len = row.DestinationPrefix.PrefixLength;

    let destination = match destination_addr {
        IpAddr::V4(addr) => {
            let Some(prefix) = net_lattice_ip::Ipv4PrefixLength::new(prefix_len) else {
                return Ok(None);
            };
            Network::from(net_lattice_ip::Ipv4Network::new(addr.into(), prefix))
        }
        IpAddr::V6(addr) => {
            let Some(prefix) = net_lattice_ip::Ipv6PrefixLength::new(prefix_len) else {
                return Ok(None);
            };
            Network::from(net_lattice_ip::Ipv6Network::new(addr.into(), prefix))
        }
    };

    let gateway = unsafe { sockaddr_inet_to_ip(&row.NextHop) }.map(std_ip_to_ip_address);

    let interface_index = if row.InterfaceIndex != 0 {
        Some(row.InterfaceIndex)
    } else {
        None
    };

    let id = synthesize_route_id(&destination, &gateway, interface_index);

    let mut route = Route::new(id, destination).with_metric(row.Metric);
    if let Some(gateway) = gateway {
        route = route.with_gateway(gateway);
    }
    if let Some(interface_index) = interface_index {
        route = route.with_interface_index(interface_index);
    }
    Ok(Some(route))
}

impl RouteProvider for WindowsBackend {
    type Route = Route;

    fn routes(&self) -> Result<Vec<Self::Route>> {
        self.runtime.block_on(async {
            let mut routes = Vec::new();

            let table_v4 = ip_forward_table(AF_INET).await?;
            unsafe {
                let rows = std::slice::from_raw_parts(
                    (*table_v4).Table.as_ptr(),
                    (*table_v4).NumEntries as usize,
                );
                for row in rows {
                    if let Some(route) = row_to_route(row)? {
                        routes.push(route);
                    }
                }
            }
            free_table(table_v4);

            let table_v6 = ip_forward_table(AF_INET6).await?;
            unsafe {
                let rows = std::slice::from_raw_parts(
                    (*table_v6).Table.as_ptr(),
                    (*table_v6).NumEntries as usize,
                );
                for row in rows {
                    if let Some(route) = row_to_route(row)? {
                        routes.push(route);
                    }
                }
            }
            free_table(table_v6);

            Ok(routes)
        })
    }
}

impl RouteMutator for WindowsBackend {
    type RouteConfig = RouteConfig;

    fn add_route(&self, route: Self::RouteConfig) -> Result<()> {
        validate_route_family(&route)?;
        self.runtime.block_on(async move {
            let row = build_row(route);
            unsafe {
                let status = CreateIpForwardEntry2(&row);
                if status.0 != 0 {
                    return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
                }
            }
            Ok(())
        })
    }

    fn remove_route(&self, route: Self::RouteConfig) -> Result<()> {
        self.runtime.block_on(async move {
            let address_family = match route.destination {
                Network::V4(_) => AF_INET,
                Network::V6(_) => AF_INET6,
            };

            let table = ip_forward_table(address_family).await?;
            unsafe {
                let rows = std::slice::from_raw_parts(
                    (*table).Table.as_ptr(),
                    (*table).NumEntries as usize,
                );
                let mut found = false;
                for row in rows {
                    if row.InterfaceIndex == route.interface_index.unwrap_or(0)
                        && let Ok(Some(existing)) = row_to_route(row)
                        && existing.destination == route.destination
                    {
                        let status = DeleteIpForwardEntry2(row);
                        if status.0 != 0 {
                            free_table(table);
                            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
                        }
                        found = true;
                        break;
                    }
                }
                free_table(table);

                if !found {
                    return Err(Error::NotFound);
                }
            }
            Ok(())
        })
    }
}

async fn ip_forward_table(address_family: ADDRESS_FAMILY) -> Result<*mut MIB_IPFORWARD_TABLE2> {
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let status = GetIpForwardTable2(address_family, &mut table);
        if status.0 != 0 {
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }
        Ok(table)
    }
}

fn free_table(table: *mut MIB_IPFORWARD_TABLE2) {
    if !table.is_null() {
        unsafe {
            FreeMibTable(table.cast());
        }
    }
}

fn build_row(route: RouteConfig) -> MIB_IPFORWARD_ROW2 {
    let (destination, prefix_len) = network_to_std(route.destination);

    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.DestinationPrefix.PrefixLength = prefix_len;
    row.DestinationPrefix.Prefix = ip_to_sockaddr_inet(destination);
    row.NextHop = match route.gateway.map(ip_address_to_std) {
        Some(gateway) => ip_to_sockaddr_inet(gateway),
        None => SOCKADDR_INET {
            si_family: AF_UNSPEC,
        },
    };
    row.InterfaceIndex = route.interface_index.unwrap_or(0);
    row.Metric = route.metric.unwrap_or(0);

    row
}

/// Maps an IANA `ifType` (RFC 2863, `MIB_IF_ROW2::Type`) to the
/// cross-platform [`InterfaceKind`]. Anything not covered falls back to
/// `Other`, carrying the raw type code for diagnostics.
fn if_type_to_kind(if_type: u32) -> InterfaceKind {
    match if_type {
        IF_TYPE_ETHERNET_CSMACD | IF_TYPE_L2_VLAN => InterfaceKind::Ethernet,
        IF_TYPE_SOFTWARE_LOOPBACK => InterfaceKind::Loopback,
        IF_TYPE_PPP => InterfaceKind::PointToPoint,
        IF_TYPE_IEEE80211 => InterfaceKind::Wireless,
        IF_TYPE_BRIDGE => InterfaceKind::Bridge,
        other => InterfaceKind::Other(other),
    }
}

fn row_to_interface(row: &MIB_IF_ROW2) -> Interface {
    let index = row.InterfaceIndex;
    let name = String::from_utf16_lossy(&row.Alias)
        .trim_end_matches('\0')
        .to_string();

    let mac = if row.PhysicalAddressLength == 6 {
        let mut octets = [0u8; 6];
        octets.copy_from_slice(&row.PhysicalAddress[..6]);
        Some(MacAddress::new(octets))
    } else {
        None
    };

    let admin_state = if row.AdminStatus == NET_IF_ADMIN_STATUS_UP {
        AdminState::Up
    } else {
        AdminState::Down
    };

    let operational_state = match row.OperStatus {
        s if s == IfOperStatusUp => OperationalState::Up,
        s if s == IfOperStatusDown => OperationalState::Down,
        s if s == IfOperStatusLowerLayerDown => OperationalState::Down,
        s if s == IfOperStatusDormant => OperationalState::NoCarrier,
        _ => OperationalState::Unknown,
    };

    let kind = if_type_to_kind(row.Type);

    let mut interface = Interface::new(Id::new(index as u64), index, name, kind)
        .with_admin_state(admin_state)
        .with_operational_state(operational_state)
        .with_mtu(row.Mtu);
    if let Some(mac) = mac {
        interface = interface.with_mac(mac);
    }
    interface
}

impl InterfaceProvider for WindowsBackend {
    type Interface = Interface;

    fn interfaces(&self) -> Result<Vec<Self::Interface>> {
        self.runtime.block_on(async {
            let mut interfaces = Vec::new();
            unsafe {
                let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
                let status = GetIfTable2(&mut table);
                if status.0 != 0 {
                    return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
                }
                let rows = std::slice::from_raw_parts(
                    (*table).Table.as_ptr(),
                    (*table).NumEntries as usize,
                );
                for row in rows {
                    interfaces.push(row_to_interface(row));
                }
                FreeMibTable(table.cast());
            }
            Ok(interfaces)
        })
    }
}

/// Reads one interface by its stable Windows interface index.
///
/// `InterfaceId` is derived from this index by [`row_to_interface`], so the
/// backend never accepts a user-supplied adapter name for a native update.
fn get_interface(index: u32) -> Result<Interface> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    let status = unsafe { GetIfEntry2(&mut row) };
    if status.0 != 0 {
        return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
    }
    Ok(row_to_interface(&row))
}

fn desired_admin_status(state: DesiredAdminState) -> Result<u32> {
    match state {
        DesiredAdminState::Up => Ok(MIB_IF_ADMIN_STATUS_UP),
        DesiredAdminState::Down => Ok(MIB_IF_ADMIN_STATUS_DOWN),
        _ => Err(Error::InvalidState),
    }
}

fn set_admin_state(index: u32, state: DesiredAdminState) -> Result<()> {
    // SetIfEntry is the IP Helper API which supports changing the legacy
    // administrative-status field. Read the complete row first so fields not
    // owned by this operation are preserved.
    let mut row = MIB_IFROW {
        dwIndex: index,
        ..Default::default()
    };
    let status = unsafe { GetIfEntry(&mut row) };
    if status != 0 {
        return Err(Error::Platform(PlatformErrorCode::Windows(status)));
    }

    row.dwAdminStatus = desired_admin_status(state)?;
    let status = unsafe { SetIfEntry(&row) };
    if status != 0 {
        return Err(Error::Platform(PlatformErrorCode::Windows(status)));
    }
    Ok(())
}

fn set_family_mtu(index: u32, family: ADDRESS_FAMILY, mtu: u32) -> Result<bool> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceIndex: index,
        ..Default::default()
    };
    let status = unsafe { GetIpInterfaceEntry(&mut row) };
    if status == ERROR_NOT_FOUND {
        // IPv4 or IPv6 can be absent for an adapter. An interface-scoped MTU
        // request updates every family row that actually exists.
        return Ok(false);
    }
    if status.0 != 0 {
        return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
    }

    prepare_ip_interface_row_for_mtu_update(&mut row, mtu);
    let status = unsafe { SetIpInterfaceEntry(&mut row) };
    if status.0 != 0 {
        return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
    }
    Ok(true)
}

/// Prepares one observed IP-interface row for an MTU-only update.
///
/// `GetIpInterfaceEntry` is the required source of all fields that this
/// backend does not own. Windows additionally requires IPv4
/// `SitePrefixLength` to be zero when the row is submitted to
/// `SetIpInterfaceEntry`; preserving the value returned by the getter can
/// otherwise make an otherwise valid MTU update fail with
/// `ERROR_INVALID_PARAMETER`.
fn prepare_ip_interface_row_for_mtu_update(row: &mut MIB_IPINTERFACE_ROW, mtu: u32) {
    row.NlMtu = mtu;
    if row.Family == AF_INET {
        row.SitePrefixLength = 0;
    }
}

const IP_INTERFACE_FAMILIES: [ADDRESS_FAMILY; 2] = [AF_INET, AF_INET6];

/// Submits an interface-scoped MTU request to each address family that the
/// platform reports as applicable.
///
/// Keeping the sequencing separate from the FFI call makes the all-families,
/// no-family, and second-write failure boundaries deterministic to test. A
/// failed second submission deliberately returns immediately: the first
/// family may already have accepted the new MTU.
fn submit_interface_mtu<F>(mut submit: F) -> Result<()>
where
    F: FnMut(ADDRESS_FAMILY) -> Result<bool>,
{
    let mut applied = false;
    for family in IP_INTERFACE_FAMILIES {
        applied |= submit(family)?;
    }
    if applied {
        Ok(())
    } else {
        Err(Error::Platform(PlatformErrorCode::Windows(
            ERROR_NOT_FOUND.0,
        )))
    }
}

fn set_interface_mtu(index: u32, mtu: u32) -> Result<()> {
    submit_interface_mtu(|family| set_family_mtu(index, family, mtu))
}

/// Submits the requested Windows interface fields in their native order.
///
/// Administrative status is submitted before the per-family MTU rows.  The
/// calls cannot form one atomic IP Helper transaction, so an MTU failure can
/// follow a successful administrative-state update.  Keeping this small
/// dispatch boundary independent of FFI makes that contract deterministic to
/// test without mutating a host interface.
fn submit_interface_config<FAdmin, FMtu>(
    config: &InterfaceConfig,
    mut set_admin: FAdmin,
    mut set_mtu: FMtu,
) -> Result<()>
where
    FAdmin: FnMut(DesiredAdminState) -> Result<()>,
    FMtu: FnMut(u32) -> Result<()>,
{
    if let Some(admin_state) = config.admin_state() {
        set_admin(admin_state)?;
    }
    if let Some(mtu) = config.mtu() {
        set_mtu(mtu)?;
    }
    Ok(())
}

#[cfg(test)]
/// Returns whether Windows currently exposes at least one IP-interface row
/// for `index`.
///
/// This is intentionally test-only: production configuration reports native
/// failures through [`set_interface_mtu`] instead of treating an unavailable
/// address family as a generic capability check. The privileged smoke test
/// uses it solely to avoid selecting a non-loopback adapter with no TCP/IP
/// binding, for which re-submitting an MTU is guaranteed to return
/// `ERROR_NOT_FOUND`.
fn has_ip_interface_row(index: u32) -> bool {
    IP_INTERFACE_FAMILIES.into_iter().any(|family| {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: family,
            InterfaceIndex: index,
            ..Default::default()
        };
        unsafe { GetIpInterfaceEntry(&mut row) }.0 == 0
    })
}

impl InterfaceMutator for WindowsBackend {
    type InterfaceConfig = InterfaceConfig;

    /// Applies each requested field through the Windows IP Helper API and
    /// returns a fresh `GetIfEntry2` observation. Administrative state and
    /// MTU use independent native operations; an error after either write can
    /// therefore leave a combined patch partially applied.
    fn set_interface_config(&self, config: Self::InterfaceConfig) -> Result<Self::Interface> {
        let index = u32::try_from(config.interface_id().value()).map_err(|_| Error::NotFound)?;

        // Establish target existence before submitting any write. This keeps
        // the platform error mapping precise and protects the MTU family
        // helpers from operating on an arbitrary stale index.
        get_interface(index)?;

        submit_interface_config(
            &config,
            |admin_state| set_admin_state(index, admin_state),
            |mtu| set_interface_mtu(index, mtu),
        )?;

        // Native acknowledgement is insufficient for the Stage 0.16
        // ReadAfterWrite contract.
        get_interface(index)
    }
}

/// Placeholder identity scheme, same rationale as `synthesize_route_id`: an
/// interface address has no kernel-assigned numeric ID, so this hashes its
/// interface and address together.
///
/// Deliberately hashes only `interface_index` and the address itself, not
/// the full `Network` (which also carries `OnLinkPrefixLength`).
/// `OnLinkPrefixLength` is documented as unreliable on a
/// `MibDeleteInstance` notification row (see
/// `complete_address_notification_row`'s doc comment for the exact
/// Microsoft Learn citation: `Address`/`InterfaceLuid`/`InterfaceIndex` are
/// the only fields Windows guarantees on any notification, not
/// `OnLinkPrefixLength`). Hashing the prefix length would make a delete
/// notification's id disagree with the id computed when the same address
/// was added (or read from a full table dump) whenever the delete row's
/// `OnLinkPrefixLength` differs even slightly from what was observed at add
/// time — there is no documented way to recover the correct value once the
/// entry is gone. Since a given `(interface, address)` pair does not
/// meaningfully have more than one prefix length at once in practice
/// (rebinding goes through remove+re-add, not two simultaneous entries
/// differing only by prefix), excluding it from the identity avoids
/// depending on an explicitly non-guaranteed field rather than trying to
/// work around its unreliability after the fact.
fn synthesize_interface_address_id(interface_index: u32, address: IpAddr) -> InterfaceAddressId {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    interface_index.hash(&mut hasher);
    address.hash(&mut hasher);
    InterfaceAddressId::new(hasher.finish())
}

fn row_to_interface_address(row: &MIB_UNICASTIPADDRESS_ROW) -> Option<InterfaceAddress> {
    let address_addr = unsafe { sockaddr_inet_to_ip(&row.Address) }?;
    let prefix_len = row.OnLinkPrefixLength;

    let network = match address_addr {
        IpAddr::V4(addr) => {
            let prefix = net_lattice_ip::Ipv4PrefixLength::new(prefix_len)?;
            Network::from(net_lattice_ip::Ipv4Network::new(addr.into(), prefix))
        }
        IpAddr::V6(addr) => {
            let prefix = net_lattice_ip::Ipv6PrefixLength::new(prefix_len)?;
            Network::from(net_lattice_ip::Ipv6Network::new(addr.into(), prefix))
        }
    };

    Some(InterfaceAddress::new(
        synthesize_interface_address_id(row.InterfaceIndex, address_addr),
        row.InterfaceIndex,
        network,
    ))
}

/// Builds the row a full `GetUnicastIpAddressTable` read would have produced
/// for the same address, from a possibly-incomplete change-notification row.
///
/// Per Microsoft's documented remarks for `NotifyUnicastIpAddressChange`
/// (`nf-netioapi-notifyunicastipaddresschange`), an application "should
/// allocate a `MIB_UNICASTIPADDRESS_ROW` structure and initialize it with
/// the `Address`, `InterfaceLuid` and `InterfaceIndex` members" from the
/// notification row and pass it to `GetUnicastIpAddressEntry` for complete
/// information — those three fields are documented-reliable on every
/// notification, including `MibDeleteInstance`. `OnLinkPrefixLength` is
/// notably absent from that list, so it is *not* guaranteed reliable on the
/// row itself:
/// - On `MibAddInstance`/`MibParameterNotification` the entry still exists,
///   so re-querying with `GetUnicastIpAddressEntry` (using the reliable
///   `Address`/`InterfaceLuid`/`InterfaceIndex` as the lookup key) recovers
///   the authoritative `OnLinkPrefixLength` — this is exactly the pattern
///   Microsoft's docs describe.
/// - On `MibDeleteInstance` the entry is already gone, so
///   `GetUnicastIpAddressEntry` would fail not-found; there is no
///   documented way to recover the deleted entry's prefix length, so the
///   notification row's own `OnLinkPrefixLength` is used as-is.
fn complete_address_notification_row(
    row: &MIB_UNICASTIPADDRESS_ROW,
    notification: MIB_NOTIFICATION_TYPE,
) -> MIB_UNICASTIPADDRESS_ROW {
    let mut corrected = *row;
    corrected.InterfaceIndex =
        resolve_notification_interface_index(row.InterfaceLuid, row.InterfaceIndex);

    if notification == MibDeleteInstance {
        return corrected;
    }

    let mut queried = MIB_UNICASTIPADDRESS_ROW {
        Address: row.Address,
        InterfaceLuid: row.InterfaceLuid,
        InterfaceIndex: corrected.InterfaceIndex,
        ..Default::default()
    };
    let status = unsafe { GetUnicastIpAddressEntry(&mut queried) };
    if status.0 == 0 {
        corrected = queried;
        corrected.InterfaceIndex =
            resolve_notification_interface_index(corrected.InterfaceLuid, corrected.InterfaceIndex);
    }

    corrected
}

impl AddressProvider for WindowsBackend {
    type InterfaceAddress = InterfaceAddress;

    fn addresses(&self) -> Result<Vec<Self::InterfaceAddress>> {
        self.runtime.block_on(async {
            let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
            let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
            if status.0 != 0 {
                return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
            }

            let addresses: Vec<InterfaceAddress> = unsafe {
                let rows = std::slice::from_raw_parts(
                    (*table).Table.as_ptr(),
                    (*table).NumEntries as usize,
                );
                rows.iter().filter_map(row_to_interface_address).collect()
            };
            unsafe { FreeMibTable(table.cast()) };

            Ok(addresses)
        })
    }
}

fn build_unicast_address_row(address: &NewInterfaceAddress) -> MIB_UNICASTIPADDRESS_ROW {
    let (ip, prefix_len) = network_to_std(address.address);
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = address.interface_id.value() as u32;
    row.Address = ip_to_sockaddr_inet(ip);
    row.OnLinkPrefixLength = prefix_len;
    row
}

impl AddressMutator for WindowsBackend {
    type NewInterfaceAddress = NewInterfaceAddress;
    type InterfaceAddress = InterfaceAddress;

    fn add_address(&self, address: Self::NewInterfaceAddress) -> Result<Self::InterfaceAddress> {
        if matches!(address.address, Network::V6(_)) && address.broadcast.is_some() {
            return Err(Error::InvalidState);
        }
        // IP Helper derives IPv4 broadcast from the prefix and cannot accept
        // an override. Refuse one rather than silently discarding intent.
        if address.broadcast.is_some() {
            return Err(Error::Unsupported);
        }
        let row = build_unicast_address_row(&address);
        let status = unsafe { CreateUnicastIpAddressEntry(&row) };
        if status.0 != 0 {
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }
        self.addresses()?
            .into_iter()
            .find(|observed| {
                observed.interface_index == row.InterfaceIndex
                    && observed.address == address.address
            })
            .ok_or(Error::InvalidState)
    }

    fn remove_address(&self, address: Self::InterfaceAddress) -> Result<()> {
        let request =
            NewInterfaceAddress::new(Id::new(address.interface_index as u64), address.address);
        let row = build_unicast_address_row(&request);
        let status = unsafe { DeleteUnicastIpAddressEntry(&row) };
        if status.0 != 0 {
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }
        Ok(())
    }
}

/// Reads the address out of a raw `SOCKADDR`, dispatching on its
/// `sa_family` — used for `GetAdaptersAddresses`'s DNS server entries,
/// which point at a `sockaddr_in`/`sockaddr_in6`-sized buffer directly
/// rather than embedding a `SOCKADDR_INET` union like the routing APIs do.
///
/// # Safety
/// `ptr`, if non-null, must point at a validly initialized
/// `sockaddr_in`/`sockaddr_in6` for the family it claims (true for anything
/// returned by `GetAdaptersAddresses`).
unsafe fn sockaddr_ptr_to_ip(ptr: *const SOCKADDR) -> Option<IpAddr> {
    if ptr.is_null() {
        return None;
    }
    match unsafe { (*ptr).sa_family } {
        AF_INET => {
            let sin = unsafe { &*ptr.cast::<SOCKADDR_IN>() };
            let b = unsafe { sin.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                b.s_b1, b.s_b2, b.s_b3, b.s_b4,
            )))
        }
        AF_INET6 => {
            let sin6 = unsafe { &*ptr.cast::<SOCKADDR_IN6>() };
            let bytes = unsafe { sin6.sin6_addr.u.Byte };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Calls `GetAdaptersAddresses` with the standard two-call pattern (first
/// to learn the required buffer size, then to fill it) and returns the raw
/// buffer, since `IP_ADAPTER_ADDRESSES_LH` is a variable-length structure
/// chained via `Next` pointers into the buffer itself.
///
/// Skips unicast/anycast/multicast address enumeration via `GAA_FLAG_*`:
/// this backend only reads DNS servers and suffixes, which shrinks the
/// buffer considerably on machines with many addresses per adapter.
fn adapter_addresses() -> Result<Vec<u8>> {
    const FAMILY_UNSPEC: u32 = 0;
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;

    let mut size: u32 = 0;
    unsafe {
        GetAdaptersAddresses(FAMILY_UNSPEC, flags, None, None, &mut size);
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        GetAdaptersAddresses(
            FAMILY_UNSPEC,
            flags,
            None,
            Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
            &mut size,
        )
    };
    if status != 0 {
        return Err(Error::Platform(PlatformErrorCode::Windows(status)));
    }
    Ok(buffer)
}

/// Placeholder identity scheme, same rationale as `synthesize_route_id`: a
/// neighbor entry has no kernel-assigned numeric ID, so this hashes its
/// interface and address together.
fn synthesize_neighbor_id(interface_index: u32, address: &IpAddress) -> NeighborId {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    interface_index.hash(&mut hasher);
    address.hash(&mut hasher);
    NeighborId::new(hasher.finish())
}

/// Maps Windows `NL_NEIGHBOR_STATE` to the cross-platform [`NeighborState`].
fn neighbor_state_to_state(state: NL_NEIGHBOR_STATE) -> NeighborState {
    match state {
        s if s == NlnsIncomplete => NeighborState::Incomplete,
        s if s == NlnsReachable => NeighborState::Reachable,
        s if s == NlnsStale => NeighborState::Stale,
        s if s == NlnsDelay => NeighborState::Delay,
        s if s == NlnsProbe => NeighborState::Probe,
        s if s == NlnsPermanent => NeighborState::Permanent,
        _ => NeighborState::Unknown,
    }
}

fn row_to_neighbor(row: &MIB_IPNET_ROW2) -> Option<NeighborEntry> {
    let address = unsafe { sockaddr_inet_to_ip(&row.Address) }.map(std_ip_to_ip_address)?;

    let mac = if row.PhysicalAddressLength == 6 {
        let mut octets = [0u8; 6];
        octets.copy_from_slice(&row.PhysicalAddress[..6]);
        Some(MacAddress::new(octets))
    } else {
        None
    };

    let mut entry = NeighborEntry::new(
        synthesize_neighbor_id(row.InterfaceIndex, &address),
        row.InterfaceIndex,
        address,
    )
    .with_state(neighbor_state_to_state(row.State));
    if let Some(mac) = mac {
        entry = entry.with_mac(mac);
    }
    Some(entry)
}

/// Reads the current kernel neighbor (ARP/NDP) table via `GetIpNetTable2`.
///
/// A plain synchronous Win32 call with no dependency on `WindowsBackend`'s
/// Tokio runtime, so it can be called both from
/// [`NeighborProvider::neighbors`] (via `self.runtime.block_on`, preserving
/// prior behavior) and directly from the background polling thread backing
/// [`Addition::NEIGHBOR_MONITORING_POLLING`], which has no access to `self`.
fn read_neighbor_table() -> Result<Vec<NeighborEntry>> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) };
    if status.0 != 0 {
        return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
    }

    let neighbors = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        rows.iter().filter_map(row_to_neighbor).collect()
    };
    unsafe { FreeMibTable(table.cast()) };
    Ok(neighbors)
}

impl NeighborProvider for WindowsBackend {
    type NeighborEntry = NeighborEntry;

    fn neighbors(&self) -> Result<Vec<Self::NeighborEntry>> {
        self.runtime.block_on(async { read_neighbor_table() })
    }
}

/// Builds the `MIB_IPNET_ROW2` input required by `CreateIpNetEntry2` for a
/// static ARP/NDP entry, per ADR-0001. `PhysicalAddressLength` is always 6
/// (the only length [`MacAddress`] represents) and `State` is always
/// `NlnsPermanent`, since this stage only creates caller-configured static
/// mappings.
fn static_neighbor_create_row(
    interface_index: u32,
    address: IpAddr,
    mac: [u8; 6],
) -> MIB_IPNET_ROW2 {
    let mut row = MIB_IPNET_ROW2 {
        InterfaceIndex: interface_index,
        Address: ip_to_sockaddr_inet(address),
        PhysicalAddressLength: mac.len() as u32,
        State: NlnsPermanent,
        ..Default::default()
    };
    row.PhysicalAddress[..mac.len()].copy_from_slice(&mac);
    row
}

/// Builds the documented identity-only input for `DeleteIpNetEntry2`. Per
/// Microsoft Learn, delete selects an entry by interface and address only;
/// the physical address and state fields are not part of this request.
fn static_neighbor_delete_row(interface_index: u32, address: IpAddr) -> MIB_IPNET_ROW2 {
    MIB_IPNET_ROW2 {
        InterfaceIndex: interface_index,
        Address: ip_to_sockaddr_inet(address),
        ..Default::default()
    }
}

/// Guards `remove_static_neighbor` against deleting a present but
/// dynamically learned (non-permanent) ARP/NDP cache entry — mirrors
/// Linux's `ensure_removable_static_neighbor_state`. This is the safety
/// property ADR-0001 exists for: `DeleteIpNetEntry2`'s own contract does not
/// distinguish "existing but dynamic" from "existing and static," so only a
/// currently `Permanent` entry may proceed to the native delete call.
fn ensure_removable_static_neighbor_state(state: NeighborState) -> Result<()> {
    if state == NeighborState::Permanent {
        Ok(())
    } else {
        Err(Error::InvalidState)
    }
}

/// Maps a `CreateIpNetEntry2`/`DeleteIpNetEntry2` native status to the
/// shared `Error` model.
///
/// Per Microsoft Learn (accessed 2026-08-02):
/// - `CreateIpNetEntry2`:
///   <https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipnetentry2>
///   documents `ERROR_ACCESS_DENIED` (caller lacks the required privilege),
///   `ERROR_INVALID_PARAMETER`, `ERROR_NOT_FOUND` (the interface was not
///   found), `ERROR_NOT_SUPPORTED` (the address family's stack is not
///   present on the interface), and `ERROR_OBJECT_ALREADY_EXISTS` (a
///   neighbor entry for that address already exists on the interface).
/// - `DeleteIpNetEntry2`:
///   <https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipnetentry2>
///   documents `ERROR_ACCESS_DENIED`, `ERROR_INVALID_PARAMETER`,
///   `ERROR_NOT_FOUND` (the *interface* was not found — confirmed against
///   the live page 2026-08-02: it does not document `ERROR_NOT_FOUND` for a
///   missing neighbor entry, only "The specified interface could not be
///   found"), and `ERROR_NOT_SUPPORTED`. It does not document
///   `ERROR_OBJECT_ALREADY_EXISTS` at all, since that condition cannot arise
///   on delete. `remove_static_neighbor` never reaches this ambiguity in
///   practice: it always performs its own pre-delete existence/state read
///   via [`NeighborProvider::neighbors`] and returns [`Error::NotFound`]
///   from that read before the native call is ever made, so an
///   entry-not-found `DeleteIpNetEntry2` status is not relied upon here —
///   this remains unverified against a live, concurrently-racing kernel
///   because no Windows host was available to run the elevated round trip
///   in this environment.
///
/// Any status not covered by the above falls back to
/// `Error::Platform(PlatformErrorCode::Windows(status.0))`.
fn static_neighbor_mutation_error(status: WIN32_ERROR) -> Error {
    match status {
        ERROR_ACCESS_DENIED => Error::PermissionDenied,
        ERROR_NOT_FOUND => Error::NotFound,
        ERROR_OBJECT_ALREADY_EXISTS => Error::AlreadyExists,
        ERROR_NOT_SUPPORTED => Error::Unsupported,
        other => Error::Platform(PlatformErrorCode::Windows(other.0)),
    }
}

impl NeighborMutator for WindowsBackend {
    type StaticNeighbor = StaticNeighbor;
    type NeighborEntry = NeighborEntry;

    /// Submits a static ARP/NDP entry via `CreateIpNetEntry2` with
    /// `State: NlnsPermanent`, then re-reads that exact row via
    /// `GetIpNetEntry2` so the returned entry reflects what IP Helper
    /// actually holds (`ReadAfterWrite`, per ADR-0001) rather than a
    /// synthesized guess. This deliberately queries the single row instead
    /// of scanning a `GetIpNetTable2` dump: an elevated CI run showed the
    /// full-table snapshot can omit the physical address of a row created
    /// moments earlier, while `GetIpNetEntry2` keyed on the same
    /// interface/address the entry was just created with is authoritative
    /// for that row. `ERROR_ACCESS_DENIED` maps to
    /// [`Error::PermissionDenied`], `ERROR_NOT_FOUND` (missing interface) to
    /// [`Error::NotFound`], `ERROR_OBJECT_ALREADY_EXISTS` to
    /// [`Error::AlreadyExists`], and `ERROR_NOT_SUPPORTED` (address family
    /// stack absent on the interface) to [`Error::Unsupported`]; any other
    /// status surfaces as `Error::Platform` with the raw code.
    fn add_static_neighbor(&self, neighbor: Self::StaticNeighbor) -> Result<Self::NeighborEntry> {
        let interface_index = neighbor.interface_id.value() as u32;
        let address = ip_address_to_std(neighbor.address);
        let row = static_neighbor_create_row(interface_index, address, neighbor.mac.octets());

        let status = unsafe { CreateIpNetEntry2(&row) };
        if status.0 != 0 {
            return Err(static_neighbor_mutation_error(status));
        }

        let mut readback = static_neighbor_delete_row(interface_index, address);
        let status = unsafe { GetIpNetEntry2(&mut readback) };
        if status.0 != 0 {
            return Err(Error::InvalidState);
        }
        row_to_neighbor(&readback).ok_or(Error::InvalidState)
    }

    /// Deletes a static entry through `DeleteIpNetEntry2`, but only after
    /// confirming through [`NeighborProvider::neighbors`] that a matching
    /// `(interface_id, address)` entry currently exists and is
    /// `NeighborState::Permanent`. This is the safety property ADR-0001
    /// exists for: a present but dynamically learned (non-permanent)
    /// ARP/NDP cache entry is never deleted by this call. A missing target
    /// returns [`Error::NotFound`]; a present but non-permanent target
    /// returns [`Error::InvalidState`].
    fn remove_static_neighbor(&self, neighbor: Self::StaticNeighbor) -> Result<()> {
        let interface_index = neighbor.interface_id.value() as u32;

        let observed = self
            .neighbors()?
            .into_iter()
            .find(|entry| {
                entry.interface_index == interface_index && entry.address == neighbor.address
            })
            .ok_or(Error::NotFound)?;

        ensure_removable_static_neighbor_state(observed.state)?;

        let address = ip_address_to_std(neighbor.address);
        let row = static_neighbor_delete_row(interface_index, address);

        let status = unsafe { DeleteIpNetEntry2(&row) };
        if status.0 != 0 {
            return Err(static_neighbor_mutation_error(status));
        }
        Ok(())
    }
}

struct WindowsWatchState {
    sender: EventSender<Event>,
    filter: EventFilter,
}

#[cfg(feature = "async")]
struct WindowsTokioWatchState {
    sender: TokioEventSender<Event>,
    filter: EventFilter,
}

/// Owns all native notification handles and their callback context. IP Helper
/// guarantees `CancelMibChangeNotify2` waits for active callbacks, so freeing
/// `state` after cancellation cannot race a callback dereference.
struct WindowsWatch {
    state: *mut WindowsWatchState,
    route: HANDLE,
    interface: HANDLE,
    address: HANDLE,
}

unsafe impl Send for WindowsWatch {}

impl WindowsWatch {
    unsafe fn cancel(handle: HANDLE) {
        if !handle.is_invalid() {
            let _ = unsafe { CancelMibChangeNotify2(handle) };
        }
    }
}

impl Drop for WindowsWatch {
    fn drop(&mut self) {
        unsafe {
            Self::cancel(self.route);
            Self::cancel(self.interface);
            Self::cancel(self.address);
            drop(Box::from_raw(self.state));
        }
    }
}

/// Async counterpart to [`WindowsWatch`]. It owns the registration handles
/// and callback state for as long as the Tokio receiver remains alive.
#[cfg(feature = "async")]
struct WindowsTokioWatch {
    state: *mut WindowsTokioWatchState,
    route: HANDLE,
    interface: HANDLE,
    address: HANDLE,
}

#[cfg(feature = "async")]
unsafe impl Send for WindowsTokioWatch {}

#[cfg(feature = "async")]
impl Drop for WindowsTokioWatch {
    fn drop(&mut self) {
        unsafe {
            WindowsWatch::cancel(self.route);
            WindowsWatch::cancel(self.interface);
            WindowsWatch::cancel(self.address);
            drop(Box::from_raw(self.state));
        }
    }
}

/// How long `watch_filtered`/`watch_tokio` block waiting for all three
/// `MibInitialNotification` registration confirmations before treating the
/// registration as failed. IP Helper's own documented mechanism (see
/// [`RegistrationReadiness`]) fires this confirmation as soon as a
/// registration is genuinely live, so this is not a tuning knob for native
/// event *delivery* latency (unrelated timing budgets elsewhere in this
/// crate/the facade already cover that) — it only bounds how long the OS
/// may reasonably take to finish wiring up a change-notification
/// registration that has already returned success synchronously. Five
/// seconds is generous headroom over the sub-millisecond confirmation this
/// normally takes, while still failing fast (rather than hanging forever)
/// if IP Helper never delivers the confirmation at all.
const REGISTRATION_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Synthetic Windows-style error code used only when a `watch_filtered`/
/// `watch_tokio` registration never receives all three documented
/// `MibInitialNotification` confirmations within [`REGISTRATION_READY_TIMEOUT`].
/// This does not come from an actual IP Helper API return value — the
/// registration calls themselves already reported success — so it is
/// deliberately `ERROR_TIMEOUT` (`1460` / `0x5B4`), Windows' own generic
/// "this operation did not complete within the time allotted" code, chosen
/// for diagnostic familiarity rather than being returned by any Win32 call
/// in this module.
const ERROR_TIMEOUT: u32 = 1460;

/// Blocks the registering thread until every expected `MibInitialNotification`
/// confirmation has arrived from IP Helper's callback threads.
///
/// Per Microsoft's documented `InitialNotification` parameter (quoted
/// verbatim, `NotifyRouteChange2`/`NotifyUnicastIpAddressChange`, Microsoft
/// Learn, accessed 2026-08-02): "A value that indicates whether the
/// callback should be invoked immediately after registration for change
/// notification completes. This initial notification does not indicate a
/// change occurred to an IP route entry. The purpose of this parameter to
/// provide confirmation that the callback is registered." When set `TRUE`
/// (as every registration call in this module now does), the callback
/// fires once per registration with `NotificationType ==
/// MibInitialNotification` and a `NULL` row as soon as the registration is
/// genuinely, fully live — not merely as soon as the synchronous
/// registration call has returned `NO_ERROR`. `NotifyIpInterfaceChange`
/// shares the same IP Helper notification-registration family and is
/// treated identically here by symmetry.
///
/// This closes a startup race that existed when every registration call
/// passed `InitialNotification = FALSE`: a filtered/selected watcher
/// created shortly before a very fast native mutation could previously miss
/// that mutation's notification if the OS had not yet finished wiring up
/// the registration internally, even though `NotifyRouteChange2` et al. had
/// already returned success. Blocking here, using the documented
/// confirmation mechanism instead of assuming synchronous return implies a
/// live registration, eliminates that race by construction rather than by
/// guessing at row-field reliability (a settled, doc-confirmed non-issue —
/// see `resolve_notification_interface_index`/
/// `complete_address_notification_row`).
///
/// IP Helper invokes every callback (including the `MibInitialNotification`
/// confirmation) on arbitrary OS threads, per its own documentation, so the
/// handoff between the registering thread (which calls [`RegistrationReadiness::wait`])
/// and the callback threads (which call [`RegistrationReadiness::signal`])
/// must be thread-safe; `Mutex`+`Condvar` is the natural fit already used
/// throughout the standard library for exactly this "block until N
/// external signals arrive" pattern.
struct RegistrationReadiness {
    remaining: Mutex<usize>,
    ready: Condvar,
}

impl RegistrationReadiness {
    fn new(expected_confirmations: usize) -> Self {
        Self {
            remaining: Mutex::new(expected_confirmations),
            ready: Condvar::new(),
        }
    }

    /// Called from an IP Helper callback thread when it observes
    /// `NotificationType == MibInitialNotification`.
    fn signal(&self) {
        let mut remaining = self
            .remaining
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *remaining > 0 {
            *remaining -= 1;
        }
        self.ready.notify_all();
    }

    /// Blocks the calling (registering) thread until every expected
    /// confirmation has arrived or `timeout` elapses. Returns `true` once
    /// all confirmations arrived, `false` on timeout.
    fn wait(&self, timeout: Duration) -> bool {
        let remaining = self
            .remaining
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (remaining, wait_result) = self
            .ready
            .wait_timeout_while(remaining, timeout, |remaining| *remaining > 0)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(remaining);
        !wait_result.timed_out()
    }
}

/// Registration-readiness signals keyed by the raw `WindowsWatchState`/
/// `WindowsTokioWatchState` pointer passed to IP Helper as the notification
/// callback context (all three registrations in one `watch_filtered`/
/// `watch_tokio` call share the same context pointer). A module-level map
/// keyed by that pointer's address lets the `route_change_callback`/
/// `interface_change_callback`/`address_change_callback` family (and their
/// Tokio counterparts) signal readiness without adding a field to
/// `WindowsWatchState`/`WindowsTokioWatchState` themselves — those structs
/// are also constructed directly by this module's deterministic fixture
/// tests, which never exercise `MibInitialNotification` and should not need
/// to know about registration bookkeeping that only applies to a real IP
/// Helper registration.
static REGISTRATION_READY: LazyLock<Mutex<HashMap<usize, Arc<RegistrationReadiness>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Registers a new readiness tracker for `expected_confirmations` upcoming
/// `MibInitialNotification` callbacks against `context`, returning the
/// `Arc` the registering thread should call [`RegistrationReadiness::wait`]
/// on.
fn register_readiness(
    context: *const c_void,
    expected_confirmations: usize,
) -> Arc<RegistrationReadiness> {
    let readiness = Arc::new(RegistrationReadiness::new(expected_confirmations));
    REGISTRATION_READY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(context as usize, Arc::clone(&readiness));
    readiness
}

/// Removes `context`'s readiness tracker once registration either succeeds
/// or is abandoned, so the map does not grow unboundedly across repeated
/// `watch_filtered`/`watch_tokio` calls.
fn unregister_readiness(context: *const c_void) {
    REGISTRATION_READY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&(context as usize));
}

/// Called from every callback (sync and Tokio) when
/// `NotificationType == MibInitialNotification`. Looks up `context`'s
/// tracker, if any is currently registered, and signals it. A miss is not
/// an error: it means either registration already finished (the tracker
/// was removed) or, for the deterministic fixture tests in this module that
/// invoke callbacks directly without going through `watch_filtered`/
/// `watch_tokio`, no tracker was ever registered for that context.
fn signal_registration_ready(context: *const c_void) {
    if let Some(readiness) = REGISTRATION_READY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&(context as usize))
    {
        readiness.signal();
    }
}

fn change_kind(notification: MIB_NOTIFICATION_TYPE) -> ChangeKind {
    if notification == MibAddInstance {
        ChangeKind::Added
    } else if notification == MibDeleteInstance {
        ChangeKind::Removed
    } else {
        // MibParameterNotification is the common case. Treat the documented
        // initial notification the same way defensively; registrations below
        // request no initial snapshot.
        ChangeKind::Changed
    }
}

unsafe extern "system" fn route_change_callback(
    context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    notification: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    if notification == MibInitialNotification {
        // Row is documented as NULL for this notification kind; there is
        // nothing to process, only a "registration is now live"
        // confirmation. See `RegistrationReadiness` for the full
        // documented rationale.
        signal_registration_ready(context);
        return;
    }
    if row.is_null() {
        return;
    }
    let state = unsafe { &*(context.cast::<WindowsWatchState>()) };
    let corrected = corrected_route_notification_row(unsafe { &*row });
    if let Ok(Some(route)) = row_to_route(&corrected) {
        let event = Event::Route {
            id: route.id,
            kind: change_kind(notification),
        };
        if state.filter.matches(event) {
            let _ = state.sender.send(event, Event::resync_all());
        }
    }
}

unsafe extern "system" fn interface_change_callback(
    context: *const c_void,
    row: *const windows::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW,
    notification: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    if notification == MibInitialNotification {
        signal_registration_ready(context);
        return;
    }
    if row.is_null() {
        return;
    }
    let state = unsafe { &*(context.cast::<WindowsWatchState>()) };
    let row = unsafe { &*row };
    let event = Event::Interface {
        id: Id::new(row.InterfaceIndex as u64),
        kind: change_kind(notification),
    };
    if state.filter.matches(event) {
        let _ = state.sender.send(event, Event::resync_all());
    }
}

unsafe extern "system" fn address_change_callback(
    context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    notification: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    if notification == MibInitialNotification {
        signal_registration_ready(context);
        return;
    }
    if row.is_null() {
        return;
    }
    let state = unsafe { &*(context.cast::<WindowsWatchState>()) };
    let corrected = complete_address_notification_row(unsafe { &*row }, notification);
    if let Some(address) = row_to_interface_address(&corrected) {
        let event = Event::Address {
            id: address.id,
            kind: change_kind(notification),
        };
        if state.filter.matches(event) {
            let _ = state.sender.send(event, Event::resync_all());
        }
    }
}

#[cfg(feature = "async")]
unsafe extern "system" fn tokio_route_change_callback(
    context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    notification: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    if notification == MibInitialNotification {
        signal_registration_ready(context);
        return;
    }
    if row.is_null() {
        return;
    }
    let state = unsafe { &*(context.cast::<WindowsTokioWatchState>()) };
    let corrected = corrected_route_notification_row(unsafe { &*row });
    if let Ok(Some(route)) = row_to_route(&corrected) {
        let event = Event::Route {
            id: route.id,
            kind: change_kind(notification),
        };
        if state.filter.matches(event) {
            let _ = state.sender.send(event, Event::resync_all);
        }
    }
}

#[cfg(feature = "async")]
unsafe extern "system" fn tokio_interface_change_callback(
    context: *const c_void,
    row: *const windows::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW,
    notification: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    if notification == MibInitialNotification {
        signal_registration_ready(context);
        return;
    }
    if row.is_null() {
        return;
    }
    let state = unsafe { &*(context.cast::<WindowsTokioWatchState>()) };
    let event = Event::Interface {
        id: Id::new(unsafe { (*row).InterfaceIndex } as u64),
        kind: change_kind(notification),
    };
    if state.filter.matches(event) {
        let _ = state.sender.send(event, Event::resync_all);
    }
}

#[cfg(feature = "async")]
unsafe extern "system" fn tokio_address_change_callback(
    context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    notification: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    if notification == MibInitialNotification {
        signal_registration_ready(context);
        return;
    }
    if row.is_null() {
        return;
    }
    let state = unsafe { &*(context.cast::<WindowsTokioWatchState>()) };
    let corrected = complete_address_notification_row(unsafe { &*row }, notification);
    if let Some(address) = row_to_interface_address(&corrected) {
        let event = Event::Address {
            id: address.id,
            kind: change_kind(notification),
        };
        if state.filter.matches(event) {
            let _ = state.sender.send(event, Event::resync_all);
        }
    }
}

impl CapabilityProvider for WindowsBackend {
    /// `IPV6` unconditionally, same rationale as the other backends: every
    /// provider this backend implements already handles both address
    /// families. IP Helper natively delivers route, interface, and unicast
    /// address notifications, but not neighbor-table notifications; therefore
    /// this backend intentionally does not advertise aggregate `MONITORING`.
    /// `VRF`/`NAMESPACES` remain unset because Net Lattice does not implement
    /// either domain yet. `NEIGHBOR_MUTATION` is advertised because
    /// `CreateIpNetEntry2`/`DeleteIpNetEntry2` now back a real
    /// `NeighborMutator` implementation (ADR-0001); this does not imply a
    /// native neighbor-change watcher, which IP Helper still does not
    /// provide. `ROUTE_MUTATION` is advertised because
    /// `CreateIpForwardEntry2`/`DeleteIpForwardEntry2` back a real
    /// `RouteMutator` implementation (ADR-0002).
    fn capabilities(&self) -> Capability {
        Capability::IPV6
            | Capability::ROUTE_MONITORING
            | Capability::INTERFACE_MONITORING
            | Capability::ADDRESS_MONITORING
            | Capability::DNS_MUTATION
            | Capability::INTERFACE_ADMIN_STATE
            | Capability::INTERFACE_MTU
            | Capability::NEIGHBOR_MUTATION
            | Capability::ROUTE_MUTATION
    }
}

impl EventProvider for WindowsBackend {
    type Event = Event;
    type EventFilter = EventFilter;

    fn watch(&self) -> Result<EventReceiver<Self::Event>> {
        self.watch_filtered(EventFilter::ALL)
    }
    fn watch_filtered(&self, filter: Self::EventFilter) -> Result<EventReceiver<Self::Event>> {
        if !supports_event_filter(&filter) {
            return Err(Error::Unsupported);
        }
        let (sender, receiver) = EventReceiver::bounded();
        let state = Box::into_raw(Box::new(WindowsWatchState { sender, filter }));
        // Three registrations below, so three `MibInitialNotification`
        // confirmations are expected before this watcher is considered
        // live. See `RegistrationReadiness` for the full rationale.
        let readiness = register_readiness(state.cast(), 3);
        let mut route = HANDLE::default();
        let mut interface = HANDLE::default();
        let mut address = HANDLE::default();

        let status = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC,
                Some(route_change_callback),
                state.cast(),
                true,
                &mut route,
            )
        };
        if status.0 != 0 {
            unsafe {
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }

        let status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_change_callback),
                Some(state.cast()),
                true,
                &mut interface,
            )
        };
        if status.0 != 0 {
            unsafe {
                WindowsWatch::cancel(route);
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }

        let status = unsafe {
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(address_change_callback),
                Some(state.cast()),
                true,
                &mut address,
            )
        };
        if status.0 != 0 {
            unsafe {
                WindowsWatch::cancel(route);
                WindowsWatch::cancel(interface);
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }

        if !readiness.wait(REGISTRATION_READY_TIMEOUT) {
            unsafe {
                WindowsWatch::cancel(route);
                WindowsWatch::cancel(interface);
                WindowsWatch::cancel(address);
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(ERROR_TIMEOUT)));
        }
        unregister_readiness(state.cast());

        Ok(receiver.with_subscription(WindowsWatch {
            state,
            route,
            interface,
            address,
        }))
    }
}

/// Default poll interval for [`Addition::NEIGHBOR_MONITORING_POLLING`], per
/// ADR-0014 (NL-A-16) Decision 5. A tunable override is left to a future
/// Task if a caller ever needs a different cadence; this Task fixes only the
/// documented default.
const NEIGHBOR_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Diffs two successive neighbor-table snapshots into synthesized
/// [`Event::Neighbor`] change events, per ADR-0014 (NL-A-16) Decision 5.
///
/// `previous` is `None` on the very first poll: the first snapshot is
/// treated as a baseline and produces no events (there is nothing to diff
/// against yet). A [`NeighborId`] present in `current` but not `previous` is
/// [`ChangeKind::Added`]; present in `previous` but not `current` is
/// [`ChangeKind::Removed`]; present in both with a different `mac` or
/// `state` is [`ChangeKind::Changed`] (the conservative fallback — polling
/// cannot distinguish a genuine in-place change from a removal followed by
/// an identical re-addition within the same interval).
fn diff_neighbor_snapshots(
    previous: Option<&HashMap<NeighborId, NeighborEntry>>,
    current: &HashMap<NeighborId, NeighborEntry>,
) -> Vec<Event> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let mut events = Vec::new();
    for (id, entry) in current {
        match previous.get(id) {
            None => events.push(Event::Neighbor {
                id: *id,
                kind: ChangeKind::Added,
            }),
            Some(previous_entry) => {
                if previous_entry.mac != entry.mac || previous_entry.state != entry.state {
                    events.push(Event::Neighbor {
                        id: *id,
                        kind: ChangeKind::Changed,
                    });
                }
            }
        }
    }
    for id in previous.keys() {
        if !current.contains_key(id) {
            events.push(Event::Neighbor {
                id: *id,
                kind: ChangeKind::Removed,
            });
        }
    }
    events
}

/// Owns the background polling thread's stop channel and join handle for
/// [`Addition::NEIGHBOR_MONITORING_POLLING`].
///
/// Dropping this guard drops the stop [`mpsc::Sender`] first, which
/// disconnects the thread's paired `Receiver`: the thread's blocking
/// `recv_timeout` call returns immediately with
/// `RecvTimeoutError::Disconnected` rather than waiting out the remainder of
/// [`NEIGHBOR_POLL_INTERVAL`], so teardown latency on receiver drop is
/// bounded by one poll iteration's own work, not by the poll interval
/// itself. The guard then joins the thread so the polling loop is
/// guaranteed stopped before the guard finishes dropping (mirrors
/// `WindowsWatch::drop`'s synchronous-cancellation contract for native
/// subscriptions above).
struct WindowsAdditionWatch {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for WindowsAdditionWatch {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Windows has no native neighbor-table-change notification mechanism (see
/// `windows_backend_does_not_advertise_neighbor_monitoring` and
/// `CapabilityProvider for WindowsBackend` above), but can synthesize change
/// events by periodically polling [`NeighborProvider::neighbors`] — an
/// already-implemented, unprivileged read. This is the addition-tier
/// implementation for `Addition::NEIGHBOR_MONITORING_POLLING`, per ADR-0014
/// (NL-A-16) Decision 5.
impl AdditionProvider for WindowsBackend {
    fn additions(&self) -> Addition {
        Addition::NEIGHBOR_MONITORING_POLLING
    }

    fn watch_addition(&self, addition: Addition) -> Result<EventReceiver<Self::Event>> {
        if addition != Addition::NEIGHBOR_MONITORING_POLLING {
            return Err(Error::Unsupported);
        }

        let (sender, receiver) = EventReceiver::bounded();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        let handle = thread::spawn(move || {
            let mut previous: Option<HashMap<NeighborId, NeighborEntry>> = None;
            loop {
                match read_neighbor_table() {
                    Ok(snapshot) => {
                        let current: HashMap<NeighborId, NeighborEntry> = snapshot
                            .into_iter()
                            .map(|entry| (entry.id, entry))
                            .collect();
                        for event in diff_neighbor_snapshots(previous.as_ref(), &current) {
                            if !sender.send(event, Event::resync_all()) {
                                return;
                            }
                        }
                        previous = Some(current);
                    }
                    Err(error) => {
                        if !sender.send_error(error) {
                            return;
                        }
                    }
                }

                match stop_rx.recv_timeout(NEIGHBOR_POLL_INTERVAL) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        });

        Ok(receiver.with_subscription(WindowsAdditionWatch {
            stop: Some(stop_tx),
            handle: Some(handle),
        }))
    }
}

/// Native async monitoring: IP Helper invokes the callbacks directly and the
/// callbacks enqueue into a bounded Tokio transport without blocking a system
/// callback thread.
#[cfg(feature = "async")]
impl TokioEventProvider for WindowsBackend {
    type Event = Event;
    type EventFilter = EventFilter;

    fn watch_tokio(&self, filter: Self::EventFilter) -> Result<TokioEventReceiver<Self::Event>> {
        if !supports_event_filter(&filter) {
            return Err(Error::Unsupported);
        }
        let (sender, receiver) = TokioEventReceiver::bounded();
        let state = Box::into_raw(Box::new(WindowsTokioWatchState { sender, filter }));
        // Three registrations below, so three `MibInitialNotification`
        // confirmations are expected before this watcher is considered
        // live. See `RegistrationReadiness` for the full rationale.
        let readiness = register_readiness(state.cast(), 3);
        let mut route = HANDLE::default();
        let mut interface = HANDLE::default();
        let mut address = HANDLE::default();
        let status = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC,
                Some(tokio_route_change_callback),
                state.cast(),
                true,
                &mut route,
            )
        };
        if status.0 != 0 {
            unsafe {
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }
        let status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(tokio_interface_change_callback),
                Some(state.cast()),
                true,
                &mut interface,
            )
        };
        if status.0 != 0 {
            unsafe {
                WindowsWatch::cancel(route);
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }
        let status = unsafe {
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(tokio_address_change_callback),
                Some(state.cast()),
                true,
                &mut address,
            )
        };
        if status.0 != 0 {
            unsafe {
                WindowsWatch::cancel(route);
                WindowsWatch::cancel(interface);
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }

        if !readiness.wait(REGISTRATION_READY_TIMEOUT) {
            unsafe {
                WindowsWatch::cancel(route);
                WindowsWatch::cancel(interface);
                WindowsWatch::cancel(address);
                unregister_readiness(state.cast());
                drop(Box::from_raw(state));
            }
            return Err(Error::Platform(PlatformErrorCode::Windows(ERROR_TIMEOUT)));
        }
        unregister_readiness(state.cast());

        Ok(receiver.with_subscription(WindowsTokioWatch {
            state,
            route,
            interface,
            address,
        }))
    }
}

impl DnsProvider for WindowsBackend {
    type DnsConfig = DnsConfig;

    /// Reads the machine's current DNS configuration via
    /// `GetAdaptersAddresses`.
    ///
    /// On some Windows hosts (observed on Azure-hosted CI runners with
    /// site-local IPv6 nameservers present), the returned `nameservers` can
    /// include RFC 3879-deprecated site-local addresses in the `fec0::/10`
    /// range (e.g. `fec0:0:0:ffff::1`/`::2`/`::3`). These are read back
    /// successfully by this function, but [`DnsMutator::set_dns_config`] has
    /// been observed to reject writing them back verbatim
    /// (`ERROR_INVALID_PARAMETER`/`87` from `SetInterfaceDnsSettings`) even
    /// though this crate's own `NameServer` string formatting is unchanged
    /// from what successfully applies IPv4/global-unicast IPv6 nameservers.
    /// A caller that captures a [`Self::DnsConfig`] containing such an
    /// address for the sole purpose of restoring it later via
    /// `set_dns_config` should not assume the round trip will succeed.
    fn dns_config(&self) -> Result<Self::DnsConfig> {
        let buffer = adapter_addresses()?;
        let mut config = DnsConfig::new();
        if buffer.is_empty() {
            return Ok(config);
        }

        // Every adapter can list the same DNS server / suffix (e.g. a
        // router advertised on both the wired and wireless adapter), so
        // dedupe across the whole machine rather than reporting duplicates.
        let mut seen_nameservers = std::collections::HashSet::new();
        let mut seen_suffixes = std::collections::HashSet::new();

        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            unsafe {
                let mut dns_server = (*adapter).FirstDnsServerAddress;
                while !dns_server.is_null() {
                    let socket_address = (*dns_server).Address;
                    if let Some(ip) = sockaddr_ptr_to_ip(socket_address.lpSockaddr) {
                        let ip_address = std_ip_to_ip_address(ip);
                        if seen_nameservers.insert(ip_address) {
                            config.nameservers.push(ip_address);
                        }
                    }
                    dns_server = (*dns_server).Next;
                }

                if !(*adapter).DnsSuffix.is_null()
                    && let Ok(suffix) = (*adapter).DnsSuffix.to_string()
                    && !suffix.is_empty()
                    && seen_suffixes.insert(suffix.clone())
                {
                    config.search_domains.push(suffix);
                }

                adapter = (*adapter).Next;
            }
        }
        Ok(config)
    }
}

impl DnsMutator for WindowsBackend {
    type NewDnsConfig = NewDnsConfig;

    /// Uses the IP Helper DNS settings API rather than a command-line tool.
    /// Windows stores nameservers per adapter, so the system-wide model is
    /// applied consistently to every adapter returned by
    /// `GetAdaptersAddresses`; the global search list is updated too. Global
    /// and adapter settings are separate native calls, so a later adapter
    /// failure can leave an earlier update applied; callers must re-read
    /// [`DnsProvider::dns_config`] after an error. This operation does not
    /// produce a DNS watcher event.
    fn set_dns_config(&self, config: Self::NewDnsConfig) -> Result<Self::DnsConfig> {
        let nameservers = nul_terminated_wide(&config_list(&config.nameservers));
        let search_domains = nul_terminated_wide(&config.search_domains.join(","));

        let global = DNS_SETTINGS {
            Version: DNS_SETTINGS_VERSION1,
            Flags: DNS_SETTING_SEARCHLIST as u64,
            SearchList: PWSTR(search_domains.as_ptr().cast_mut()),
            ..Default::default()
        };
        let status = unsafe { SetDnsSettings(&global) };
        if status.0 != 0 {
            return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
        }

        let adapters = adapter_addresses()?;
        if adapters.is_empty() {
            return Err(Error::InvalidState);
        }
        let mut adapter = adapters.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            let guid = unsafe { adapter_guid(&*adapter) }?;
            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST) as u64,
                NameServer: PWSTR(nameservers.as_ptr().cast_mut()),
                SearchList: PWSTR(search_domains.as_ptr().cast_mut()),
                ..Default::default()
            };
            let status = unsafe { SetInterfaceDnsSettings(guid, &settings) };
            if status.0 != 0 {
                return Err(Error::Platform(PlatformErrorCode::Windows(status.0)));
            }
            adapter = unsafe { (*adapter).Next };
        }
        self.dns_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};
    use windows::Win32::NetworkManagement::IpHelper::MibParameterNotification;

    /// Serializes ignored native tests in this module. Each one mutates or
    /// observes real Windows IP Helper state (routes, addresses, neighbor
    /// entries, and change-notification subscriptions) on a live interface;
    /// running more than one concurrently in this process would race on
    /// that shared native state and produce inconsistent, order-dependent
    /// failures. Every `#[ignore]`-gated test below takes this guard as its
    /// first statement.
    fn windows_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        GUARD
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn interface_configuration_uses_legacy_admin_status_values() {
        assert_eq!(
            desired_admin_status(DesiredAdminState::Up).expect("up is supported"),
            MIB_IF_ADMIN_STATUS_UP
        );
        assert_eq!(
            desired_admin_status(DesiredAdminState::Down).expect("down is supported"),
            MIB_IF_ADMIN_STATUS_DOWN
        );
    }

    #[test]
    fn static_neighbour_rows_preserve_ipv4_arp_and_ipv6_ndp_create_delete_inputs() {
        let ipv4 = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 17));
        let ipv4_create = static_neighbor_create_row(7, ipv4, [0, 1, 2, 3, 4, 5]);
        assert_eq!(ipv4_create.InterfaceIndex, 7);
        assert_eq!(unsafe { ipv4_create.Address.si_family }, AF_INET);
        assert_eq!(
            unsafe { sockaddr_inet_to_ip(&ipv4_create.Address) },
            Some(ipv4)
        );
        assert_eq!(ipv4_create.PhysicalAddressLength, 6);
        assert_eq!(&ipv4_create.PhysicalAddress[..6], &[0, 1, 2, 3, 4, 5]);
        assert_eq!(ipv4_create.State, NlnsPermanent);

        let ipv4_delete = static_neighbor_delete_row(7, ipv4);
        assert_eq!(ipv4_delete.InterfaceIndex, 7);
        assert_eq!(unsafe { ipv4_delete.Address.si_family }, AF_INET);
        assert_eq!(
            unsafe { sockaddr_inet_to_ip(&ipv4_delete.Address) },
            Some(ipv4)
        );
        assert_eq!(ipv4_delete.PhysicalAddressLength, 0);

        let ipv6 = IpAddr::V6("2001:db8:0:17::1".parse().expect("valid IPv6 NDP address"));
        let ipv6_create = static_neighbor_create_row(9, ipv6, [2, 0, 0, 0, 0, 0x17]);
        assert_eq!(ipv6_create.InterfaceIndex, 9);
        assert_eq!(unsafe { ipv6_create.Address.si_family }, AF_INET6);
        assert_eq!(
            unsafe { sockaddr_inet_to_ip(&ipv6_create.Address) },
            Some(ipv6)
        );
        assert_eq!(ipv6_create.PhysicalAddressLength, 6);
        assert_eq!(&ipv6_create.PhysicalAddress[..6], &[2, 0, 0, 0, 0, 0x17]);
        assert_eq!(ipv6_create.State, NlnsPermanent);

        let ipv6_delete = static_neighbor_delete_row(9, ipv6);
        assert_eq!(ipv6_delete.InterfaceIndex, 9);
        assert_eq!(unsafe { ipv6_delete.Address.si_family }, AF_INET6);
        assert_eq!(
            unsafe { sockaddr_inet_to_ip(&ipv6_delete.Address) },
            Some(ipv6)
        );
        assert_eq!(ipv6_delete.PhysicalAddressLength, 0);
    }

    #[test]
    fn static_neighbor_status_maps_documented_create_delete_errors() {
        assert!(matches!(
            static_neighbor_mutation_error(ERROR_ACCESS_DENIED),
            Error::PermissionDenied
        ));
        assert!(matches!(
            static_neighbor_mutation_error(ERROR_NOT_FOUND),
            Error::NotFound
        ));
        assert!(matches!(
            static_neighbor_mutation_error(ERROR_OBJECT_ALREADY_EXISTS),
            Error::AlreadyExists
        ));
        assert!(matches!(
            static_neighbor_mutation_error(ERROR_NOT_SUPPORTED),
            Error::Unsupported
        ));
    }

    #[test]
    fn static_neighbor_status_falls_back_to_platform_code_for_unmapped_status() {
        let unmapped = WIN32_ERROR(87); // ERROR_INVALID_PARAMETER: not a dedicated Error variant here.
        match static_neighbor_mutation_error(unmapped) {
            Error::Platform(PlatformErrorCode::Windows(code)) => assert_eq!(code, 87),
            other => panic!("expected Error::Platform(Windows(87)), got {other:?}"),
        }
    }

    #[test]
    fn interface_configuration_dispatches_each_requested_shape_in_windows_order() {
        fn calls_for(config: InterfaceConfig) -> Vec<String> {
            let calls = std::cell::RefCell::new(Vec::new());
            submit_interface_config(
                &config,
                |state| {
                    calls.borrow_mut().push(format!("admin:{state:?}"));
                    Ok(())
                },
                |mtu| {
                    calls.borrow_mut().push(format!("mtu:{mtu}"));
                    Ok(())
                },
            )
            .expect("deterministic dispatch fixture succeeds");
            calls.into_inner()
        }

        assert_eq!(
            calls_for(
                InterfaceConfig::new(Id::new(7), Some(DesiredAdminState::Down), None)
                    .expect("valid admin-only patch"),
            ),
            ["admin:Down"]
        );
        assert_eq!(
            calls_for(
                InterfaceConfig::new(Id::new(7), None, Some(1500)).expect("valid MTU-only patch"),
            ),
            ["mtu:1500"]
        );
        assert_eq!(
            calls_for(
                InterfaceConfig::new(Id::new(7), Some(DesiredAdminState::Up), Some(9000))
                    .expect("valid combined patch"),
            ),
            ["admin:Up", "mtu:9000"]
        );
    }

    #[test]
    fn interface_configuration_reports_the_windows_partial_application_boundary() {
        let config = InterfaceConfig::new(Id::new(7), Some(DesiredAdminState::Up), Some(9000))
            .expect("valid combined patch");
        let calls = std::cell::RefCell::new(Vec::new());
        let error = submit_interface_config(
            &config,
            |state| {
                calls.borrow_mut().push(format!("admin:{state:?}"));
                Ok(())
            },
            |mtu| {
                calls.borrow_mut().push(format!("mtu:{mtu}"));
                Err(Error::InvalidState)
            },
        )
        .expect_err("a failure after the administrative write is observable");

        assert!(matches!(error, Error::InvalidState));
        assert_eq!(calls.into_inner(), ["admin:Up", "mtu:9000"]);
    }

    #[test]
    fn interface_mtu_submission_covers_every_applicable_ip_family() {
        let mut families = Vec::new();
        submit_interface_mtu(|family| {
            families.push(family);
            Ok(true)
        })
        .expect("both IP families were submitted");

        assert_eq!(families, vec![AF_INET, AF_INET6]);
    }

    #[test]
    fn interface_mtu_update_resets_only_the_ipv4_site_prefix_length() {
        let mut ipv4 = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            SitePrefixLength: 24,
            ..Default::default()
        };
        prepare_ip_interface_row_for_mtu_update(&mut ipv4, 1500);
        assert_eq!(ipv4.NlMtu, 1500);
        assert_eq!(ipv4.SitePrefixLength, 0);

        let mut ipv6 = MIB_IPINTERFACE_ROW {
            Family: AF_INET6,
            SitePrefixLength: 64,
            ..Default::default()
        };
        prepare_ip_interface_row_for_mtu_update(&mut ipv6, 1500);
        assert_eq!(ipv6.NlMtu, 1500);
        assert_eq!(ipv6.SitePrefixLength, 64);
    }

    #[test]
    fn interface_mtu_submission_reports_when_no_ip_family_exists() {
        let error = submit_interface_mtu(|_| Ok(false)).expect_err("no family was applicable");
        assert!(matches!(
            error,
            Error::Platform(PlatformErrorCode::Windows(code)) if code == ERROR_NOT_FOUND.0
        ));
    }

    #[test]
    fn interface_mtu_submission_stops_after_a_partially_applied_second_family_failure() {
        let mut families = Vec::new();
        let error = submit_interface_mtu(|family| {
            families.push(family);
            if family == AF_INET6 {
                Err(Error::InvalidState)
            } else {
                Ok(true)
            }
        })
        .expect_err("the second native submission failed");

        assert_eq!(families, vec![AF_INET, AF_INET6]);
        assert!(matches!(error, Error::InvalidState));
    }

    #[test]
    fn interface_change_fixture_uses_native_changed_event_and_filter() {
        let (sender, receiver) = EventReceiver::bounded();
        let state = WindowsWatchState {
            sender,
            filter: EventFilter::none().interface(Id::new(7)),
        };
        let row = MIB_IPINTERFACE_ROW {
            InterfaceIndex: 7,
            ..Default::default()
        };

        unsafe {
            interface_change_callback(
                (&raw const state).cast(),
                &raw const row,
                MibParameterNotification,
            );
        }

        assert_eq!(
            receiver.try_recv().expect("fixture callback succeeded"),
            Some(Event::Interface {
                id: Id::new(7),
                kind: ChangeKind::Changed,
            })
        );
    }

    #[cfg(feature = "async")]
    fn tokio_route_event(watcher: &mut TokioEventReceiver<Event>, id: RouteId) -> bool {
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};
        use std::time::Duration;

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        for _ in 0..12 {
            match Pin::new(&mut *watcher).poll_recv(&mut context) {
                Poll::Ready(Some(Ok(Event::Route { id: event_id, .. }))) if event_id == id => {
                    return true;
                }
                Poll::Ready(None) => return false,
                Poll::Ready(Some(_)) | Poll::Pending => {
                    std::thread::sleep(Duration::from_millis(250))
                }
            }
        }
        false
    }

    #[test]
    fn ip_helper_row_fixtures_round_trip_all_read_models() {
        let destination = Network::from(Ipv4Network::new(
            Ipv4Address::new(198, 51, 100, 0),
            Ipv4PrefixLength::new(24).unwrap(),
        ));
        let route = RouteConfig::new(destination)
            .with_gateway(IpAddress::from(Ipv4Address::new(192, 0, 2, 1)))
            .with_interface_index(7)
            .with_metric(42);
        let row = build_row(route);
        let observed = row_to_route(&row).unwrap().expect("valid route row");
        assert_eq!(observed.destination, destination);
        assert_eq!(observed.interface_index, Some(7));
        assert_eq!(observed.metric, Some(42));
        assert_eq!(
            observed.gateway,
            Some(IpAddress::from(Ipv4Address::new(192, 0, 2, 1)))
        );

        let address = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: 7,
            Address: ip_to_sockaddr_inet(IpAddr::V4(Ipv4Address::new(192, 0, 2, 7).into())),
            OnLinkPrefixLength: 24,
            ..Default::default()
        };
        let observed = row_to_interface_address(&address).expect("valid address row");
        assert_eq!(observed.interface_index, 7);
        assert_eq!(
            observed.address,
            Network::from(Ipv4Network::new(
                Ipv4Address::new(192, 0, 2, 7),
                Ipv4PrefixLength::new(24).unwrap(),
            ))
        );

        let mut interface = MIB_IF_ROW2 {
            InterfaceIndex: 7,
            Type: IF_TYPE_ETHERNET_CSMACD,
            AdminStatus: NET_IF_ADMIN_STATUS_UP,
            OperStatus: IfOperStatusUp,
            Mtu: 1500,
            ..Default::default()
        };
        interface.Alias[0] = 'e' as u16;
        interface.Alias[1] = 't' as u16;
        interface.Alias[2] = 'h' as u16;
        interface.PhysicalAddressLength = 6;
        interface.PhysicalAddress[..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        let observed = row_to_interface(&interface);
        assert_eq!(observed.name, "eth");
        assert_eq!(observed.kind, InterfaceKind::Ethernet);
        assert_eq!(observed.operational_state, OperationalState::Up);
        assert_eq!(observed.mac, Some(MacAddress::new([0, 1, 2, 3, 4, 5])));

        let mut neighbor = MIB_IPNET_ROW2 {
            InterfaceIndex: 7,
            Address: ip_to_sockaddr_inet(IpAddr::V4(Ipv4Address::new(192, 0, 2, 1).into())),
            State: NlnsReachable,
            PhysicalAddressLength: 6,
            ..Default::default()
        };
        neighbor.PhysicalAddress[..6].copy_from_slice(&[5, 4, 3, 2, 1, 0]);
        let observed = row_to_neighbor(&neighbor).expect("valid neighbor row");
        assert_eq!(observed.interface_index, 7);
        assert_eq!(observed.state, NeighborState::Reachable);
        assert_eq!(observed.mac, Some(MacAddress::new([5, 4, 3, 2, 1, 0])));

        let mut ipv6_neighbor = MIB_IPNET_ROW2 {
            InterfaceIndex: 7,
            Address: ip_to_sockaddr_inet(IpAddr::V6(
                "2001:db8:0:16::1".parse().expect("valid IPv6 NDP address"),
            )),
            State: NlnsReachable,
            PhysicalAddressLength: 6,
            ..Default::default()
        };
        ipv6_neighbor.PhysicalAddress[..6].copy_from_slice(&[2, 0, 0, 0, 0, 0x16]);
        let observed = row_to_neighbor(&ipv6_neighbor).expect("valid IPv6 neighbor row");
        let expected_address = IpAddress::from(net_lattice_ip::Ipv6Address::new([
            0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1,
        ]));
        assert_eq!(observed.interface_index, 7);
        assert_eq!(observed.address, expected_address);
        assert_eq!(observed.state, NeighborState::Reachable);
        assert_eq!(observed.mac, Some(MacAddress::new([2, 0, 0, 0, 0, 0x16])));
        assert_eq!(observed.id, synthesize_neighbor_id(7, &expected_address));
    }

    #[test]
    fn ip_helper_ipv6_route_row_and_callbacks_preserve_route_identity() {
        let destination = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 0]),
            net_lattice_ip::Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let route = RouteConfig::new(destination)
            .with_gateway(IpAddress::from(net_lattice_ip::Ipv6Address::new([
                0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1,
            ])))
            .with_interface_index(7)
            .with_metric(42);
        let row = build_row(route);
        assert_eq!(unsafe { row.DestinationPrefix.Prefix.si_family }, AF_INET6);
        assert_eq!(unsafe { row.NextHop.si_family }, AF_INET6);

        let observed = row_to_route(&row)
            .expect("IPv6 route row is supported")
            .expect("IPv6 route row has a destination");
        assert_eq!(observed.destination, destination);
        assert_eq!(observed.gateway, route.gateway);
        assert_eq!(observed.interface_index, route.interface_index);
        assert_eq!(observed.metric, route.metric);

        let (sender, receiver) = EventReceiver::bounded();
        let state = WindowsWatchState {
            sender,
            filter: EventFilter::none().route(observed.id),
        };
        unsafe {
            route_change_callback((&raw const state).cast(), &raw const row, MibAddInstance);
            route_change_callback((&raw const state).cast(), &raw const row, MibDeleteInstance);
        }
        assert_eq!(
            receiver.try_recv().expect("add callback succeeded"),
            Some(Event::Route {
                id: observed.id,
                kind: ChangeKind::Added,
            })
        );
        assert_eq!(
            receiver.try_recv().expect("delete callback succeeded"),
            Some(Event::Route {
                id: observed.id,
                kind: ChangeKind::Removed,
            })
        );
    }

    #[test]
    fn ip_helper_ipv6_unicast_row_and_callbacks_preserve_address_identity() {
        let network = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 7]),
            net_lattice_ip::Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let request = NewInterfaceAddress::new(Id::new(7), network);
        let row = build_unicast_address_row(&request);
        assert_eq!(unsafe { row.Address.si_family }, AF_INET6);
        assert_eq!(row.InterfaceIndex, 7);
        assert_eq!(row.OnLinkPrefixLength, 64);

        let observed = row_to_interface_address(&row).expect("valid IPv6 unicast row");
        assert_eq!(observed.interface_index, 7);
        assert_eq!(observed.address, network);
        assert!(observed.broadcast.is_none());

        let (sender, receiver) = EventReceiver::bounded();
        let state = WindowsWatchState {
            sender,
            filter: EventFilter::none().address(observed.id),
        };
        unsafe {
            address_change_callback((&raw const state).cast(), &raw const row, MibAddInstance);
            address_change_callback((&raw const state).cast(), &raw const row, MibDeleteInstance);
        }
        assert_eq!(
            receiver.try_recv().expect("add callback succeeded"),
            Some(Event::Address {
                id: observed.id,
                kind: ChangeKind::Added,
            })
        );
        assert_eq!(
            receiver.try_recv().expect("delete callback succeeded"),
            Some(Event::Address {
                id: observed.id,
                kind: ChangeKind::Removed,
            })
        );
    }

    #[test]
    fn ip_helper_kind_and_state_mappings_cover_supported_values() {
        assert_eq!(
            if_type_to_kind(IF_TYPE_SOFTWARE_LOOPBACK),
            InterfaceKind::Loopback
        );
        assert_eq!(if_type_to_kind(IF_TYPE_PPP), InterfaceKind::PointToPoint);
        assert_eq!(if_type_to_kind(IF_TYPE_IEEE80211), InterfaceKind::Wireless);
        assert_eq!(if_type_to_kind(IF_TYPE_BRIDGE), InterfaceKind::Bridge);
        assert_eq!(if_type_to_kind(IF_TYPE_L2_VLAN), InterfaceKind::Ethernet);
        assert_eq!(if_type_to_kind(999), InterfaceKind::Other(999));
        assert_eq!(
            neighbor_state_to_state(NlnsIncomplete),
            NeighborState::Incomplete
        );
        assert_eq!(neighbor_state_to_state(NlnsStale), NeighborState::Stale);
        assert_eq!(neighbor_state_to_state(NlnsDelay), NeighborState::Delay);
        assert_eq!(neighbor_state_to_state(NlnsProbe), NeighborState::Probe);
        assert_eq!(
            neighbor_state_to_state(NlnsPermanent),
            NeighborState::Permanent
        );
    }

    /// Exercises a real round trip through the IP Helper API, no privilege
    /// required: routing table dumps are readable by any user. This is the
    /// one test in this module that runs by default and actually proves the
    /// backend talks to the kernel, rather than only exercising conversion
    /// logic.
    #[test]
    fn routes_reads_the_real_kernel_routing_table() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let routes = backend
            .routes()
            .expect("GetIpForwardTable dump should not require privilege");
        // Not asserting on contents: the routing table of the machine
        // running this test is arbitrary. Reaching here without an error is
        // the assertion.
        let _ = routes;
    }

    /// Exercises a real round trip through `GetAdaptersAddresses`, no
    /// privilege required: every Windows system has a loopback adapter.
    #[test]
    fn interfaces_includes_the_loopback_interface() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let interfaces = backend
            .interfaces()
            .expect("GetAdaptersAddresses should not require privilege");
        assert!(
            interfaces
                .iter()
                .any(|interface| matches!(interface.kind, InterfaceKind::Loopback)),
            "expected a loopback interface, got: {interfaces:?}"
        );
    }

    /// Keeps the runtime capability advertisement aligned with the provider
    /// implementations exercised by this backend's native tests.
    #[test]
    fn capabilities_match_the_implemented_provider_surface() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let capabilities = backend.capabilities();
        assert!(capabilities.contains(Capability::IPV6));
        assert!(capabilities.contains(Capability::ROUTE_MONITORING));
        assert!(capabilities.contains(Capability::INTERFACE_MONITORING));
        assert!(capabilities.contains(Capability::ADDRESS_MONITORING));
        assert!(!capabilities.contains(Capability::NEIGHBOR_MONITORING));
        assert!(!capabilities.contains(Capability::MONITORING));
        assert!(capabilities.contains(Capability::DNS_MUTATION));
        assert!(capabilities.contains(Capability::INTERFACE_ADMIN_STATE));
        assert!(capabilities.contains(Capability::INTERFACE_MTU));
        assert!(capabilities.contains(Capability::NEIGHBOR_MUTATION));
        assert!(capabilities.contains(Capability::ROUTE_MUTATION));
    }

    #[test]
    fn monitoring_filter_rejects_only_the_unsupported_neighbor_domain() {
        assert!(supports_event_filter(&EventFilter::none()));
        assert!(supports_event_filter(&EventFilter::none().routes()));
        assert!(supports_event_filter(&EventFilter::none().interfaces()));
        assert!(supports_event_filter(&EventFilter::none().addresses()));
        assert!(!supports_event_filter(&EventFilter::none().neighbors()));
        assert!(!supports_event_filter(&EventFilter::ALL));
    }

    /// Re-submits the already-observed administrative state, MTU, and combined
    /// patch for one non-loopback interface with an actual TCP/IP binding.
    /// This exercises each privileged native write/readback shape without
    /// deliberately changing host networking state; the drop guard attempts
    /// full combined restoration even if an assertion panics after submission.
    #[test]
    #[ignore = "requires Administrator; run from elevated cmd/PowerShell: cargo test -p net-lattice-backend-windows interface_configuration_round_trips_observed_values -- --ignored"]
    fn interface_configuration_round_trips_observed_values() {
        let _guard = windows_test_guard();

        struct RestoreInterfaceConfig<'a> {
            backend: &'a WindowsBackend,
            config: InterfaceConfig,
        }

        impl Drop for RestoreInterfaceConfig<'_> {
            fn drop(&mut self) {
                let _ = self.backend.set_interface_config(self.config.clone());
            }
        }

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let interfaces = backend
            .interfaces()
            .expect("failed to list Windows interfaces");
        let original = interfaces
            .iter()
            .find(|interface| {
                !matches!(interface.kind, InterfaceKind::Loopback)
                    && matches!(interface.admin_state, AdminState::Up | AdminState::Down)
                    && interface.mtu.is_some_and(|mtu| mtu != 0)
                    && has_ip_interface_row(interface.index)
            })
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "no non-loopback interface with known admin state, nonzero MTU, and an IP-interface row was available: {interfaces:?}"
                )
            });

        let admin_state = match original.admin_state {
            AdminState::Up => DesiredAdminState::Up,
            AdminState::Down => DesiredAdminState::Down,
            _ => unreachable!("selection requires a known administrative state"),
        };
        let mtu = original.mtu.expect("selection requires a nonzero MTU");
        let combined = InterfaceConfig::new(original.id, Some(admin_state), Some(mtu))
            .expect("observed values form a valid combined configuration patch");
        let admin_only = InterfaceConfig::new(original.id, Some(admin_state), None)
            .expect("observed administrative state forms a valid patch");
        let mtu_only = InterfaceConfig::new(original.id, None, Some(mtu))
            .expect("observed MTU forms a valid patch");
        {
            let _restore = RestoreInterfaceConfig {
                backend: &backend,
                config: combined.clone(),
            };

            for (shape, config) in [
                ("admin-only", admin_only),
                ("MTU-only", mtu_only),
                ("combined", combined),
            ] {
                let observed = backend.set_interface_config(config).unwrap_or_else(|error| {
                    panic!("{shape} observed-value submission failed - are you running as Administrator?: {error:?}")
                });
                assert_eq!(observed.id, original.id, "{shape} readback changed target");
                assert_eq!(
                    observed.admin_state, original.admin_state,
                    "{shape} readback changed administrative state"
                );
                assert_eq!(observed.mtu, original.mtu, "{shape} readback changed MTU");
            }
        }

        let restored = backend
            .interfaces()
            .expect("failed to list Windows interfaces after restoration")
            .into_iter()
            .find(|interface| interface.id == original.id)
            .expect("configured interface disappeared during restoration");
        assert_eq!(restored.admin_state, original.admin_state);
        assert_eq!(restored.mtu, original.mtu);
    }

    /// Exercises a real round trip through `GetUnicastIpAddressTable`, no
    /// privilege required: every Windows system has a loopback address
    /// assigned.
    #[test]
    fn addresses_includes_loopbacks_address() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let addresses = backend
            .addresses()
            .expect("GetUnicastIpAddressTable dump should not require privilege");
        assert!(
            addresses.iter().any(|addr| matches!(
                addr.address,
                Network::V4(net) if net.address() == Ipv4Address::new(127, 0, 0, 1)
            )),
            "expected `127.0.0.1` among the assigned addresses, got: {addresses:?}"
        );
    }

    /// Exercises the complete IP Helper address-mutation path against the
    /// kernel: create a TEST-NET-1 address on the loopback adapter, read its
    /// canonical row, then delete that observed row.
    #[test]
    #[ignore = "requires Administrator; run from elevated cmd/PowerShell: cargo test -p net-lattice-backend-windows add_then_remove_address_round_trips_through_the_kernel -- --ignored"]
    fn add_then_remove_address_round_trips_through_the_kernel() {
        let _guard = windows_test_guard();

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let interface_index = backend
            .interfaces()
            .expect("failed to list Windows interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .expect("Windows loopback interface was not found")
            .index;
        let network = Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, 9),
            Ipv4PrefixLength::new(24).unwrap(),
        ));

        if let Some(existing) = backend
            .addresses()
            .expect("addresses() failed before add_address")
            .into_iter()
            .find(|address| {
                address.interface_index == interface_index && address.address == network
            })
        {
            let _ = backend.remove_address(existing);
        }

        let observed = backend
            .add_address(NewInterfaceAddress::new(
                Id::new(interface_index as u64),
                network,
            ))
            .expect("add_address failed - are you running as Administrator?");
        let present = backend
            .addresses()
            .expect("addresses() failed after add_address")
            .into_iter()
            .any(|address| address.id == observed.id);

        backend
            .remove_address(observed.clone())
            .expect("remove_address failed after successful add_address");
        let absent = !backend
            .addresses()
            .expect("addresses() failed after remove_address")
            .into_iter()
            .any(|address| address.id == observed.id);

        assert!(
            present,
            "added address was not present in addresses() afterward"
        );
        assert!(
            absent,
            "removed address was still present in addresses() afterward"
        );
    }

    /// IPv6 counterpart of `add_then_remove_address_round_trips_through_the_kernel`:
    /// create an RFC 3849 documentation-prefix address on the loopback
    /// adapter, read its canonical row, then delete that observed row.
    #[test]
    #[ignore = "requires Administrator; run from elevated cmd/PowerShell: cargo test -p net-lattice-backend-windows add_then_remove_ipv6_address_round_trips_through_the_kernel -- --ignored"]
    fn add_then_remove_ipv6_address_round_trips_through_the_kernel() {
        let _guard = windows_test_guard();

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let interface_index = backend
            .interfaces()
            .expect("failed to list Windows interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .expect("Windows loopback interface was not found")
            .index;
        let network = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0xd, 0, 0, 0, 0, 9]),
            net_lattice_ip::Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));

        if let Some(existing) = backend
            .addresses()
            .expect("addresses() failed before add_address")
            .into_iter()
            .find(|address| {
                address.interface_index == interface_index && address.address == network
            })
        {
            let _ = backend.remove_address(existing);
        }

        let observed = backend
            .add_address(NewInterfaceAddress::new(
                Id::new(interface_index as u64),
                network,
            ))
            .expect("add_address failed - are you running as Administrator?");
        let present = backend
            .addresses()
            .expect("addresses() failed after add_address")
            .into_iter()
            .any(|address| address.id == observed.id);

        backend
            .remove_address(observed.clone())
            .expect("remove_address failed after successful add_address");
        let absent = !backend
            .addresses()
            .expect("addresses() failed after remove_address")
            .into_iter()
            .any(|address| address.id == observed.id);

        assert!(
            present,
            "added IPv6 address was not present in addresses() afterward"
        );
        assert!(
            absent,
            "removed IPv6 address was still present in addresses() afterward"
        );
    }

    /// Exercises a real round trip through `GetIpNetTable2`, no privilege
    /// required: reading the neighbor cache is readable by any user.
    #[test]
    fn neighbors_reads_the_real_kernel_neighbor_table() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let neighbors = backend
            .neighbors()
            .expect("GetIpNetTable2 dump should not require privilege");
        // Not asserting on contents: the neighbor table of the machine
        // running this test is arbitrary. Reaching here without an error is
        // the assertion.
        let _ = neighbors;
    }

    /// Exercises the complete `NeighborMutator` path against the kernel:
    /// create a static ARP entry on a real (non-loopback) adapter using a
    /// documentation-range (TEST-NET-2, RFC 5737) IPv4 address, confirm it
    /// reads back as `NeighborState::Permanent` with the requested MAC,
    /// remove it, confirm it is gone, and confirm a second removal correctly
    /// reports `Error::NotFound` rather than silently succeeding.
    ///
    /// Does NOT use the loopback adapter. Two elevated CI runs
    /// (2026-08-02) confirmed `CreateIpNetEntry2` on the loopback interface
    /// succeeds and the row reads back with `State: NlnsPermanent`, but its
    /// `PhysicalAddress` never persists (`observed.mac` came back `None`
    /// against a requested MAC both before and after switching the
    /// read-after-write from a `GetIpNetTable2` dump to a targeted
    /// `GetIpNetEntry2` call, ruling out dump staleness as the cause). This
    /// is the same bug class as Linux's `lo`/`IFF_LOOPBACK` restriction (see
    /// `crates/net-lattice-backend-linux/src/lib.rs`'s `DummyLinkFixture`),
    /// though the exact Windows-internal mechanism is not documented on
    /// Microsoft Learn — `CreateIpNetEntry2`'s page only documents
    /// `ERROR_INVALID_PARAMETER` for a *loopback address* in `Address`
    /// (irrelevant here; the address is a normal TEST-NET-2 host, only the
    /// *interface* is loopback), fetched 2026-08-02. Selects a real adapter
    /// the same way `interface_configuration_round_trips_observed_values`
    /// does (non-loopback, known admin state, nonzero MTU, has an IP
    /// interface row) rather than reusing the loopback fixture.
    #[test]
    #[ignore = "requires Administrator; run from elevated cmd/PowerShell: cargo test -p net-lattice-backend-windows add_then_remove_static_neighbor_round_trips_through_the_kernel -- --ignored"]
    fn add_then_remove_static_neighbor_round_trips_through_the_kernel() {
        let _guard = windows_test_guard();

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let interface_index = backend
            .interfaces()
            .expect("failed to list Windows interfaces")
            .into_iter()
            .find(|interface| {
                !matches!(interface.kind, InterfaceKind::Loopback)
                    && matches!(interface.admin_state, AdminState::Up | AdminState::Down)
                    && interface.mtu.is_some_and(|mtu| mtu != 0)
                    && has_ip_interface_row(interface.index)
            })
            .expect("no non-loopback interface with known admin state, nonzero MTU, and an IP-interface row was available")
            .index;
        let address = IpAddress::from(Ipv4Address::new(198, 51, 100, 42));
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x2a]);
        let neighbor = StaticNeighbor::new(Id::new(interface_index as u64), address, mac);

        // Best effort even under `#[ignore]`: if a prior run was
        // interrupted, don't let a stale entry fail this run's add with
        // `AlreadyExists`.
        if let Some(existing) = backend
            .neighbors()
            .expect("neighbors() failed before add_static_neighbor")
            .into_iter()
            .find(|entry| entry.interface_index == interface_index && entry.address == address)
            && existing.state == NeighborState::Permanent
        {
            let _ = backend.remove_static_neighbor(neighbor);
        }

        let observed = backend
            .add_static_neighbor(neighbor)
            .expect("add_static_neighbor failed - are you running as Administrator?");
        assert_eq!(observed.interface_index, interface_index);
        assert_eq!(observed.address, address);
        assert_eq!(
            observed.state,
            NeighborState::Permanent,
            "static entry must read back as Permanent, got {:?}",
            observed.state
        );
        assert_eq!(observed.mac, Some(mac));

        backend
            .remove_static_neighbor(neighbor)
            .expect("remove_static_neighbor failed after successful add_static_neighbor");
        let absent = !backend
            .neighbors()
            .expect("neighbors() failed after remove_static_neighbor")
            .into_iter()
            .any(|entry| entry.interface_index == interface_index && entry.address == address);
        assert!(
            absent,
            "removed static neighbor was still present in neighbors() afterward"
        );

        let second_remove = backend.remove_static_neighbor(neighbor);
        assert!(
            matches!(second_remove, Err(Error::NotFound)),
            "removing an already-absent static neighbor should report NotFound, got {second_remove:?}"
        );
    }

    /// Exercises a real round trip through `GetAdaptersAddresses`, no
    /// privilege required: reading DNS configuration is readable by any
    /// user. Not asserting on contents since the machine running this test
    /// may have any DNS configuration (including none, e.g. a sandboxed CI
    /// runner) — reaching here without an error is the assertion.
    #[test]
    fn dns_config_reads_the_real_adapter_dns_settings() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let config = backend
            .dns_config()
            .expect("GetAdaptersAddresses should not require privilege");
        let _ = config;
    }

    /// Exercises the complete `SetDnsSettings`/`SetInterfaceDnsSettings`
    /// mutation path against the kernel: capture the current adapter DNS
    /// configuration, apply a documentation-only test value, verify it via
    /// a read-after-write, and restore the original configuration on every
    /// exit path (success, assertion failure, or panic) via
    /// `RestoreDnsConfig`'s `Drop` implementation, mirroring
    /// `RestoreInterfaceConfig` above.
    ///
    /// `search_domains` is checked with a "desired entries are present"
    /// containment assertion rather than exact equality: on a domain-joined
    /// host, `GetAdaptersAddresses`'s per-adapter `DnsSuffix` field also
    /// reports the connection's primary/domain DNS suffix, a value managed
    /// separately from the `SearchList` this mutator writes, and observed to
    /// persist in the read-after-write on real Windows CI runners.
    /// `nameservers` has no such ambient source and is still asserted with
    /// exact equality.
    ///
    /// Both the read-after-write and the final restore-verification reads are
    /// wrapped in [`poll_until_dns_config_converges`] rather than a single
    /// immediate `dns_config()` call: `SetDnsSettings`/
    /// `SetInterfaceDnsSettings` are observed on real Windows CI runners to
    /// apply asynchronously relative to the call returning, so a read taken
    /// immediately after either the desired write or the restore write can
    /// still observe the pre-write state. This previously surfaced as a
    /// spurious failure of the final `assert_eq!(restored.nameservers,
    /// before.nameservers)` (the "left" side still showing the test's desired
    /// value, not the real original) even though `RestoreDnsConfig::drop` had
    /// already run and its `set_dns_config` call had not returned an error.
    #[test]
    #[ignore = "requires Administrator; run from elevated cmd/PowerShell: cargo test -p net-lattice-backend-windows dns_configuration_round_trips_through_the_kernel -- --ignored"]
    fn dns_configuration_round_trips_through_the_kernel() {
        let _guard = windows_test_guard();

        /// `fec0::/10` (RFC 3879-deprecated site-local unicast) nameserver
        /// addresses have been observed on real Windows CI runners to be
        /// readable via `GetAdaptersAddresses` but rejected outright
        /// (`ERROR_INVALID_PARAMETER`/`87`) when written back verbatim via
        /// `SetInterfaceDnsSettings` - see the doc comment on
        /// [`DnsProvider::dns_config`]. A privileged round-trip test must be
        /// able to restore the exact state it captured on every exit path
        /// (see `@.claude/rules/ci.md`); if the *ambient* configuration
        /// itself contains an address this backend cannot write back, the
        /// test must not attempt the destructive mutation at all rather than
        /// discover mid-test that restoration is structurally impossible.
        fn contains_unwritable_site_local_nameserver(config: &DnsConfig) -> bool {
            config.nameservers.iter().any(|address| match address {
                IpAddress::V6(address) => {
                    // fec0::/10: top 10 bits are 1111 1110 11, i.e. the
                    // first segment masked with 0xffc0 equals 0xfec0.
                    (address.segments()[0] & 0xffc0) == 0xfec0
                }
                IpAddress::V4(_) => false,
            })
        }

        struct RestoreDnsConfig<'a> {
            backend: &'a WindowsBackend,
            original: NewDnsConfig,
        }

        impl Drop for RestoreDnsConfig<'_> {
            fn drop(&mut self) {
                // `Drop::drop` cannot return a `Result`, and panicking here
                // would abort the process if already unwinding from a test
                // failure, so a failed restore write can't be turned into a
                // clean test failure. Retry a bounded number of times first
                // (a transient failure deserves a second chance even in the
                // cleanup path), then make the final failure loud in CI
                // output instead of silently discarding it (as `let _ = ...`
                // used to), so a broken shared runner's DNS state is at
                // least visible, matching the "loud, not silent" convention
                // this Bug requires for a Drop-based restore guard.
                const RESTORE_ATTEMPTS: u32 = 3;
                let mut last_error = None;
                for attempt in 0..RESTORE_ATTEMPTS {
                    match self.backend.set_dns_config(self.original.clone()) {
                        Ok(_) => return,
                        Err(error) => {
                            last_error = Some(error);
                            if attempt + 1 < RESTORE_ATTEMPTS {
                                std::thread::sleep(Duration::from_millis(200));
                            }
                        }
                    }
                }
                eprintln!(
                    "DNS RESTORE FAILED after {RESTORE_ATTEMPTS} attempt(s), runner network \
                     may be in a bad state: set_dns_config({:?}) returned {last_error:?}",
                    self.original
                );
            }
        }

        /// Polls `dns_config()` up to `attempts` times, sleeping `delay`
        /// between attempts, until `matches` returns `true` for the result or
        /// the attempt budget is exhausted. Returns the last observed
        /// `DnsConfig` either way, so callers get a normal assertion failure
        /// (with the last-seen value in the message) rather than a bespoke
        /// timeout error when convergence never happens.
        ///
        /// `SetDnsSettings`/`SetInterfaceDnsSettings` are Windows APIs known
        /// to apply asynchronously in some configurations; 10 attempts x
        /// 200ms (up to 2s total) mirrors the bounded-retry-with-sleep shape
        /// already used by this file's `tokio_route_event` helper for
        /// similarly eventually-consistent native state.
        fn poll_until_dns_config_converges(
            backend: &WindowsBackend,
            mut matches: impl FnMut(&<WindowsBackend as DnsProvider>::DnsConfig) -> bool,
        ) -> <WindowsBackend as DnsProvider>::DnsConfig {
            let mut last = backend
                .dns_config()
                .expect("GetAdaptersAddresses should not require privilege");
            for attempt in 0..10 {
                if matches(&last) {
                    return last;
                }
                if attempt + 1 < 10 {
                    std::thread::sleep(Duration::from_millis(200));
                    last = backend
                        .dns_config()
                        .expect("GetAdaptersAddresses should not require privilege");
                }
            }
            last
        }

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let before = backend
            .dns_config()
            .expect("GetAdaptersAddresses should not require privilege");

        if contains_unwritable_site_local_nameserver(&before) {
            // This runner's ambient DNS configuration cannot be safely
            // restored via `set_dns_config` (see
            // `contains_unwritable_site_local_nameserver`'s doc comment and
            // `DnsProvider::dns_config`'s doc comment). Attempting the
            // destructive mutation anyway would violate the privileged-test
            // restore-on-every-exit-path requirement, so skip rather than
            // force it. This is a deliberate, logged skip, not a silent
            // pass: it must not be mistaken for a verified round trip.
            eprintln!(
                "SKIPPING dns_configuration_round_trips_through_the_kernel: ambient \
                 nameservers {:?} include a fec0::/10 site-local address this backend's \
                 set_dns_config cannot reliably write back (observed ERROR_INVALID_PARAMETER \
                 on real Windows CI); the round trip cannot be safely restored on this host, \
                 so the destructive mutation was not attempted",
                before.nameservers
            );
            return;
        }

        let original =
            NewDnsConfig::with(before.nameservers.clone(), before.search_domains.clone());
        let desired = NewDnsConfig::with(
            vec![IpAddress::from(Ipv4Address::new(203, 0, 113, 53))],
            vec!["net-lattice-test.invalid".to_string()],
        );

        {
            let _restore = RestoreDnsConfig {
                backend: &backend,
                original: original.clone(),
            };
            let observed = backend
                .set_dns_config(desired.clone())
                .unwrap_or_else(|error| {
                    panic!("set_dns_config failed - are you running as Administrator?: {error:?}")
                });
            assert_eq!(observed.nameservers, desired.nameservers);
            // Not an exact-equality check: on a domain-joined machine,
            // `GetAdaptersAddresses`'s per-adapter `DnsSuffix` field reports
            // the adapter's connection-specific/primary DNS suffix, which is
            // populated by domain membership (DHCP/Group Policy) rather than
            // by `SetDnsSettings`/`SetInterfaceDnsSettings`'s `SearchList`
            // flag. `set_dns_config` writes the search list, but has no way
            // to clear that separately-managed primary suffix, so on a
            // domain-joined host (e.g. some cloud CI runners) it legitimately
            // persists alongside whatever search list this test requests.
            // Assert only that the desired entry is present, not that it is
            // the sole entry.
            for domain in &desired.search_domains {
                assert!(
                    observed.search_domains.contains(domain),
                    "expected search_domains {:?} to contain {domain:?}",
                    observed.search_domains
                );
            }

            // Bounded poll: the write above may not have propagated to a
            // fresh `GetAdaptersAddresses` read yet (see the doc comment on
            // this test).
            let read_after_write = poll_until_dns_config_converges(&backend, |config| {
                config.nameservers == desired.nameservers
                    && desired
                        .search_domains
                        .iter()
                        .all(|domain| config.search_domains.contains(domain))
            });
            assert_eq!(read_after_write.nameservers, desired.nameservers);
            for domain in &desired.search_domains {
                assert!(
                    read_after_write.search_domains.contains(domain),
                    "expected search_domains {:?} to contain {domain:?}",
                    read_after_write.search_domains
                );
            }
        }

        // Bounded poll: `RestoreDnsConfig::drop` has already run by this
        // point (the guard's scope just closed), but its `set_dns_config`
        // write is subject to the same propagation delay as the write above
        // - an immediate read can still observe the just-restored-from
        // (i.e. `desired`) state rather than the real original.
        let restored = poll_until_dns_config_converges(&backend, |config| {
            config.nameservers == before.nameservers
                && config.search_domains == before.search_domains
        });
        assert_eq!(restored.nameservers, before.nameservers);
        assert_eq!(restored.search_domains, before.search_domains);
    }

    #[test]
    fn dns_nameserver_list_preserves_requested_order() {
        let config = NewDnsConfig::with(
            vec![
                IpAddress::from(Ipv4Address::new(1, 1, 1, 1)),
                IpAddress::from(net_lattice_ip::Ipv6Address::from(
                    "2606:4700:4700::1111"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap(),
                )),
                IpAddress::from(Ipv4Address::new(8, 8, 8, 8)),
            ],
            Vec::new(),
        );
        assert_eq!(
            config_list(&config.nameservers),
            "1.1.1.1,2606:4700:4700::1111,8.8.8.8"
        );
    }

    #[test]
    fn dns_ipv6_sockaddr_mapping_preserves_family_and_value() {
        let expected = "2606:4700:4700::1111"
            .parse::<std::net::Ipv6Addr>()
            .unwrap();
        let sockaddr = ip_to_sockaddr_inet(std::net::IpAddr::V6(expected));
        let observed = unsafe {
            sockaddr_ptr_to_ip((&sockaddr.Ipv6 as *const SOCKADDR_IN6).cast::<SOCKADDR>())
        };
        assert_eq!(observed, Some(std::net::IpAddr::V6(expected)));
    }

    /// IP Helper natively delivers route, interface, and unicast address
    /// change notifications, but never neighbor-table notifications (see the
    /// `CapabilityProvider for WindowsBackend` rustdoc above). This asserts
    /// that documented limitation directly against `capabilities()`, so a
    /// future accidental `NEIGHBOR_MONITORING` addition fails immediately
    /// without requiring any native privilege, topology, or connection.
    #[test]
    fn windows_backend_does_not_advertise_neighbor_monitoring() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        assert!(
            !backend
                .capabilities()
                .contains(Capability::NEIGHBOR_MONITORING)
        );
    }

    /// Registers and immediately drops the supported native notification
    /// handles without changing Windows networking state. Neighbor and
    /// all-domain requests are rejected before any callback allocation. The
    /// ignored test below verifies a real route notification end-to-end.
    #[test]
    fn watch_registers_ip_helper_notifications() {
        use std::time::Duration;

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        assert!(!backend.capabilities().contains(Capability::MONITORING));
        assert!(matches!(backend.watch(), Err(Error::Unsupported)));
        assert!(matches!(
            backend.watch_filtered(EventFilter::none().neighbors()),
            Err(Error::Unsupported)
        ));
        drop(
            backend
                .watch_filtered(EventFilter::none().routes())
                .expect("failed to register IP Helper notifications"),
        );
        let filtered = backend
            .watch_filtered(EventFilter::none())
            .expect("failed to register filtered IP Helper notifications");
        assert_eq!(
            filtered.recv_timeout(Duration::from_millis(1)).unwrap(),
            None
        );
    }

    #[cfg(feature = "async")]
    #[test]
    fn watch_tokio_registers_ip_helper_notifications() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        assert!(matches!(
            backend.watch_tokio(EventFilter::ALL),
            Err(Error::Unsupported)
        ));
        assert!(matches!(
            backend.watch_tokio(EventFilter::none().neighbors()),
            Err(Error::Unsupported)
        ));
        let watcher = backend
            .watch_tokio(EventFilter::none().addresses())
            .expect("failed to register IP Helper notifications");
        drop(watcher);
    }

    /// Requires `Administrator` privileges (root, or `sudo -E cargo test -- --ignored`
    /// in this crate). Not run by default because most development and CI
    /// environments — including the one this crate was originally written
    /// in — don't grant it, and this test would otherwise fail with
    /// `PermissionDenied` rather than being skipped.
    ///
    /// Uses a documentation-only prefix (RFC 5737 `203.0.113.0/24`,
    /// TEST-NET-3) on `lo` so it can't collide with or disrupt real
    /// routing, and removes what it added regardless of assertion outcome.
    #[test]
    #[ignore = "requires Administrator; run manually from elevated cmd/PowerShell on Windows"]
    fn add_then_remove_route_round_trips_through_the_kernel() {
        let _guard = windows_test_guard();

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let interface_index = 1u32;

        let destination = Network::from(Ipv4Network::new(
            Ipv4Address::new(203, 0, 113, 0),
            Ipv4PrefixLength::new(24).unwrap(),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface_index);

        let add_result = backend.add_route(route);
        if matches!(
            add_result,
            Err(Error::PermissionDenied) | Err(Error::Platform(_))
        ) {
            // Best effort even under #[ignore]: if it's run without the
            // capability after all, fail loudly rather than silently
            // passing on a no-op.
            add_result.expect("add_route failed - are you running as Administrator?");
        }

        let routes = backend
            .routes()
            .expect("routes() failed after add_route succeeded");
        let found = routes
            .iter()
            .any(|r| r.destination == destination && r.interface_index == Some(interface_index));

        // Clean up before asserting, so a failed assertion doesn't leave
        // the test route behind on the machine that ran this.
        let _ = backend.remove_route(route);

        assert!(found, "added route was not present in routes() afterward");

        let routes_after_removal = backend
            .routes()
            .expect("routes() failed after remove_route");
        assert!(
            !routes_after_removal
                .iter()
                .any(|r| r.destination == destination && r.interface_index == Some(interface_index)),
            "removed route was still present in routes() afterward"
        );
    }

    /// IPv6 counterpart of `add_then_remove_route_round_trips_through_the_kernel`:
    /// uses an RFC 3849 documentation-only prefix (`2001:db8:c::/64`) on `lo`
    /// so it can't collide with or disrupt real routing, and removes what it
    /// added regardless of assertion outcome.
    #[test]
    #[ignore = "requires Administrator; run manually from elevated cmd/PowerShell on Windows"]
    fn add_then_remove_ipv6_route_round_trips_through_the_kernel() {
        let _guard = windows_test_guard();

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let interface_index = 1u32;

        let destination = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0xc, 0, 0, 0, 0, 0]),
            net_lattice_ip::Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface_index);

        let add_result = backend.add_route(route);
        if matches!(
            add_result,
            Err(Error::PermissionDenied) | Err(Error::Platform(_))
        ) {
            // Best effort even under #[ignore]: if it's run without the
            // capability after all, fail loudly rather than silently
            // passing on a no-op.
            add_result.expect("add_route failed - are you running as Administrator?");
        }

        let routes = backend
            .routes()
            .expect("routes() failed after add_route succeeded");
        let found = routes
            .iter()
            .any(|r| r.destination == destination && r.interface_index == Some(interface_index));

        // Clean up before asserting, so a failed assertion doesn't leave
        // the test route behind on the machine that ran this.
        let _ = backend.remove_route(route);

        assert!(
            found,
            "added IPv6 route was not present in routes() afterward"
        );

        let routes_after_removal = backend
            .routes()
            .expect("routes() failed after remove_route");
        assert!(
            !routes_after_removal
                .iter()
                .any(|r| r.destination == destination && r.interface_index == Some(interface_index)),
            "removed IPv6 route was still present in routes() afterward"
        );
    }

    /// End-to-end monitoring verification using a temporary route. This
    /// requires an elevated Windows token because `CreateIpForwardEntry2`
    /// modifies kernel routing state.
    #[test]
    #[ignore = "requires Administrator; run from elevated cmd/PowerShell: cargo test -p net-lattice-backend-windows watch_observes_route_changes -- --ignored"]
    fn watch_observes_route_changes() {
        let _guard = windows_test_guard();

        use std::time::Duration;

        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        assert!(
            backend
                .capabilities()
                .contains(Capability::ROUTE_MONITORING)
        );
        let watcher = backend
            .watch_filtered(EventFilter::none().routes())
            .expect("failed to register IP Helper notifications");
        #[cfg(feature = "async")]
        let mut async_watcher = backend
            .watch_tokio(EventFilter::none().routes())
            .expect("failed to register async IP Helper notifications");
        let interface_index = backend
            .interfaces()
            .expect("failed to list Windows interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .expect("Windows loopback interface was not found")
            .index;
        let destination = Network::from(Ipv4Network::new(
            // TEST-NET-2 is distinct from the route CRUD test's TEST-NET-3
            // prefix because ignored tests run in parallel.
            Ipv4Address::new(198, 51, 100, 0),
            Ipv4PrefixLength::new(24).unwrap(),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface_index);

        backend
            .add_route(route)
            .expect("failed to add monitoring test route");
        // The kernel may canonicalize an on-link next hop differently from
        // the `AF_UNSPEC` value used to create it. Read the canonical row so
        // the asserted ID is exactly the one the notification callback maps.
        let watched_id = backend
            .routes()
            .expect("failed to read routes after adding test route")
            .into_iter()
            .find(|candidate| {
                candidate.destination == destination
                    && candidate.interface_index == Some(interface_index)
            })
            .expect("test route was not present after it was added")
            .id;

        let observed = (0..12).any(|_| {
            matches!(
                watcher.recv_timeout(Duration::from_millis(250)),
                Ok(Some(Event::Route { id, .. })) if id == watched_id
            )
        });
        #[cfg(feature = "async")]
        let async_observed = tokio_route_event(&mut async_watcher, watched_id);
        let selected_watcher = backend
            .watch_filtered(EventFilter::none().route(watched_id))
            .expect("failed to register selected IP Helper route notifications");
        #[cfg(feature = "async")]
        let mut selected_async_watcher = backend
            .watch_tokio(EventFilter::none().route(watched_id))
            .expect("failed to register selected async IP Helper notifications");
        let _ = backend.remove_route(route);
        let selected_observed = (0..12).any(|_| {
            matches!(
                selected_watcher.recv_timeout(Duration::from_millis(250)),
                Ok(Some(Event::Route { id, kind: ChangeKind::Removed })) if id == watched_id
            )
        });
        #[cfg(feature = "async")]
        let selected_async_observed = tokio_route_event(&mut selected_async_watcher, watched_id);
        assert!(observed, "watch() did not report the route mutation");
        assert!(
            selected_observed,
            "object route filter did not report removal"
        );
        #[cfg(feature = "async")]
        assert!(
            async_observed,
            "watch_tokio() did not report the route mutation"
        );
        #[cfg(feature = "async")]
        assert!(
            selected_async_observed,
            "async object route filter did not report removal"
        );
    }

    fn neighbor(id: u64, mac: [u8; 6], state: NeighborState) -> NeighborEntry {
        NeighborEntry::new(
            NeighborId::new(id),
            1,
            IpAddress::from(Ipv4Address::new(10, 0, 0, id as u8)),
        )
        .with_mac(MacAddress::new(mac))
        .with_state(state)
    }

    fn snapshot(entries: Vec<NeighborEntry>) -> HashMap<NeighborId, NeighborEntry> {
        entries.into_iter().map(|entry| (entry.id, entry)).collect()
    }

    /// The very first poll has nothing to diff against: it must establish a
    /// baseline and synthesize no events, per ADR-0014 (NL-A-16) Decision 5.
    #[test]
    fn neighbor_diff_first_poll_produces_no_events() {
        let current = snapshot(vec![neighbor(
            1,
            [0, 1, 2, 3, 4, 5],
            NeighborState::Reachable,
        )]);
        let events = diff_neighbor_snapshots(None, &current);
        assert!(events.is_empty());
    }

    /// A `NeighborId` present only in the newer snapshot synthesizes
    /// `ChangeKind::Added`.
    #[test]
    fn neighbor_diff_reports_added_entries() {
        let previous = snapshot(vec![]);
        let current = snapshot(vec![neighbor(
            1,
            [0, 1, 2, 3, 4, 5],
            NeighborState::Reachable,
        )]);
        let events = diff_neighbor_snapshots(Some(&previous), &current);
        assert_eq!(
            events,
            vec![Event::Neighbor {
                id: NeighborId::new(1),
                kind: ChangeKind::Added,
            }]
        );
    }

    /// A `NeighborId` present only in the older snapshot synthesizes
    /// `ChangeKind::Removed`.
    #[test]
    fn neighbor_diff_reports_removed_entries() {
        let previous = snapshot(vec![neighbor(
            1,
            [0, 1, 2, 3, 4, 5],
            NeighborState::Reachable,
        )]);
        let current = snapshot(vec![]);
        let events = diff_neighbor_snapshots(Some(&previous), &current);
        assert_eq!(
            events,
            vec![Event::Neighbor {
                id: NeighborId::new(1),
                kind: ChangeKind::Removed,
            }]
        );
    }

    /// A `NeighborId` present in both snapshots with a different MAC or
    /// state synthesizes the conservative `ChangeKind::Changed` fallback.
    #[test]
    fn neighbor_diff_reports_changed_mac_and_state() {
        let previous = snapshot(vec![
            neighbor(1, [0, 1, 2, 3, 4, 5], NeighborState::Reachable),
            neighbor(2, [1, 1, 1, 1, 1, 1], NeighborState::Stale),
        ]);
        let current = snapshot(vec![
            neighbor(1, [9, 9, 9, 9, 9, 9], NeighborState::Reachable),
            neighbor(2, [1, 1, 1, 1, 1, 1], NeighborState::Reachable),
        ]);
        let mut events = diff_neighbor_snapshots(Some(&previous), &current);
        // `diff_neighbor_snapshots` iterates a `HashMap`, so the resulting
        // order is not part of its contract (no ordering guarantee across
        // producers, per this session's Event Delivery Guarantees finding);
        // sort by the `Id<T>` inner numeric value (`Id<T>` deliberately does
        // not implement `Ord` itself) purely so this assertion is
        // order-independent and deterministic.
        events.sort_by_key(|event| match event {
            Event::Neighbor { id, .. } => id.value(),
            _ => unreachable!("only Neighbor events are synthesized"),
        });
        assert_eq!(
            events,
            vec![
                Event::Neighbor {
                    id: NeighborId::new(1),
                    kind: ChangeKind::Changed,
                },
                Event::Neighbor {
                    id: NeighborId::new(2),
                    kind: ChangeKind::Changed,
                },
            ]
        );
    }

    /// An identical entry across both snapshots synthesizes no event.
    #[test]
    fn neighbor_diff_reports_nothing_for_an_unchanged_entry() {
        let previous = snapshot(vec![neighbor(
            1,
            [0, 1, 2, 3, 4, 5],
            NeighborState::Reachable,
        )]);
        let current = previous.clone();
        let events = diff_neighbor_snapshots(Some(&previous), &current);
        assert!(events.is_empty());
    }

    /// Mirrors `windows_backend_does_not_advertise_neighbor_monitoring`: the
    /// polling addition is the one thing Windows *does* report, since it
    /// closes exactly the native gap that test asserts.
    #[test]
    fn windows_backend_advertises_neighbor_monitoring_polling_addition() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        assert!(
            backend
                .additions()
                .contains(Addition::NEIGHBOR_MONITORING_POLLING)
        );
    }

    /// Requesting any bit other than `NEIGHBOR_MONITORING_POLLING` is
    /// rejected via `AdditionProvider::watch_addition`'s own default
    /// behavior — this backend overrides the method only for the one bit it
    /// actually supports.
    #[test]
    fn watch_addition_rejects_an_unsupported_bit() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let result = backend.watch_addition(Addition::empty());
        assert!(matches!(result, Err(Error::Unsupported)));
    }

    /// The underlying `neighbors()` read is unprivileged (see
    /// `neighbors_reads_the_real_kernel_neighbor_table` above), so this
    /// exercises the real polling thread end-to-end without requiring
    /// `#[ignore]`: it starts the addition, confirms at least one poll runs
    /// (a resync/error/event delivery would all prove the thread is alive;
    /// absent any real neighbor-table change, an idle host may legitimately
    /// deliver nothing within the timeout), then drops the receiver and
    /// confirms drop does not hang or panic — the polling thread's stop
    /// channel/join teardown is what this asserts, not any particular
    /// synthesized event.
    #[test]
    fn watch_addition_polling_thread_starts_and_tears_down_on_drop() {
        let backend = WindowsBackend::new().expect("failed to create Windows backend");
        let receiver = backend
            .watch_addition(Addition::NEIGHBOR_MONITORING_POLLING)
            .expect("failed to start neighbor-monitoring-via-polling addition");
        // Best-effort: on a quiet host, no neighbor-table change may occur
        // within this timeout, so a `None` result here is not a failure —
        // only that dropping the receiver afterward must not hang or panic.
        let _ = receiver.recv_timeout(Duration::from_millis(50));
        drop(receiver);
    }
}
