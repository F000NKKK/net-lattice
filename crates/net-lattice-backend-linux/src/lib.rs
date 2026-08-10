//! Linux backend for Net Lattice: implements `net-lattice-platform`'s provider
//! traits via Netlink.
//!
//! Only ever compiled for `target_os = "linux"` — its dependencies
//! (`rtnetlink`, Linux-only) are gated the same way in `Cargo.toml`. See
//! ARCHITECTURE.md for how this crate binds `net-lattice-platform`'s generic
//! `RouteProvider::Route` associated type to the concrete
//! `net_lattice_model::route::Route`.

#![cfg(target_os = "linux")]

use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use futures::{StreamExt, TryStreamExt};
use net_lattice_core::{Error, Id, PlatformErrorCode, Result};
use net_lattice_model::dns::{DnsConfig, NewDnsConfig};
use net_lattice_model::event::{ChangeKind, Event, EventFilter};
use net_lattice_model::ifaddr::{InterfaceAddress, InterfaceAddressId, NewInterfaceAddress};
use net_lattice_model::interface::{
    AdminState, DesiredAdminState, Interface, InterfaceConfig, InterfaceKind, OperationalState,
};
use net_lattice_model::mac::MacAddress;
use net_lattice_model::neighbor::{NeighborEntry, NeighborId, NeighborState, StaticNeighbor};
use net_lattice_model::route::{Route, RouteConfig, RouteId};
use net_lattice_model::{IpAddress, Network};
use net_lattice_platform::{
    AddressMutator, AddressProvider, Capability, CapabilityProvider, DnsMutator, DnsProvider,
    EventProvider, EventReceiver, InterfaceMutator, InterfaceProvider, NeighborMutator,
    NeighborProvider, RouteMutator, RouteProvider,
};
#[cfg(feature = "async")]
use net_lattice_platform::{TokioEventProvider, TokioEventReceiver};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkLayerType, LinkMessage, State};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState as RtNeighbourState,
};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::{Handle, MulticastGroup, RouteMessageBuilder};

/// The Linux Netlink-backed implementation of Net Lattice's provider traits.
pub struct LinuxBackend {
    runtime: tokio::runtime::Runtime,
    handle: Handle,
}

struct LinuxWatch {
    connection: tokio::task::JoinHandle<()>,
    events: tokio::task::JoinHandle<()>,
}

impl Drop for LinuxWatch {
    fn drop(&mut self) {
        self.events.abort();
        self.connection.abort();
    }
}

impl LinuxBackend {
    pub fn new() -> Result<Self> {
        let runtime =
            tokio::runtime::Runtime::new().map_err(|err| Error::Platform(io_error_code(&err)))?;
        // `rtnetlink::new_connection` constructs a `tokio::io::unix::AsyncFd`
        // socket synchronously, which requires an active Tokio reactor
        // context at construction time (not just when later polled) -
        // without `_guard`, this panics with "there is no reactor running"
        // the moment `add_route`/`remove_route`/`routes` first drives it.
        let _guard = runtime.enter();
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|err| Error::Platform(io_error_code(&err)))?;
        runtime.spawn(connection);
        Ok(Self { runtime, handle })
    }
}

fn io_error_code(err: &std::io::Error) -> PlatformErrorCode {
    PlatformErrorCode::Linux(err.raw_os_error().unwrap_or(0))
}

fn rtnetlink_error_code(err: &rtnetlink::Error) -> PlatformErrorCode {
    match err {
        rtnetlink::Error::NetlinkError(message) => {
            PlatformErrorCode::Linux(message.code.map(i32::from).unwrap_or(0))
        }
        _ => PlatformErrorCode::Linux(0),
    }
}

/// Maps an `RTM_NEWNEIGH`/`RTM_DELNEIGH` Netlink failure to a semantic
/// [`Error`], per ADR-0001's static-neighbor mutation contract.
///
/// Unlike [`rtnetlink_error_code`] (used by the address/route/interface
/// mutators, which deliberately pass the raw errno through as
/// `Error::Platform` — see
/// `rtnetlink_error_code_passes_through_raw_errno_without_semantic_mapping`),
/// `NeighborMutator` requires a caller-facing distinction between "already
/// exists", "no such destination/interface", and "permission denied" so a
/// plan-level compensator can react to the specific failure ADR-0001 calls
/// out. `EEXIST` (`errno` 17) maps to [`Error::AlreadyExists`]; `ENOENT`
/// (`errno` 2, missing destination) and `ENODEV` (`errno` 19, missing
/// interface) map to [`Error::NotFound`]; `EPERM`/`EACCES` (`errno` 1/13)
/// map to [`Error::PermissionDenied`]. Any other Netlink error, or a
/// non-`NetlinkError` transport failure, falls back to `Error::Platform`
/// with the raw code, matching every other mutator in this backend.
fn neighbor_mutation_error(err: rtnetlink::Error) -> Error {
    match &err {
        rtnetlink::Error::NetlinkError(message) => match message.code.map(i32::from) {
            Some(-17) => Error::AlreadyExists,
            Some(-2) | Some(-19) => Error::NotFound,
            Some(-1) | Some(-13) => Error::PermissionDenied,
            _ => Error::Platform(rtnetlink_error_code(&err)),
        },
        _ => Error::Platform(rtnetlink_error_code(&err)),
    }
}

/// Placeholder identity scheme, same rationale as `synthesize_route_id`: an
/// interface address has no kernel-assigned numeric ID, so this hashes its
/// interface and network together (the pair `RTM_GETADDR` itself keys
/// entries by).
fn synthesize_interface_address_id(interface_index: u32, network: &Network) -> InterfaceAddressId {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    interface_index.hash(&mut hasher);
    network.hash(&mut hasher);
    InterfaceAddressId::new(hasher.finish())
}

fn message_to_interface_address(message: &AddressMessage) -> Option<InterfaceAddress> {
    let interface_index = message.header.index;
    let prefix_len = message.header.prefix_len;

    let mut address_addr = None;
    let mut broadcast = None;
    for attribute in &message.attributes {
        match attribute {
            // `IFA_LOCAL`, when present, is the actual assigned address —
            // `IFA_ADDRESS` alone (no `IFA_LOCAL`) names the *peer* address
            // on a point-to-point link, so prefer `Local` and only fall
            // back to `Address` when there is no separate local entry.
            AddressAttribute::Local(addr) => address_addr = Some(*addr),
            AddressAttribute::Address(addr) if address_addr.is_none() => {
                address_addr = Some(*addr);
            }
            AddressAttribute::Broadcast(addr) => {
                broadcast = Some(std_ip_to_ip_address(IpAddr::V4(*addr)));
            }
            _ => {}
        }
    }

    let network = match address_addr? {
        IpAddr::V4(addr) => {
            let prefix = net_lattice_ip::Ipv4PrefixLength::new(prefix_len)?;
            Network::from(net_lattice_ip::Ipv4Network::new(addr.into(), prefix))
        }
        IpAddr::V6(addr) => {
            let prefix = net_lattice_ip::Ipv6PrefixLength::new(prefix_len)?;
            Network::from(net_lattice_ip::Ipv6Network::new(addr.into(), prefix))
        }
    };

    let mut entry = InterfaceAddress::new(
        synthesize_interface_address_id(interface_index, &network),
        interface_index,
        network,
    );
    if let Some(broadcast) = broadcast {
        entry = entry.with_broadcast(broadcast);
    }
    Some(entry)
}

impl AddressProvider for LinuxBackend {
    type InterfaceAddress = InterfaceAddress;

    fn addresses(&self) -> Result<Vec<Self::InterfaceAddress>> {
        self.runtime.block_on(async {
            let mut messages = self.handle.address().get().execute();
            let mut addresses = Vec::new();
            while let Some(message) = messages
                .try_next()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))?
            {
                addresses.extend(message_to_interface_address(&message));
            }
            Ok(addresses)
        })
    }
}

impl AddressMutator for LinuxBackend {
    type NewInterfaceAddress = NewInterfaceAddress;
    type InterfaceAddress = InterfaceAddress;

    fn add_address(&self, address: Self::NewInterfaceAddress) -> Result<Self::InterfaceAddress> {
        if matches!(address.address, Network::V6(_)) && address.broadcast.is_some() {
            return Err(Error::InvalidState);
        }
        let interface_index = address.interface_id.value() as u32;
        let (ip, prefix_len) = network_to_std(address.address);
        self.runtime.block_on(async {
            let mut request = self.handle.address().add(interface_index, ip, prefix_len);
            if let Some(broadcast) = address.broadcast {
                request
                    .message_mut()
                    .attributes
                    .push(AddressAttribute::Broadcast(broadcast.into()));
            }
            request
                .execute()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))
        })?;

        self.addresses()?
            .into_iter()
            .find(|observed| {
                observed.interface_index == interface_index && observed.address == address.address
            })
            .ok_or(Error::InvalidState)
    }

    fn remove_address(&self, address: Self::InterfaceAddress) -> Result<()> {
        self.runtime.block_on(async {
            let mut messages = self.handle.address().get().execute();
            while let Some(message) = messages
                .try_next()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))?
            {
                if message_to_interface_address(&message)
                    .is_some_and(|observed| observed.id == address.id)
                {
                    return self
                        .handle
                        .address()
                        .del(message)
                        .execute()
                        .await
                        .map_err(|err| Error::Platform(rtnetlink_error_code(&err)));
                }
            }
            Err(Error::NotFound)
        })
    }
}

/// Placeholder identity scheme: a route has no kernel-assigned numeric ID,
/// so this hashes its defining fields. See ARCHITECTURE.md's open Object
/// Identity question — this is not a long-term answer, only enough to give
/// `Stage 0.1` a `RouteId` to work with.
///
/// Hashes destination, gateway, and outgoing interface together so that
/// two routes to the same destination that differ only in gateway or
/// interface (a common case with multiple default routes, or ECMP-like
/// setups) don't collide on the same `RouteId`.
fn synthesize_route_id(message: &RouteMessage) -> RouteId {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    message.header.destination_prefix_length.hash(&mut hasher);
    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Destination(addr) => {
                route_address_to_ip(addr).hash(&mut hasher);
            }
            RouteAttribute::Gateway(addr) => {
                route_address_to_ip(addr).hash(&mut hasher);
            }
            RouteAttribute::Oif(index) => {
                index.hash(&mut hasher);
            }
            _ => {}
        }
    }
    RouteId::new(hasher.finish())
}

fn route_address_to_ip(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(addr) => Some(IpAddr::V4(*addr)),
        RouteAddress::Inet6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

fn std_ip_to_ip_address(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(addr) => IpAddress::from(net_lattice_ip::Ipv4Address::from(addr)),
        IpAddr::V6(addr) => IpAddress::from(net_lattice_ip::Ipv6Address::from(addr)),
    }
}

fn message_to_route(message: &RouteMessage) -> Option<Route> {
    let mut destination_addr = None;
    let mut gateway = None;
    let mut metric = None;
    let mut interface_index = None;

    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Destination(addr) => {
                destination_addr = route_address_to_ip(addr);
            }
            RouteAttribute::Gateway(addr) => {
                gateway = route_address_to_ip(addr).map(std_ip_to_ip_address);
            }
            RouteAttribute::Priority(priority) => {
                metric = Some(*priority);
            }
            RouteAttribute::Oif(index) => {
                interface_index = Some(*index);
            }
            _ => {}
        }
    }

    let destination_addr = destination_addr?;
    let prefix_len = message.header.destination_prefix_length;
    let destination = match destination_addr {
        IpAddr::V4(addr) => {
            let prefix = net_lattice_ip::Ipv4PrefixLength::new(prefix_len)?;
            Network::from(net_lattice_ip::Ipv4Network::new(addr.into(), prefix))
        }
        IpAddr::V6(addr) => {
            let prefix = net_lattice_ip::Ipv6PrefixLength::new(prefix_len)?;
            Network::from(net_lattice_ip::Ipv6Network::new(addr.into(), prefix))
        }
    };

    let mut route = Route::new(synthesize_route_id(message), destination);
    if let Some(gateway) = gateway {
        route = route.with_gateway(gateway);
    }
    if let Some(metric) = metric {
        route = route.with_metric(metric);
    }
    if let Some(interface_index) = interface_index {
        route = route.with_interface_index(interface_index);
    }
    Some(route)
}

fn ip_address_to_std(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::V4(addr) => IpAddr::V4(addr.into()),
        IpAddress::V6(addr) => IpAddr::V6(addr.into()),
    }
}

fn network_to_std(network: Network) -> (IpAddr, u8) {
    match network {
        Network::V4(net) => (IpAddr::V4(net.address().into()), net.prefix().value()),
        Network::V6(net) => (IpAddr::V6(net.address().into()), net.prefix().value()),
    }
}

impl RouteProvider for LinuxBackend {
    type Route = Route;

    fn routes(&self) -> Result<Vec<Self::Route>> {
        self.runtime.block_on(async {
            let route_handle = self.handle.route();

            let mut v4 = route_handle
                .get(RouteMessageBuilder::<std::net::Ipv4Addr>::new().build())
                .execute();

            let mut routes = Vec::new();
            while let Some(message) = v4
                .try_next()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))?
            {
                routes.extend(message_to_route(&message));
            }

            let mut v6 = route_handle
                .get(RouteMessageBuilder::<std::net::Ipv6Addr>::new().build())
                .execute();
            while let Some(message) = v6
                .try_next()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))?
            {
                routes.extend(message_to_route(&message));
            }
            Ok(routes)
        })
    }
}

impl RouteMutator for LinuxBackend {
    type RouteConfig = RouteConfig;

    fn add_route(&self, route: Self::RouteConfig) -> Result<()> {
        self.runtime.block_on(async {
            let message = route_request_message(&route, true);

            self.handle
                .route()
                .add(message)
                .execute()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))
        })
    }

    fn remove_route(&self, route: Self::RouteConfig) -> Result<()> {
        self.runtime.block_on(async {
            let message = route_request_message(&route, false);

            self.handle
                .route()
                .del(message)
                .execute()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))
        })
    }
}

/// Builds the shared native route request used for add and delete operations.
///
/// A delete request deliberately omits the optional gateway and metric, while
/// the destination family and output interface are retained for both request
/// kinds.
fn route_request_message(route: &RouteConfig, include_gateway_and_metric: bool) -> RouteMessage {
    let (destination, prefix_len) = network_to_std(route.destination);
    match destination {
        IpAddr::V4(addr) => {
            let mut builder = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                .destination_prefix(addr, prefix_len);
            if include_gateway_and_metric {
                if let Some(IpAddr::V4(gateway)) = route.gateway.map(ip_address_to_std) {
                    builder = builder.gateway(gateway);
                }
                if let Some(metric) = route.metric {
                    builder = builder.priority(metric);
                }
            }
            if let Some(interface_index) = route.interface_index {
                builder = builder.output_interface(interface_index);
            }
            builder.build()
        }
        IpAddr::V6(addr) => {
            let mut builder = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                .destination_prefix(addr, prefix_len);
            if include_gateway_and_metric {
                if let Some(IpAddr::V6(gateway)) = route.gateway.map(ip_address_to_std) {
                    builder = builder.gateway(gateway);
                }
                if let Some(metric) = route.metric {
                    builder = builder.priority(metric);
                }
            }
            if let Some(interface_index) = route.interface_index {
                builder = builder.output_interface(interface_index);
            }
            builder.build()
        }
    }
}

/// Maps Linux `ARPHRD_*` link-layer types (`LinkLayerType`) to the
/// cross-platform [`InterfaceKind`]. Anything not covered falls back to
/// `Other`, carrying the raw type code for diagnostics.
fn link_layer_type_to_kind(link_layer_type: LinkLayerType) -> InterfaceKind {
    match link_layer_type {
        LinkLayerType::Ether => InterfaceKind::Ethernet,
        LinkLayerType::Loopback => InterfaceKind::Loopback,
        LinkLayerType::Ppp => InterfaceKind::PointToPoint,
        LinkLayerType::Ieee80211
        | LinkLayerType::Ieee80211Prism
        | LinkLayerType::Ieee80211Radiotap => InterfaceKind::Wireless,
        other => InterfaceKind::Other(u16::from(other) as u32),
    }
}

fn message_to_interface(message: &LinkMessage) -> Interface {
    let index = message.header.index;
    let mut name = String::new();
    let mut mac = None;
    let mut mtu = None;
    let mut operational_state = OperationalState::Unknown;

    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => name = value.clone(),
            LinkAttribute::Address(bytes) if bytes.len() == 6 => {
                let mut octets = [0u8; 6];
                octets.copy_from_slice(bytes);
                mac = Some(MacAddress::new(octets));
            }
            LinkAttribute::Mtu(value) => mtu = Some(*value),
            LinkAttribute::OperState(state) => {
                operational_state = match state {
                    State::Up => OperationalState::Up,
                    State::Down | State::LowerLayerDown | State::NotPresent => {
                        OperationalState::Down
                    }
                    State::Dormant => OperationalState::NoCarrier,
                    _ => OperationalState::Unknown,
                };
            }
            _ => {}
        }
    }

    let admin_state = if message
        .header
        .flags
        .contains(rtnetlink::packet_route::link::LinkFlags::Up)
    {
        AdminState::Up
    } else {
        AdminState::Down
    };

    let kind = link_layer_type_to_kind(message.header.link_layer_type);

    let mut interface = Interface::new(Id::new(index as u64), index, name, kind)
        .with_admin_state(admin_state)
        .with_operational_state(operational_state);
    if let Some(mac) = mac {
        interface = interface.with_mac(mac);
    }
    if let Some(mtu) = mtu {
        interface = interface.with_mtu(mtu);
    }
    interface
}

impl InterfaceProvider for LinuxBackend {
    type Interface = Interface;

    fn interfaces(&self) -> Result<Vec<Self::Interface>> {
        self.runtime.block_on(async {
            let mut links = self.handle.link().get().execute();
            let mut interfaces = Vec::new();
            while let Some(message) = links
                .try_next()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))?
            {
                interfaces.push(message_to_interface(&message));
            }
            Ok(interfaces)
        })
    }
}

/// Builds the minimal `RTM_NEWLINK` request used to modify an existing link.
///
/// Linux uses `ifi_change` to select which `IFF_*` bits the request may
/// alter. Only `IFF_UP` is included, so a request to change administrative
/// state cannot accidentally overwrite flags the caller did not request.
fn interface_config_to_link_change(config: &InterfaceConfig) -> Result<LinkMessage> {
    let index = u32::try_from(config.interface_id().value()).map_err(|_| Error::NotFound)?;
    let mut message = LinkMessage::default();
    message.header.index = index;

    if let Some(admin_state) = config.admin_state() {
        message.header.change_mask = LinkFlags::Up;
        message.header.flags = match admin_state {
            DesiredAdminState::Up => LinkFlags::Up,
            DesiredAdminState::Down => LinkFlags::empty(),
            // `DesiredAdminState` is non-exhaustive. A newer model intent
            // must not turn a backend request into a process panic before
            // this backend has learned its native representation.
            _ => return Err(Error::Unsupported),
        };
    }

    if let Some(mtu) = config.mtu() {
        message.attributes.push(LinkAttribute::Mtu(mtu));
    }

    Ok(message)
}

impl InterfaceMutator for LinuxBackend {
    type InterfaceConfig = InterfaceConfig;

    /// Applies an MTU and/or administrative-state patch through
    /// `RTM_NEWLINK`, then re-reads the link before reporting success.
    ///
    /// Linux may apply one requested field before rejecting another, notably
    /// when a combined MTU/admin-state request is constrained by device
    /// policy. Callers using a transaction must therefore rely on the
    /// mutation's partial-application semantics and opt into explicit
    /// compensation when restoration is required.
    fn set_interface_config(&self, config: Self::InterfaceConfig) -> Result<Self::Interface> {
        let index = u32::try_from(config.interface_id().value()).map_err(|_| Error::NotFound)?;
        let message = interface_config_to_link_change(&config)?;

        self.runtime.block_on(async {
            self.handle
                .link()
                .change(message)
                .execute()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))
        })?;

        self.runtime.block_on(async {
            let mut links = self.handle.link().get().match_index(index).execute();
            links
                .try_next()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))?
                .map(|message| message_to_interface(&message))
                .ok_or(Error::NotFound)
        })
    }
}

/// Placeholder identity scheme, same rationale as `synthesize_route_id`: a
/// neighbor entry has no kernel-assigned numeric ID, so this hashes its
/// interface and address together (the pair the kernel itself keys entries
/// by, via `RTM_GETNEIGH`).
fn synthesize_neighbor_id(interface_index: u32, address: &IpAddress) -> NeighborId {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    interface_index.hash(&mut hasher);
    address.hash(&mut hasher);
    NeighborId::new(hasher.finish())
}

/// Maps Linux `NUD_*` neighbor states (`NeighbourState`) to the
/// cross-platform [`NeighborState`].
fn neighbour_state_to_state(state: RtNeighbourState) -> NeighborState {
    match state {
        RtNeighbourState::Incomplete => NeighborState::Incomplete,
        RtNeighbourState::Reachable => NeighborState::Reachable,
        RtNeighbourState::Stale => NeighborState::Stale,
        RtNeighbourState::Delay => NeighborState::Delay,
        RtNeighbourState::Probe => NeighborState::Probe,
        RtNeighbourState::Failed => NeighborState::Failed,
        RtNeighbourState::Permanent => NeighborState::Permanent,
        _ => NeighborState::Unknown,
    }
}

fn message_to_neighbor(message: &NeighbourMessage) -> Option<NeighborEntry> {
    let interface_index = message.header.ifindex;
    let mut address = None;
    let mut mac = None;

    for attribute in &message.attributes {
        match attribute {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) => {
                address = Some(std_ip_to_ip_address(IpAddr::V4(*addr)));
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) => {
                address = Some(std_ip_to_ip_address(IpAddr::V6(*addr)));
            }
            NeighbourAttribute::LinkLayerAddress(bytes) if bytes.len() == 6 => {
                let mut octets = [0u8; 6];
                octets.copy_from_slice(bytes);
                mac = Some(MacAddress::new(octets));
            }
            _ => {}
        }
    }

    let address = address?;
    let mut entry = NeighborEntry::new(
        synthesize_neighbor_id(interface_index, &address),
        interface_index,
        address,
    )
    .with_state(neighbour_state_to_state(message.header.state));
    if let Some(mac) = mac {
        entry = entry.with_mac(mac);
    }
    Some(entry)
}

impl NeighborProvider for LinuxBackend {
    type NeighborEntry = NeighborEntry;

    fn neighbors(&self) -> Result<Vec<Self::NeighborEntry>> {
        self.runtime.block_on(async {
            let mut messages = self.handle.neighbours().get().execute();
            let mut neighbors = Vec::new();
            while let Some(message) = messages
                .try_next()
                .await
                .map_err(|err| Error::Platform(rtnetlink_error_code(&err)))?
            {
                neighbors.extend(message_to_neighbor(&message));
            }
            Ok(neighbors)
        })
    }
}

/// Builds the `ndmsg` payload used to select an existing entry for
/// `RTM_DELNEIGH`. Per `rtnetlink(7)`, `RTM_DELNEIGH` selects by
/// family/ifindex/`NDA_DST` and does not require `NDA_LLADDR`, so this
/// deliberately omits the link-layer address attribute that
/// `NeighbourHandle::add` sets.
/// Guards `remove_static_neighbor` against deleting a present but
/// dynamically learned (non-permanent) ARP/NDP cache entry: this is the
/// safety property ADR-0001 exists for. Only a currently `Permanent` entry
/// may proceed to `RTM_DELNEIGH`.
fn ensure_removable_static_neighbor_state(state: NeighborState) -> Result<()> {
    if state == NeighborState::Permanent {
        Ok(())
    } else {
        Err(Error::InvalidState)
    }
}

fn static_neighbor_del_message(interface_index: u32, destination: IpAddr) -> NeighbourMessage {
    let mut message = NeighbourMessage::default();
    message.header.family = match destination {
        IpAddr::V4(_) => rtnetlink::packet_route::AddressFamily::Inet,
        IpAddr::V6(_) => rtnetlink::packet_route::AddressFamily::Inet6,
    };
    message.header.ifindex = interface_index;
    message.attributes = vec![NeighbourAttribute::Destination(match destination {
        IpAddr::V4(address) => NeighbourAddress::Inet(address),
        IpAddr::V6(address) => NeighbourAddress::Inet6(address),
    })];
    message
}

impl NeighborMutator for LinuxBackend {
    type StaticNeighbor = StaticNeighbor;
    type NeighborEntry = NeighborEntry;

    /// Submits `RTM_NEWNEIGH` with `NUD_PERMANENT` and `NDA_LLADDR` via
    /// `rtnetlink 0.21`'s `neighbours().add(index, destination)` builder,
    /// then re-reads the neighbor table so the returned entry reflects what
    /// the kernel now actually holds (`ReadAfterWrite`, per ADR-0001) rather
    /// than a synthesized guess. `EEXIST` maps to [`Error::AlreadyExists`],
    /// `ENODEV`/`ENOENT` to [`Error::NotFound`], and `EPERM`/`EACCES` to
    /// [`Error::PermissionDenied`]; any other Netlink failure surfaces as
    /// `Error::Platform` with the raw errno.
    fn add_static_neighbor(&self, neighbor: Self::StaticNeighbor) -> Result<Self::NeighborEntry> {
        let interface_index =
            u32::try_from(neighbor.interface_id.value()).map_err(|_| Error::NotFound)?;
        let destination = ip_address_to_std(neighbor.address);
        let mac = neighbor.mac.octets();

        self.runtime.block_on(async {
            self.handle
                .neighbours()
                .add(interface_index, destination)
                .link_layer_address(&mac)
                .execute()
                .await
                .map_err(neighbor_mutation_error)
        })?;

        self.neighbors()?
            .into_iter()
            .find(|entry| {
                entry.interface_index == interface_index && entry.address == neighbor.address
            })
            .ok_or(Error::InvalidState)
    }

    /// Deletes a static entry through `RTM_DELNEIGH`, but only after
    /// confirming through [`NeighborProvider::neighbors`] that a matching
    /// `(interface_id, address)` entry currently exists and is
    /// `NeighborState::Permanent`. This is the safety property ADR-0001
    /// exists for: a present but dynamically learned (non-permanent)
    /// ARP/NDP cache entry is never deleted by this call. A missing target
    /// returns [`Error::NotFound`]; a present but non-permanent target
    /// returns [`Error::InvalidState`].
    fn remove_static_neighbor(&self, neighbor: Self::StaticNeighbor) -> Result<()> {
        let interface_index =
            u32::try_from(neighbor.interface_id.value()).map_err(|_| Error::NotFound)?;

        let observed = self
            .neighbors()?
            .into_iter()
            .find(|entry| {
                entry.interface_index == interface_index && entry.address == neighbor.address
            })
            .ok_or(Error::NotFound)?;

        ensure_removable_static_neighbor_state(observed.state)?;

        let destination = ip_address_to_std(neighbor.address);
        let message = static_neighbor_del_message(interface_index, destination);

        self.runtime.block_on(async {
            self.handle
                .neighbours()
                .del(message)
                .execute()
                .await
                .map_err(neighbor_mutation_error)
        })
    }
}

/// Parses the `nameserver`/`search`/`domain` directives out of a
/// `resolv.conf`-format file (`man 5 resolv.conf`) — the same format on
/// Linux and BSD/macOS, so this parser is shared verbatim by
/// `net-lattice-backend-darwin`.
///
/// `domain` is folded into `search_domains` too: it is the legacy
/// single-domain predecessor of `search` and every modern resolver treats a
/// lone `domain` entry as an implicit one-element search list.
fn parse_resolv_conf(contents: &str) -> DnsConfig {
    let mut config = DnsConfig::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("nameserver") => {
                if let Some(addr) = parts.next().and_then(|s| s.parse::<IpAddr>().ok()) {
                    config.nameservers.push(std_ip_to_ip_address(addr));
                }
            }
            Some("search") | Some("domain") => {
                config
                    .search_domains
                    .extend(parts.map(|domain| domain.to_string()));
            }
            _ => {}
        }
    }
    config
}

fn render_resolv_conf(config: &NewDnsConfig) -> String {
    let mut contents = String::new();
    for nameserver in &config.nameservers {
        contents.push_str("nameserver ");
        contents.push_str(&nameserver.to_string());
        contents.push('\n');
    }
    if !config.search_domains.is_empty() {
        contents.push_str("search ");
        contents.push_str(&config.search_domains.join(" "));
        contents.push('\n');
    }
    contents
}

fn write_resolv_conf(path: &std::path::Path, config: &NewDnsConfig) -> Result<()> {
    std::fs::write(path, render_resolv_conf(config)).map_err(|err| resolv_conf_error(&err))
}

fn resolv_conf_error(err: &std::io::Error) -> Error {
    match err.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound,
        std::io::ErrorKind::PermissionDenied => Error::PermissionDenied,
        _ => Error::Platform(io_error_code(err)),
    }
}

impl CapabilityProvider for LinuxBackend {
    /// `IPV6` unconditionally: every provider this backend implements
    /// (routes, interfaces, neighbors, addresses) already handles both
    /// address families. Netlink delivers every currently modeled event
    /// domain, so this backend truthfully advertises the aggregate
    /// `MONITORING` capability. `VRF`/`NAMESPACES` are left unset — Linux
    /// genuinely supports both at the kernel level, but Net Lattice doesn't
    /// implement either yet, and a `Capability` this backend can't actually
    /// act on would be a lie to the caller. `NEIGHBOR_MUTATION` is now
    /// truthful too: `NeighborMutator` submits real `RTM_NEWNEIGH`/
    /// `RTM_DELNEIGH` requests (see `impl NeighborMutator for LinuxBackend`).
    /// This capability is not yet reachable through the public `net-lattice`
    /// facade — that wiring is Stage 0.17 Slice D, not this backend.
    fn capabilities(&self) -> Capability {
        Capability::IPV6
            | Capability::MONITORING
            | Capability::DNS_MUTATION
            | Capability::INTERFACE_ADMIN_STATE
            | Capability::INTERFACE_MTU
            | Capability::NEIGHBOR_MUTATION
            | Capability::ROUTE_MUTATION
    }
}

/// Maps one Netlink route/link/neighbour/address notification to an
/// [`Event`]. Reuses the existing `message_to_*` conversion functions
/// (built for the one-shot `routes()`/`interfaces()`/... dumps) purely to
/// derive the same `Id` a consumer would see from those methods — a
/// notification's `DelFoo` variant tells us an object was removed. Netlink
/// uses the corresponding `NewFoo` message for both creation and mutation,
/// so it is reported as `Changed` rather than incorrectly promising an add;
/// only the `Id` needs deriving here.
///
/// Returns `None` for Netlink message kinds this backend doesn't turn into
/// an `Event` (link property changes, neighbour tables, ...) and for any
/// notification whose attributes don't parse into an `Id` (extremely rare
/// for the kernel's own unsolicited notifications, but the parsers are
/// intentionally lenient rather than panicking on unexpected input).
fn route_netlink_message_to_event(message: RouteNetlinkMessage) -> Option<Event> {
    match message {
        RouteNetlinkMessage::NewRoute(msg) => message_to_route(&msg).map(|route| Event::Route {
            id: route.id,
            kind: ChangeKind::Changed,
        }),
        RouteNetlinkMessage::DelRoute(msg) => message_to_route(&msg).map(|route| Event::Route {
            id: route.id,
            kind: ChangeKind::Removed,
        }),
        RouteNetlinkMessage::NewLink(msg) => Some(Event::Interface {
            id: Id::new(msg.header.index as u64),
            kind: ChangeKind::Changed,
        }),
        RouteNetlinkMessage::DelLink(msg) => Some(Event::Interface {
            id: Id::new(msg.header.index as u64),
            kind: ChangeKind::Removed,
        }),
        RouteNetlinkMessage::NewNeighbour(msg) => {
            message_to_neighbor(&msg).map(|entry| Event::Neighbor {
                id: entry.id,
                kind: ChangeKind::Changed,
            })
        }
        RouteNetlinkMessage::DelNeighbour(msg) => {
            message_to_neighbor(&msg).map(|entry| Event::Neighbor {
                id: entry.id,
                kind: ChangeKind::Removed,
            })
        }
        RouteNetlinkMessage::NewAddress(msg) => {
            message_to_interface_address(&msg).map(|addr| Event::Address {
                id: addr.id,
                kind: ChangeKind::Changed,
            })
        }
        RouteNetlinkMessage::DelAddress(msg) => {
            message_to_interface_address(&msg).map(|addr| Event::Address {
                id: addr.id,
                kind: ChangeKind::Removed,
            })
        }
        _ => None,
    }
}

impl EventProvider for LinuxBackend {
    type Event = Event;
    type EventFilter = EventFilter;

    /// Opens a *second*, independent Netlink socket subscribed to the
    /// `RTNLGRP_LINK`/`RTNLGRP_NEIGH`/`RTNLGRP_IPV4_ROUTE`/
    /// `RTNLGRP_IPV6_ROUTE`/`RTNLGRP_IPV4_IFADDR`/`RTNLGRP_IPV6_IFADDR`
    /// multicast groups (`rtnetlink::new_multicast_connection`, the same
    /// mechanism `ip monitor` uses) — separate from `self.handle`'s socket,
    /// which only ever sends request/reply traffic. Two background tasks
    /// are spawned onto `self.runtime`: one drives the new socket's
    /// connection (required for it to make progress at all, mirroring
    /// `LinuxBackend::new`'s `connection` task), the other reads
    /// unsolicited notifications off it and forwards mapped `Event`s into
    /// the channel `EventReceiver` reads from.
    ///
    /// DNS resolver configuration changes (`/etc/resolv.conf`) have no
    /// Netlink signal — see `Event`'s doc comment — so no `Event::Dns` is
    /// ever produced by this backend.
    fn watch(&self) -> Result<EventReceiver<Self::Event>> {
        self.watch_filtered(EventFilter::ALL)
    }
    fn watch_filtered(&self, filter: Self::EventFilter) -> Result<EventReceiver<Self::Event>> {
        let groups = [
            MulticastGroup::Link,
            MulticastGroup::Neigh,
            MulticastGroup::Ipv4Route,
            MulticastGroup::Ipv6Route,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
        ];
        let _guard = self.runtime.enter();
        let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(&groups)
            .map_err(|err| Error::Platform(io_error_code(&err)))?;
        let connection = self.runtime.spawn(connection);

        let (sender, receiver) = EventReceiver::bounded();
        let events = self.runtime.spawn(async move {
            while let Some((message, _addr)) = messages.next().await {
                let (_header, payload) = message.into_parts();
                let rtnetlink::packet_core::NetlinkPayload::InnerMessage(inner) = payload else {
                    continue;
                };
                if let Some(event) = route_netlink_message_to_event(inner)
                    && filter.matches(event)
                    && !sender.send(event, Event::resync_all())
                {
                    break;
                }
            }
        });

        Ok(receiver.with_subscription(LinuxWatch { connection, events }))
    }
}

/// Native async monitoring uses the backend's Tokio reactor and Netlink
/// multicast socket directly.
///
/// Unlike `net_lattice_async::from_receiver`, this implementation does not
/// place a blocking worker thread between the kernel notification source and
/// the returned stream.
#[cfg(feature = "async")]
impl TokioEventProvider for LinuxBackend {
    type Event = Event;
    type EventFilter = EventFilter;

    fn watch_tokio(&self, filter: Self::EventFilter) -> Result<TokioEventReceiver<Self::Event>> {
        let groups = [
            MulticastGroup::Link,
            MulticastGroup::Neigh,
            MulticastGroup::Ipv4Route,
            MulticastGroup::Ipv6Route,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
        ];
        let _guard = self.runtime.enter();
        let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(&groups)
            .map_err(|err| Error::Platform(io_error_code(&err)))?;
        let connection = self.runtime.spawn(connection);
        let (sender, receiver) = TokioEventReceiver::bounded();
        let events = self.runtime.spawn(async move {
            while let Some((message, _addr)) = messages.next().await {
                let (_header, payload) = message.into_parts();
                let rtnetlink::packet_core::NetlinkPayload::InnerMessage(inner) = payload else {
                    continue;
                };
                if let Some(event) = route_netlink_message_to_event(inner)
                    && filter.matches(event)
                    && !sender.send(event, Event::resync_all)
                {
                    return;
                }
            }
            let _ = sender.send_error(Error::Disconnected);
        });
        Ok(receiver.with_subscription(LinuxWatch { connection, events }))
    }
}

impl DnsProvider for LinuxBackend {
    type DnsConfig = DnsConfig;

    fn dns_config(&self) -> Result<Self::DnsConfig> {
        let contents =
            std::fs::read_to_string("/etc/resolv.conf").map_err(|err| resolv_conf_error(&err))?;
        Ok(parse_resolv_conf(&contents))
    }
}

impl DnsMutator for LinuxBackend {
    type NewDnsConfig = NewDnsConfig;

    /// Replaces the active global `/etc/resolv.conf` resolver view.
    ///
    /// Only portable nameserver and search directives are rendered; other
    /// directives are not retained. Linux resolver managers can later replace
    /// the file, and this operation does not produce a DNS watcher event.
    /// Failure may leave a partially written file, so callers must re-read
    /// [`DnsProvider::dns_config`] after an error.
    fn set_dns_config(&self, config: Self::NewDnsConfig) -> Result<Self::DnsConfig> {
        write_resolv_conf(std::path::Path::new("/etc/resolv.conf"), &config)?;
        self.dns_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};
    use rtnetlink::LinkDummy;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Builds the same `ndmsg` payload shape that
    /// `impl NeighborMutator for LinuxBackend`'s `add_static_neighbor`
    /// produces via `rtnetlink 0.21`'s `neighbours().add(index,
    /// destination).link_layer_address(...)` builder. Reconstructed here
    /// (rather than calling `NeighbourAddRequest` directly, whose
    /// constructor is `pub(crate)` inside `rtnetlink`) so this deterministic
    /// test can assert the exact wire shape without a live Netlink socket.
    fn static_neighbour_add_fixture(
        interface_index: u32,
        destination: IpAddr,
        mac: [u8; 6],
    ) -> NeighbourMessage {
        let mut message = NeighbourMessage::default();
        message.header.family = match destination {
            IpAddr::V4(_) => rtnetlink::packet_route::AddressFamily::Inet,
            IpAddr::V6(_) => rtnetlink::packet_route::AddressFamily::Inet6,
        };
        message.header.ifindex = interface_index;
        message.header.state = RtNeighbourState::Permanent;
        message.attributes = vec![
            NeighbourAttribute::Destination(match destination {
                IpAddr::V4(address) => NeighbourAddress::Inet(address),
                IpAddr::V6(address) => NeighbourAddress::Inet6(address),
            }),
            NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
        ];
        message
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
                Poll::Ready(Some(_)) | Poll::Pending => thread_sleep(Duration::from_millis(250)),
                Poll::Ready(None) => return false,
            }
        }
        false
    }

    #[cfg(feature = "async")]
    fn thread_sleep(duration: std::time::Duration) {
        std::thread::sleep(duration);
    }

    #[cfg(feature = "async")]
    fn tokio_address_event(
        watcher: &mut TokioEventReceiver<Event>,
        id: InterfaceAddressId,
    ) -> bool {
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};
        use std::time::Duration;

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        for _ in 0..12 {
            match Pin::new(&mut *watcher).poll_recv(&mut context) {
                Poll::Ready(Some(Ok(Event::Address { id: event_id, .. }))) if event_id == id => {
                    return true;
                }
                Poll::Ready(Some(_)) | Poll::Pending => thread_sleep(Duration::from_millis(250)),
                Poll::Ready(None) => return false,
            }
        }
        false
    }

    /// The kernel can reject simultaneous Netlink dumps in a shared CI
    /// network namespace with `EBUSY`. All tests that open a real Netlink
    /// socket take this guard; pure parser tests intentionally do not.
    fn kernel_test_guard() -> MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            // A failed kernel assertion must not hide every later test behind
            // `PoisonError`; they should each report their own OS failure.
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Exercises a real round trip through Netlink, no privilege required:
    /// `RTM_GETROUTE` dumps are readable by any user. This is the one test
    /// in this module that runs by default and actually proves the backend
    /// talks to the kernel, rather than only exercising conversion logic.
    #[test]
    fn routes_reads_the_real_kernel_routing_table() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let routes = backend
            .routes()
            .expect("RTM_GETROUTE dump should not require privilege");
        // Not asserting on contents: the routing table of the machine
        // running this test is arbitrary (may even be empty in a minimal
        // container). Reaching here without an error is the assertion.
        let _ = routes;
    }

    /// Exercises a real round trip through Netlink, no privilege required:
    /// `RTM_GETLINK` dumps are readable by any user, and every Linux system
    /// has at least `lo`.
    #[test]
    fn interfaces_includes_the_loopback_interface() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let interfaces = backend
            .interfaces()
            .expect("RTM_GETLINK dump should not require privilege");
        assert!(
            interfaces
                .iter()
                .any(|iface| iface.name == "lo" && iface.kind == InterfaceKind::Loopback),
            "expected a `lo` interface classified as Loopback, got: {interfaces:?}"
        );
    }

    /// The advertised capabilities are the cross-platform contract exposed
    /// by this backend, rather than a claim about every Linux kernel feature.
    #[test]
    fn capabilities_match_the_implemented_provider_surface() {
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let capabilities = backend.capabilities();
        assert!(capabilities.contains(Capability::IPV6));
        assert!(capabilities.contains(Capability::ROUTE_MONITORING));
        assert!(capabilities.contains(Capability::INTERFACE_MONITORING));
        assert!(capabilities.contains(Capability::NEIGHBOR_MONITORING));
        assert!(capabilities.contains(Capability::ADDRESS_MONITORING));
        assert!(capabilities.contains(Capability::MONITORING));
        assert!(capabilities.contains(Capability::DNS_MUTATION));
        assert!(capabilities.contains(Capability::INTERFACE_ADMIN_STATE));
        assert!(capabilities.contains(Capability::INTERFACE_MTU));
        assert!(capabilities.contains(Capability::NEIGHBOR_MUTATION));
        assert!(capabilities.contains(Capability::ROUTE_MUTATION));
    }

    #[test]
    fn event_transport_covers_model_event_paths() {
        let (sender, receiver) = EventReceiver::bounded_with_capacity(1);
        assert!(sender.send(Event::resync_all(), Event::resync_all()));
        assert!(sender.send(Event::resync_all(), Event::resync_all()));
        assert!(sender.send(Event::resync_all(), Event::resync_all()));
        assert!(receiver.recv().is_ok());
        assert!(sender.send(Event::resync_all(), Event::resync_all()));
        assert!(receiver.recv().is_ok());
        drop(receiver);
        assert!(!sender.send(Event::resync_all(), Event::resync_all()));
        let (sender, receiver) = EventReceiver::<Event>::bounded();
        drop(sender);
        assert!(receiver.recv().is_err());

        #[cfg(feature = "async")]
        {
            use std::pin::Pin;
            use std::task::{Context, Poll, Waker};

            let (sender, mut receiver) = TokioEventReceiver::<Event>::bounded();
            for _ in 0..256 {
                assert!(sender.send(Event::resync_all(), Event::resync_all));
            }
            assert!(sender.send(Event::resync_all(), Event::resync_all));
            assert!(sender.send(Event::resync_all(), Event::resync_all));
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            for _ in 0..256 {
                assert!(matches!(
                    Pin::new(&mut receiver).poll_recv(&mut cx),
                    Poll::Ready(_)
                ));
            }
            assert!(sender.send(Event::resync_all(), Event::resync_all));
            assert!(matches!(
                Pin::new(&mut receiver).poll_recv(&mut cx),
                Poll::Ready(_)
            ));
            assert!(matches!(
                Pin::new(&mut receiver).poll_recv(&mut cx),
                Poll::Ready(_)
            ));
            drop(sender);
            assert!(matches!(
                Pin::new(&mut receiver).poll_recv(&mut cx),
                Poll::Ready(None)
            ));

            let (sender, receiver) = TokioEventReceiver::bounded();
            drop(receiver);
            assert!(!sender.send(Event::resync_all(), Event::resync_all));
            assert!(!sender.send_error(Error::Disconnected));

            let (sender, mut receiver) = TokioEventReceiver::<Event>::bounded();
            assert!(sender.send_error(Error::InvalidState));
            drop(sender);
            assert!(matches!(
                Pin::new(&mut receiver).poll_recv(&mut cx),
                Poll::Ready(Some(Err(Error::InvalidState)))
            ));
        }
    }

    /// Exercises a real round trip through Netlink, no privilege required:
    /// `RTM_GETADDR` dumps are readable by any user, and every Linux system
    /// has at least `lo`'s `127.0.0.1/8`.
    #[test]
    fn addresses_includes_loopbacks_address() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let addresses = backend
            .addresses()
            .expect("RTM_GETADDR dump should not require privilege");
        assert!(
            addresses.iter().any(|addr| matches!(
                addr.address,
                Network::V4(net) if net.address() == Ipv4Address::new(127, 0, 0, 1)
            )),
            "expected `127.0.0.1` among the assigned addresses, got: {addresses:?}"
        );
    }

    /// Exercises a real round trip through Netlink, no privilege required:
    /// `RTM_GETNEIGH` dumps are readable by any user.
    #[test]
    fn neighbors_reads_the_real_kernel_neighbor_table() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let neighbors = backend
            .neighbors()
            .expect("RTM_GETNEIGH dump should not require privilege");
        // Not asserting on contents: the neighbor table of the machine
        // running this test is arbitrary (may even be empty). Reaching here
        // without an error is the assertion.
        let _ = neighbors;
    }

    /// Opens a real multicast subscription without changing system state.
    /// The ignored test below verifies delivery through the same subscription
    /// by adding and removing a temporary route.
    #[test]
    fn watch_opens_a_real_netlink_subscription() {
        use std::time::Duration;

        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        assert!(backend.capabilities().contains(Capability::MONITORING));
        let watcher = backend
            .watch()
            .expect("failed to subscribe to Netlink multicast groups");
        assert!(watcher.recv_timeout(Duration::from_millis(1)).is_ok());
        let filtered = backend
            .watch_filtered(EventFilter::none())
            .expect("failed to subscribe to filtered Netlink events");
        assert_eq!(
            filtered.recv_timeout(Duration::from_millis(1)).unwrap(),
            None
        );
    }

    /// The feature-gated provider opens the same native Netlink multicast
    /// subscription, but delivers it through the Tokio-aware transport used
    /// by `Lattice::watch_async`.
    #[cfg(feature = "async")]
    #[test]
    fn watch_tokio_opens_a_real_netlink_subscription() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let watcher = backend
            .watch_tokio(EventFilter::none())
            .expect("failed to subscribe to Netlink multicast groups");
        drop(watcher);
    }

    #[test]
    fn parse_resolv_conf_reads_nameservers_and_search_domains() {
        let contents = "# comment\n\
                         nameserver 1.1.1.1\n\
                         nameserver 2606:4700:4700::1111\n\
                         search example.com corp.example.com\n";
        let config = parse_resolv_conf(contents);
        assert_eq!(
            config.nameservers,
            vec![
                IpAddress::from(Ipv4Address::new(1, 1, 1, 1)),
                std_ip_to_ip_address("2606:4700:4700::1111".parse().unwrap()),
            ]
        );
        assert_eq!(
            config.search_domains,
            vec!["example.com".to_string(), "corp.example.com".to_string()]
        );
    }

    #[test]
    fn render_resolv_conf_preserves_requested_order() {
        let config = NewDnsConfig::with(
            vec![
                IpAddress::from(Ipv4Address::new(1, 1, 1, 1)),
                std_ip_to_ip_address("2606:4700:4700::1111".parse().unwrap()),
                std_ip_to_ip_address("2001:4860:4860::8888".parse().unwrap()),
                IpAddress::from(Ipv4Address::new(8, 8, 8, 8)),
            ],
            vec!["example.test".to_string(), "corp.test".to_string()],
        );
        assert_eq!(
            render_resolv_conf(&config),
            "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\nnameserver 2001:4860:4860::8888\nnameserver 8.8.8.8\nsearch example.test corp.test\n"
        );
    }

    #[test]
    fn resolver_parser_ignores_nonportable_directives_and_renderer_handles_empty_config() {
        let config =
            parse_resolv_conf("options rotate\ninvalid 192.0.2.1\nnameserver invalid\nsearch\n");
        assert!(config.nameservers.is_empty());
        assert!(config.search_domains.is_empty());
        assert_eq!(render_resolv_conf(&NewDnsConfig::new()), "");
    }

    #[test]
    fn ip_and_network_conversion_round_trip_both_families() {
        let ipv4 = IpAddress::from(Ipv4Address::new(192, 0, 2, 1));
        let ipv6 = std_ip_to_ip_address("2001:db8::1".parse().expect("IPv6"));
        assert_eq!(std_ip_to_ip_address(ip_address_to_std(ipv4)), ipv4);
        assert_eq!(std_ip_to_ip_address(ip_address_to_std(ipv6)), ipv6);

        let v4_network = Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, 0),
            Ipv4PrefixLength::new(24).expect("prefix"),
        ));
        let v6_network = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
            net_lattice_ip::Ipv6PrefixLength::new(32).expect("prefix"),
        ));
        assert_eq!(network_to_std(v4_network).1, 24);
        assert_eq!(network_to_std(v6_network).1, 32);
    }

    #[test]
    fn netlink_message_fixtures_preserve_address_route_and_neighbor_details() {
        let mut address = AddressMessage::default();
        address.header.index = 7;
        address.header.prefix_len = 24;
        address.attributes = vec![
            AddressAttribute::Address(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 99))),
            AddressAttribute::Local(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7))),
            AddressAttribute::Broadcast(std::net::Ipv4Addr::new(192, 0, 2, 255)),
        ];
        let observed = message_to_interface_address(&address).expect("valid IPv4 address");
        assert_eq!(observed.interface_index, 7);
        assert_eq!(
            observed.address,
            Network::from(Ipv4Network::new(
                Ipv4Address::new(192, 0, 2, 7),
                Ipv4PrefixLength::new(24).unwrap(),
            ))
        );
        assert_eq!(
            observed.broadcast,
            Some(IpAddress::from(Ipv4Address::new(192, 0, 2, 255)))
        );

        let mut ipv6_address = AddressMessage::default();
        ipv6_address.header.index = 7;
        ipv6_address.header.prefix_len = 64;
        ipv6_address
            .attributes
            .push(AddressAttribute::Address(IpAddr::V6(
                "2001:db8:0:16::7".parse().expect("IPv6 address"),
            )));
        let observed =
            message_to_interface_address(&ipv6_address).expect("valid IPv6 address message");
        assert_eq!(observed.interface_index, 7);
        assert_eq!(
            observed.address,
            Network::from(net_lattice_ip::Ipv6Network::new(
                net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 7]),
                net_lattice_ip::Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
            ))
        );
        assert!(observed.broadcast.is_none());
        assert!(message_to_interface_address(&AddressMessage::default()).is_none());

        let route = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .destination_prefix(std::net::Ipv4Addr::new(198, 51, 100, 0), 24)
            .gateway(std::net::Ipv4Addr::new(192, 0, 2, 1))
            .priority(42)
            .output_interface(7)
            .build();
        let observed = message_to_route(&route).expect("valid IPv4 route");
        assert_eq!(
            observed.gateway,
            Some(IpAddress::from(Ipv4Address::new(192, 0, 2, 1)))
        );
        assert_eq!(observed.metric, Some(42));
        assert_eq!(observed.interface_index, Some(7));
        assert!(message_to_route(&RouteMessage::default()).is_none());

        let ipv6_destination = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 0]),
            net_lattice_ip::Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let ipv6_route = RouteConfig::new(ipv6_destination)
            .with_gateway(IpAddress::from(net_lattice_ip::Ipv6Address::new([
                0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1,
            ])))
            .with_metric(42)
            .with_interface_index(7);
        let add_request = route_request_message(&ipv6_route, true);
        let observed = message_to_route(&add_request).expect("valid IPv6 add request");
        assert_eq!(observed.destination, ipv6_destination);
        assert_eq!(observed.gateway, ipv6_route.gateway);
        assert_eq!(observed.metric, ipv6_route.metric);
        assert_eq!(observed.interface_index, ipv6_route.interface_index);

        let delete_request = route_request_message(&ipv6_route, false);
        let observed = message_to_route(&delete_request).expect("valid IPv6 delete request");
        assert_eq!(observed.destination, ipv6_destination);
        assert_eq!(observed.gateway, None);
        assert_eq!(observed.metric, None);
        assert_eq!(observed.interface_index, ipv6_route.interface_index);

        let mut neighbor = NeighbourMessage::default();
        neighbor.header.ifindex = 7;
        neighbor.header.state = RtNeighbourState::Reachable;
        neighbor.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet(std::net::Ipv4Addr::new(
                192, 0, 2, 1,
            ))),
            NeighbourAttribute::LinkLayerAddress(vec![0, 1, 2, 3, 4, 5]),
        ];
        let observed = message_to_neighbor(&neighbor).expect("valid IPv4 neighbour");
        assert_eq!(observed.interface_index, 7);
        assert_eq!(observed.state, NeighborState::Reachable);
        assert_eq!(observed.mac, Some(MacAddress::new([0, 1, 2, 3, 4, 5])));
        assert!(message_to_neighbor(&NeighbourMessage::default()).is_none());

        let mut ipv6_neighbor = NeighbourMessage::default();
        ipv6_neighbor.header.ifindex = 7;
        ipv6_neighbor.header.state = RtNeighbourState::Reachable;
        ipv6_neighbor.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                "2001:db8:0:16::1".parse().expect("valid IPv6 NDP address"),
            )),
            NeighbourAttribute::LinkLayerAddress(vec![2, 0, 0, 0, 0, 0x16]),
        ];
        let observed = message_to_neighbor(&ipv6_neighbor).expect("valid IPv6 neighbour");
        assert_eq!(observed.interface_index, 7);
        assert_eq!(
            observed.address,
            IpAddress::from(net_lattice_ip::Ipv6Address::new([
                0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1,
            ]))
        );
        assert_eq!(observed.state, NeighborState::Reachable);
        assert_eq!(observed.mac, Some(MacAddress::new([2, 0, 0, 0, 0, 0x16])));
        assert_eq!(
            observed.id,
            synthesize_neighbor_id(7, &observed.address),
            "IPv6 neighbor identity uses the same interface/address key"
        );
    }

    #[test]
    fn static_neighbour_add_fixtures_preserve_ipv4_arp_and_ipv6_ndp_abi_fields() {
        let ipv4 = static_neighbour_add_fixture(
            7,
            IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 17)),
            [0, 1, 2, 3, 4, 5],
        );
        assert_eq!(
            ipv4.header.family,
            rtnetlink::packet_route::AddressFamily::Inet
        );
        assert_eq!(ipv4.header.ifindex, 7);
        assert_eq!(ipv4.header.state, RtNeighbourState::Permanent);
        assert_eq!(
            ipv4.attributes,
            vec![
                NeighbourAttribute::Destination(NeighbourAddress::Inet(std::net::Ipv4Addr::new(
                    192, 0, 2, 17
                ),)),
                NeighbourAttribute::LinkLayerAddress(vec![0, 1, 2, 3, 4, 5]),
            ]
        );

        let ipv6 = static_neighbour_add_fixture(
            9,
            IpAddr::V6("2001:db8:0:17::1".parse().expect("valid IPv6 NDP address")),
            [2, 0, 0, 0, 0, 0x17],
        );
        assert_eq!(
            ipv6.header.family,
            rtnetlink::packet_route::AddressFamily::Inet6
        );
        assert_eq!(ipv6.header.ifindex, 9);
        assert_eq!(ipv6.header.state, RtNeighbourState::Permanent);
        assert_eq!(
            ipv6.attributes,
            vec![
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                    "2001:db8:0:17::1".parse().expect("valid IPv6 NDP address"),
                )),
                NeighbourAttribute::LinkLayerAddress(vec![2, 0, 0, 0, 0, 0x17]),
            ]
        );
    }

    #[test]
    fn static_neighbor_del_message_selects_by_destination_without_lladdr() {
        let ipv4 =
            static_neighbor_del_message(7, IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 17)));
        assert_eq!(
            ipv4.header.family,
            rtnetlink::packet_route::AddressFamily::Inet
        );
        assert_eq!(ipv4.header.ifindex, 7);
        assert_eq!(
            ipv4.attributes,
            vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(
                std::net::Ipv4Addr::new(192, 0, 2, 17),
            ))]
        );
        assert!(
            !ipv4
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, NeighbourAttribute::LinkLayerAddress(_))),
            "RTM_DELNEIGH selection does not require NDA_LLADDR"
        );

        let ipv6 = static_neighbor_del_message(
            9,
            IpAddr::V6("2001:db8:0:17::1".parse().expect("valid IPv6 NDP address")),
        );
        assert_eq!(
            ipv6.header.family,
            rtnetlink::packet_route::AddressFamily::Inet6
        );
        assert_eq!(ipv6.header.ifindex, 9);
        assert_eq!(
            ipv6.attributes,
            vec![NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                "2001:db8:0:17::1".parse().expect("valid IPv6 NDP address"),
            ))]
        );
        assert!(
            !ipv6
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, NeighbourAttribute::LinkLayerAddress(_))),
            "RTM_DELNEIGH selection does not require NDA_LLADDR"
        );
    }

    // Pins today's raw errno passthrough only; per-errno semantic mapping (e.g. to a NotFound/PermissionDenied variant) is a separate cross-cutting decision out of scope for this slice.
    #[test]
    fn rtnetlink_error_code_passes_through_raw_errno_without_semantic_mapping() {
        let mut enoent_message = rtnetlink::packet_core::ErrorMessage::default();
        enoent_message.code = std::num::NonZeroI32::new(-2);
        let enoent = rtnetlink::Error::NetlinkError(enoent_message);
        assert_eq!(rtnetlink_error_code(&enoent), PlatformErrorCode::Linux(-2));

        let mut eacces_message = rtnetlink::packet_core::ErrorMessage::default();
        eacces_message.code = std::num::NonZeroI32::new(-13);
        let eacces = rtnetlink::Error::NetlinkError(eacces_message);
        assert_eq!(rtnetlink_error_code(&eacces), PlatformErrorCode::Linux(-13));
    }

    fn netlink_error_with_code(code: i32) -> rtnetlink::Error {
        let mut message = rtnetlink::packet_core::ErrorMessage::default();
        message.code = std::num::NonZeroI32::new(code);
        rtnetlink::Error::NetlinkError(message)
    }

    #[test]
    fn neighbor_mutation_error_maps_eexist_enoent_enodev_eperm_and_eacces() {
        assert!(matches!(
            neighbor_mutation_error(netlink_error_with_code(-17)),
            Error::AlreadyExists
        ));
        assert!(matches!(
            neighbor_mutation_error(netlink_error_with_code(-2)),
            Error::NotFound
        ));
        assert!(matches!(
            neighbor_mutation_error(netlink_error_with_code(-19)),
            Error::NotFound
        ));
        assert!(matches!(
            neighbor_mutation_error(netlink_error_with_code(-1)),
            Error::PermissionDenied
        ));
        assert!(matches!(
            neighbor_mutation_error(netlink_error_with_code(-13)),
            Error::PermissionDenied
        ));
        assert!(matches!(
            neighbor_mutation_error(netlink_error_with_code(-22)),
            Error::Platform(PlatformErrorCode::Linux(-22))
        ));
    }

    #[test]
    fn ensure_removable_static_neighbor_state_rejects_non_permanent_entries() {
        assert!(ensure_removable_static_neighbor_state(NeighborState::Permanent).is_ok());
        for dynamic_state in [
            NeighborState::Incomplete,
            NeighborState::Reachable,
            NeighborState::Stale,
            NeighborState::Delay,
            NeighborState::Probe,
            NeighborState::Failed,
            NeighborState::Unknown,
        ] {
            assert!(matches!(
                ensure_removable_static_neighbor_state(dynamic_state),
                Err(Error::InvalidState)
            ));
        }
    }

    #[test]
    fn netlink_error_and_state_mappings_are_stable() {
        assert_eq!(
            io_error_code(&std::io::Error::from_raw_os_error(13)),
            PlatformErrorCode::Linux(13)
        );
        assert_eq!(
            io_error_code(&std::io::Error::other("no OS error")),
            PlatformErrorCode::Linux(0)
        );
        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Failed),
            NeighborState::Failed
        );
        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Reachable),
            NeighborState::Reachable
        );
    }

    #[test]
    fn netlink_interface_and_neighbor_mappings_cover_all_known_states() {
        assert_eq!(
            link_layer_type_to_kind(LinkLayerType::Ether),
            InterfaceKind::Ethernet
        );
        assert_eq!(
            link_layer_type_to_kind(LinkLayerType::Loopback),
            InterfaceKind::Loopback
        );
        assert_eq!(
            link_layer_type_to_kind(LinkLayerType::Ppp),
            InterfaceKind::PointToPoint
        );
        assert_eq!(
            link_layer_type_to_kind(LinkLayerType::Ieee80211),
            InterfaceKind::Wireless
        );
        assert_eq!(
            link_layer_type_to_kind(LinkLayerType::Ieee80211Prism),
            InterfaceKind::Wireless
        );
        assert_eq!(
            link_layer_type_to_kind(LinkLayerType::Ieee80211Radiotap),
            InterfaceKind::Wireless
        );
        assert!(matches!(
            link_layer_type_to_kind(LinkLayerType::Netrom),
            InterfaceKind::Other(_)
        ));

        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Incomplete),
            NeighborState::Incomplete
        );
        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Stale),
            NeighborState::Stale
        );
        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Delay),
            NeighborState::Delay
        );
        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Probe),
            NeighborState::Probe
        );
        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Permanent),
            NeighborState::Permanent
        );
        assert_eq!(
            neighbour_state_to_state(RtNeighbourState::Noarp),
            NeighborState::Unknown
        );
    }

    #[test]
    fn interface_config_netlink_message_changes_only_requested_fields() {
        let combined = InterfaceConfig::new(Id::new(7), Some(DesiredAdminState::Up), Some(9000))
            .expect("valid combined patch");
        let message = interface_config_to_link_change(&combined).expect("link request");
        assert_eq!(message.header.index, 7);
        assert_eq!(message.header.change_mask, LinkFlags::Up);
        assert_eq!(message.header.flags, LinkFlags::Up);
        assert!(matches!(
            message.attributes.as_slice(),
            [LinkAttribute::Mtu(9000)]
        ));

        let down_only = InterfaceConfig::new(Id::new(8), Some(DesiredAdminState::Down), None)
            .expect("valid admin-only patch");
        let message = interface_config_to_link_change(&down_only).expect("link request");
        assert_eq!(message.header.index, 8);
        assert_eq!(message.header.change_mask, LinkFlags::Up);
        assert!(message.header.flags.is_empty());
        assert!(message.attributes.is_empty());

        let up_only = InterfaceConfig::new(Id::new(9), Some(DesiredAdminState::Up), None)
            .expect("valid admin-only patch");
        let message = interface_config_to_link_change(&up_only).expect("link request");
        assert_eq!(message.header.change_mask, LinkFlags::Up);
        assert_eq!(message.header.flags, LinkFlags::Up);
        assert!(message.attributes.is_empty());

        let mtu_only =
            InterfaceConfig::new(Id::new(10), None, Some(1500)).expect("valid mtu-only patch");
        let message = interface_config_to_link_change(&mtu_only).expect("link request");
        assert_eq!(message.header.index, 10);
        assert_eq!(message.header.change_mask, LinkFlags::empty());
        assert!(message.header.flags.is_empty());
        assert!(matches!(
            message.attributes.as_slice(),
            [LinkAttribute::Mtu(1500)]
        ));
    }

    #[test]
    fn netlink_event_mapper_covers_every_supported_domain_and_change_kind() {
        let route = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .destination_prefix(std::net::Ipv4Addr::new(198, 51, 100, 0), 24)
            .build();
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::NewRoute(route.clone())),
            Some(Event::Route {
                kind: ChangeKind::Changed,
                ..
            })
        ));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::DelRoute(route)),
            Some(Event::Route {
                kind: ChangeKind::Removed,
                ..
            })
        ));

        let ipv6_route = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix("2001:db8:0:16::".parse().expect("IPv6 destination"), 64)
            .gateway("2001:db8:0:16::1".parse().expect("IPv6 gateway"))
            .priority(42)
            .output_interface(7)
            .build();
        let ipv6_id = message_to_route(&ipv6_route)
            .expect("valid IPv6 route event fixture")
            .id;
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::NewRoute(ipv6_route.clone())),
            Some(Event::Route {
                id,
                kind: ChangeKind::Changed,
            }) if id == ipv6_id
        ));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::DelRoute(ipv6_route)),
            Some(Event::Route {
                id,
                kind: ChangeKind::Removed,
            }) if id == ipv6_id
        ));

        let mut link = LinkMessage::default();
        link.header.index = 7;
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::NewLink(link.clone())),
            Some(Event::Interface { id, kind: ChangeKind::Changed }) if id == Id::new(7)
        ));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::DelLink(link)),
            Some(Event::Interface { id, kind: ChangeKind::Removed }) if id == Id::new(7)
        ));

        let mut address = AddressMessage::default();
        address.header.index = 7;
        address.header.prefix_len = 24;
        address.attributes.push(AddressAttribute::Local(IpAddr::V4(
            std::net::Ipv4Addr::new(192, 0, 2, 7),
        )));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::NewAddress(address.clone())),
            Some(Event::Address {
                kind: ChangeKind::Changed,
                ..
            })
        ));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::DelAddress(address)),
            Some(Event::Address {
                kind: ChangeKind::Removed,
                ..
            })
        ));

        let mut ipv6_address = AddressMessage::default();
        ipv6_address.header.index = 7;
        ipv6_address.header.prefix_len = 64;
        ipv6_address
            .attributes
            .push(AddressAttribute::Address(IpAddr::V6(
                "2001:db8:0:16::7".parse().expect("IPv6 address"),
            )));
        let ipv6_id = message_to_interface_address(&ipv6_address)
            .expect("valid IPv6 address event fixture")
            .id;
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::NewAddress(ipv6_address.clone())),
            Some(Event::Address { id, kind: ChangeKind::Changed }) if id == ipv6_id
        ));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::DelAddress(ipv6_address)),
            Some(Event::Address { id, kind: ChangeKind::Removed }) if id == ipv6_id
        ));

        let mut neighbor = NeighbourMessage::default();
        neighbor.header.ifindex = 7;
        neighbor
            .attributes
            .push(NeighbourAttribute::Destination(NeighbourAddress::Inet(
                std::net::Ipv4Addr::new(192, 0, 2, 1),
            )));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::NewNeighbour(neighbor.clone())),
            Some(Event::Neighbor {
                kind: ChangeKind::Changed,
                ..
            })
        ));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::DelNeighbour(neighbor)),
            Some(Event::Neighbor {
                kind: ChangeKind::Removed,
                ..
            })
        ));

        let mut ipv6_neighbor = NeighbourMessage::default();
        ipv6_neighbor.header.ifindex = 7;
        ipv6_neighbor.header.state = RtNeighbourState::Reachable;
        ipv6_neighbor.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                "2001:db8:0:16::1".parse().expect("valid IPv6 NDP address"),
            )),
            NeighbourAttribute::LinkLayerAddress(vec![2, 0, 0, 0, 0, 0x16]),
        ];
        let ipv6_id = message_to_neighbor(&ipv6_neighbor)
            .expect("valid IPv6 neighbor event fixture")
            .id;
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::NewNeighbour(ipv6_neighbor.clone())),
            Some(Event::Neighbor {
                id,
                kind: ChangeKind::Changed,
            }) if id == ipv6_id
        ));
        assert!(matches!(
            route_netlink_message_to_event(RouteNetlinkMessage::DelNeighbour(ipv6_neighbor)),
            Some(Event::Neighbor {
                id,
                kind: ChangeKind::Removed,
            }) if id == ipv6_id
        ));
    }

    #[test]
    fn mutation_validation_and_resolver_errors_are_explicit() {
        assert!(matches!(
            resolv_conf_error(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            Error::NotFound
        ));
        assert!(matches!(
            resolv_conf_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            Error::PermissionDenied
        ));
        assert!(matches!(
            resolv_conf_error(&std::io::Error::other("resolver failure")),
            Error::Platform(PlatformErrorCode::Linux(_))
        ));

        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let ipv6 = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
            net_lattice_ip::Ipv6PrefixLength::new(64).unwrap(),
        ));
        let request = NewInterfaceAddress::new(Id::new(1), ipv6)
            .with_broadcast(Ipv4Address::new(192, 0, 2, 255));
        assert!(matches!(
            backend.add_address(request),
            Err(Error::InvalidState)
        ));
    }

    /// Reads the real `/etc/resolv.conf` present on this test environment.
    /// Every Linux system has one (even if empty/symlinked to
    /// systemd-resolved's stub), so this exercises the real filesystem read
    /// without requiring any specific content.
    #[test]
    fn dns_config_reads_the_real_resolv_conf() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let config = backend
            .dns_config()
            .expect("/etc/resolv.conf should be readable");
        let _ = config;
    }

    /// Guards a real `/etc/resolv.conf` write so a test failure (assertion
    /// or panic) still restores the original resolver configuration this
    /// test environment had before the test ran, mirroring
    /// `InterfaceRestore`'s `Drop`-based restoration for interface state.
    struct DnsRestore<'a> {
        backend: &'a LinuxBackend,
        original: NewDnsConfig,
    }

    impl Drop for DnsRestore<'_> {
        fn drop(&mut self) {
            // A test failure must not leave a privileged runner's resolver
            // configuration changed. There is no useful way for `Drop` to
            // report a second failure, so the test also verifies
            // restoration below.
            let _ = self.backend.set_dns_config(self.original.clone());
        }
    }

    /// Requires `CAP_NET_ADMIN` (root, or `sudo -E cargo test -- --ignored`
    /// in this crate). Not run by default for the same reason as the other
    /// privileged round-trip tests: most development and CI environments
    /// don't grant it, and this test would otherwise fail with
    /// `PermissionDenied` rather than being skipped.
    ///
    /// Captures the real `/etc/resolv.conf` present on this test
    /// environment, writes a documentation-only test value (RFC 5737
    /// `203.0.113.53`, TEST-NET-3, plus a `net-lattice-test.invalid` search
    /// domain), verifies the write via a read-after-write, and restores the
    /// original configuration on every exit path (success, assertion
    /// failure, or panic) via `DnsRestore`'s `Drop` implementation.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux dns_configuration_round_trips_through_the_kernel -- --ignored`"]
    fn dns_configuration_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let before = backend
            .dns_config()
            .expect("/etc/resolv.conf should be readable before the test");
        let original =
            NewDnsConfig::with(before.nameservers.clone(), before.search_domains.clone());
        let desired = NewDnsConfig::with(
            vec![IpAddress::from(Ipv4Address::new(203, 0, 113, 53))],
            vec!["net-lattice-test.invalid".to_string()],
        );

        {
            let _restore = DnsRestore {
                backend: &backend,
                original: original.clone(),
            };
            let observed = backend
                .set_dns_config(desired.clone())
                .unwrap_or_else(|error| {
                    panic!("set_dns_config failed - are you running with CAP_NET_ADMIN?: {error:?}")
                });
            assert_eq!(observed.nameservers, desired.nameservers);
            assert_eq!(observed.search_domains, desired.search_domains);

            let read_after_write = backend
                .dns_config()
                .expect("/etc/resolv.conf should be readable after the write");
            assert_eq!(read_after_write.nameservers, desired.nameservers);
            assert_eq!(read_after_write.search_domains, desired.search_domains);
        }

        let restored = backend
            .dns_config()
            .expect("/etc/resolv.conf should be readable after restoration");
        assert_eq!(restored.nameservers, before.nameservers);
        assert_eq!(restored.search_domains, before.search_domains);
    }

    #[test]
    #[ignore = "requires a working Netlink socket; run with the privileged backend coverage job"]
    fn invalid_mutations_exercise_kernel_error_paths() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let network = Network::from(Ipv4Network::new(
            Ipv4Address::new(203, 0, 113, 250),
            Ipv4PrefixLength::new(32).expect("valid prefix"),
        ));
        let requested = NewInterfaceAddress::new(Id::new(u64::from(u32::MAX)), network);
        assert!(backend.add_address(requested).is_err());

        let missing = InterfaceAddress::new(Id::new(u64::MAX), u32::MAX, network);
        assert!(backend.remove_address(missing).is_err());

        let route = RouteConfig::new(network).with_interface_index(u32::MAX);
        assert!(backend.add_route(route).is_err());
        assert!(backend.remove_route(route).is_err());
    }

    fn loopback_interface_index(backend: &LinuxBackend) -> u32 {
        backend
            .runtime
            .block_on(async {
                let mut links = backend
                    .handle
                    .link()
                    .get()
                    .match_name("lo".into())
                    .execute();
                links
                    .try_next()
                    .await
                    .ok()
                    .flatten()
                    .map(|link| link.header.index)
            })
            .expect("this test environment has no `lo` interface")
    }

    /// A dedicated `dummy` interface for privileged neighbor-mutation tests.
    ///
    /// IPv4 ARP entries cannot be `NUD_PERMANENT` on `lo`: the kernel's ARP
    /// constructor (`net/ipv4/arp.c`) forces every neighbor entry on an
    /// `IFF_LOOPBACK` device to `NUD_NOARP`, silently overriding the
    /// requested state, so a freshly added static entry never appears as a
    /// matching `(interface_index, address)` row in a subsequent
    /// `RTM_GETNEIGH` dump and `add_static_neighbor`'s read-after-write
    /// lookup returns `Error::InvalidState`. IPv6 NDP has no equivalent
    /// loopback override, which is why the sibling IPv6 test tolerates `lo`.
    /// A `dummy` link (always available via the in-kernel `dummy` driver,
    /// no kernel module install required) has real `header_ops` and is not
    /// `IFF_LOOPBACK`, so it supports genuine `NUD_PERMANENT` ARP/NDP
    /// entries. `Drop` removes the link on every exit path, including test
    /// panics, per this repository's isolated-topology cleanup rule.
    struct DummyLinkFixture<'a> {
        backend: &'a LinuxBackend,
        index: u32,
    }

    impl<'a> DummyLinkFixture<'a> {
        fn new(backend: &'a LinuxBackend, name: &str) -> Self {
            let leftover = backend.runtime.block_on(async {
                let mut links = backend
                    .handle
                    .link()
                    .get()
                    .match_name(name.into())
                    .execute();
                links.try_next().await.ok().flatten()
            });
            if let Some(leftover) = leftover {
                // Recover from an interrupted prior run before attempting to
                // create a same-named interface.
                let _ = backend.runtime.block_on(async {
                    backend
                        .handle
                        .link()
                        .del(leftover.header.index)
                        .execute()
                        .await
                });
            }

            backend
                .runtime
                .block_on(async {
                    backend
                        .handle
                        .link()
                        .add(LinkDummy::new(name).build())
                        .execute()
                        .await
                })
                .expect(
                    "failed to create the dummy test interface - are you running with CAP_NET_ADMIN?",
                );

            let index = backend
                .runtime
                .block_on(async {
                    let mut links = backend
                        .handle
                        .link()
                        .get()
                        .match_name(name.into())
                        .execute();
                    links.try_next().await.ok().flatten()
                })
                .map(|link| link.header.index)
                .expect("dummy test interface disappeared immediately after creation");

            let mut up = LinkMessage::default();
            up.header.index = index;
            up.header.change_mask = LinkFlags::Up;
            up.header.flags = LinkFlags::Up;
            backend
                .runtime
                .block_on(async { backend.handle.link().set(up).execute().await })
                .expect("failed to bring the dummy test interface up");

            // `RTM_NEWLINK`'s ACK confirms the kernel accepted the admin-up
            // request, not that the device has finished transitioning to
            // `IFF_RUNNING`. Adding a static neighbor immediately afterward
            // has been observed to intermittently fail on loaded CI runners;
            // poll for `OperationalState::Up` before handing the interface
            // back, bounded so a genuine failure to come up still surfaces.
            let mut attempts = 0;
            loop {
                let ready = backend
                    .interfaces()
                    .ok()
                    .into_iter()
                    .flatten()
                    .any(|interface| {
                        interface.id == Id::new(index as u64)
                            && interface.operational_state == OperationalState::Up
                    });
                if ready || attempts >= 50 {
                    break;
                }
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }

            Self { backend, index }
        }

        fn index(&self) -> u32 {
            self.index
        }
    }

    impl Drop for DummyLinkFixture<'_> {
        fn drop(&mut self) {
            let _ = self
                .backend
                .runtime
                .block_on(async { self.backend.handle.link().del(self.index).execute().await });
        }
    }

    fn restore_config(interface: &Interface) -> InterfaceConfig {
        let admin_state = match interface.admin_state {
            AdminState::Up => DesiredAdminState::Up,
            AdminState::Down => DesiredAdminState::Down,
            AdminState::Unknown => panic!("Linux must report an administrative state"),
            _ => panic!("unexpected future administrative state"),
        };
        InterfaceConfig::new(interface.id, Some(admin_state), interface.mtu)
            .expect("observed Linux interface is a valid restoration patch")
    }

    struct InterfaceRestore<'a> {
        backend: &'a LinuxBackend,
        config: InterfaceConfig,
    }

    impl Drop for InterfaceRestore<'_> {
        fn drop(&mut self) {
            // A test failure must not leave a privileged runner's link in a
            // changed state. There is no useful way for `Drop` to report a
            // second failure, so the test also verifies restoration below.
            let _ = self.backend.set_interface_config(self.config.clone());
        }
    }

    /// Requires `CAP_NET_ADMIN` (root, or `sudo -E cargo test -- --ignored`
    /// in this crate). Not run by default because most development and CI
    /// environments — including the one this crate was originally written
    /// in — don't grant it, and this test would otherwise fail with
    /// `PermissionDenied` rather than being skipped.
    ///
    /// Uses a documentation-only prefix (RFC 5737 `203.0.113.0/24`,
    /// TEST-NET-3) on `lo` so it can't collide with or disrupt real
    /// routing, and removes what it added regardless of assertion outcome.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux -- --ignored`"]
    fn add_then_remove_route_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let interface_index = loopback_interface_index(&backend);

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
            add_result.expect("add_route failed - are you running with CAP_NET_ADMIN?");
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

    /// Exercises the complete route-mutation path against the real kernel
    /// for an IPv6 destination: create a route on `lo`, read the canonical
    /// observed record, then remove that exact record. Uses RFC 3849
    /// `2001:db8::/32` (the IPv6 documentation prefix), the IPv6 counterpart
    /// of the IPv4 route test's RFC 5737 `203.0.113.0/24`, distinct from
    /// the other IPv6 subnets used by the other ignored tests in this
    /// module so concurrent kernel state never overlaps.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux add_then_remove_ipv6_route_round_trips_through_the_kernel -- --ignored`"]
    fn add_then_remove_ipv6_route_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let interface_index = loopback_interface_index(&backend);

        let destination = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 1, 0, 0, 0, 0, 0]),
            net_lattice_ip::Ipv6PrefixLength::new(64).unwrap(),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface_index);

        // Recover from an interrupted prior run before attempting the add.
        let _ = backend.remove_route(route);

        let add_result = backend.add_route(route);
        if matches!(
            add_result,
            Err(Error::PermissionDenied) | Err(Error::Platform(_))
        ) {
            // Best effort even under #[ignore]: if it's run without the
            // capability after all, fail loudly rather than silently
            // passing on a no-op.
            add_result.expect("add_route failed - are you running with CAP_NET_ADMIN?");
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

    /// Exercises the complete address-mutation path against the real
    /// kernel: create an IPv4 address on `lo`, read the canonical observed
    /// record, then remove that exact record. TEST-NET-1 is reserved for
    /// documentation and is distinct from the route tests' prefixes.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux add_then_remove_address_round_trips_through_the_kernel -- --ignored`"]
    fn add_then_remove_address_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let interface_index = loopback_interface_index(&backend);
        let network = Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, 9),
            Ipv4PrefixLength::new(24).unwrap(),
        ));
        let requested = NewInterfaceAddress::new(Id::new(interface_index as u64), network);

        // A prior interrupted ignored-test run must not turn this run into a
        // false duplicate. The address range is test-only and cleanup is
        // deliberately best-effort before the actual assertion path.
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
            .add_address(requested)
            .expect("add_address failed - are you running with CAP_NET_ADMIN?");
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

    /// Exercises the complete address-mutation path against the real
    /// kernel for an IPv6 address: create an address on `lo`, read the
    /// canonical observed record, then remove that exact record. Uses RFC
    /// 3849 `2001:db8::/32`, the IPv6 counterpart of the IPv4 address
    /// test's TEST-NET-1 `192.0.2.0/24`, on a subnet distinct from the
    /// other IPv6 subnets used by the other ignored tests in this module.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux add_then_remove_ipv6_address_round_trips_through_the_kernel -- --ignored`"]
    fn add_then_remove_ipv6_address_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let interface_index = loopback_interface_index(&backend);
        let network = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 2, 0, 0, 0, 0, 9]),
            net_lattice_ip::Ipv6PrefixLength::new(64).unwrap(),
        ));
        let requested = NewInterfaceAddress::new(Id::new(interface_index as u64), network);

        // A prior interrupted ignored-test run must not turn this run into a
        // false duplicate. The address range is test-only and cleanup is
        // deliberately best-effort before the actual assertion path.
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
            .add_address(requested)
            .expect("add_address failed - are you running with CAP_NET_ADMIN?");
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

    /// Exercises the complete static-neighbor mutation path against the real
    /// kernel for an IPv4 ARP entry: add a permanent entry on a dedicated
    /// `dummy` test interface, confirm it reads back as
    /// `NeighborState::Permanent` with the requested MAC (`ReadAfterWrite`),
    /// confirm the non-permanent-target guard rejects a mismatched-state
    /// removal attempt is unreachable here (this entry is permanent by
    /// construction), then remove it and confirm it is gone. Uses
    /// TEST-NET-2 (RFC 5737 `198.51.100.0/24`), distinct from the
    /// address/route tests' TEST-NET-1/TEST-NET-3 ranges so concurrent
    /// kernel state never overlaps. Runs on `DummyLinkFixture`, not `lo`:
    /// the kernel's IPv4 ARP constructor forces `NUD_NOARP` on every
    /// `IFF_LOOPBACK` device, so a requested `NUD_PERMANENT` entry on `lo`
    /// never appears in a `neighbors()` read-after-write lookup.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux add_then_remove_static_neighbor_round_trips_through_the_kernel -- --ignored`"]
    fn add_then_remove_static_neighbor_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let link = DummyLinkFixture::new(&backend, "nl-test-arp0");
        let interface_index = link.index();
        let interface_id = Id::new(interface_index as u64);
        let address = IpAddress::from(Ipv4Address::new(198, 51, 100, 77));
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x77]);
        let neighbor = StaticNeighbor::new(interface_id, address, mac);

        // Recover from an interrupted prior run before attempting the add.
        let _ = backend.remove_static_neighbor(neighbor);

        let added = backend
            .add_static_neighbor(neighbor)
            .expect("add_static_neighbor failed - are you running with CAP_NET_ADMIN?");
        assert_eq!(added.interface_index, interface_index);
        assert_eq!(added.address, address);
        assert_eq!(added.mac, Some(mac));
        assert_eq!(added.state, NeighborState::Permanent);

        let present = backend
            .neighbors()
            .expect("neighbors() failed after add_static_neighbor")
            .into_iter()
            .any(|entry| entry.interface_index == interface_index && entry.address == address);

        backend
            .remove_static_neighbor(neighbor)
            .expect("remove_static_neighbor failed after successful add_static_neighbor");
        let absent = !backend
            .neighbors()
            .expect("neighbors() failed after remove_static_neighbor")
            .into_iter()
            .any(|entry| entry.interface_index == interface_index && entry.address == address);

        assert!(
            present,
            "added static neighbor was not present in neighbors() afterward"
        );
        assert!(
            absent,
            "removed static neighbor was still present in neighbors() afterward"
        );
        assert!(matches!(
            backend.remove_static_neighbor(neighbor),
            Err(Error::NotFound)
        ));
    }

    /// Exercises the complete static-neighbor mutation path against the real
    /// kernel for an IPv6 NDP entry, mirroring
    /// `add_then_remove_static_neighbor_round_trips_through_the_kernel`.
    /// Uses `2001:db8:5::1` (RFC 3849 documentation prefix), a subnet
    /// distinct from every other IPv6 subnet used by the other ignored
    /// tests in this module. Runs on `DummyLinkFixture` for the same
    /// isolated-topology reason as the IPv4 test, even though `lo` happens
    /// not to force NDP entries to a non-permanent state the way it does
    /// for ARP.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux add_then_remove_ipv6_static_neighbor_round_trips_through_the_kernel -- --ignored`"]
    fn add_then_remove_ipv6_static_neighbor_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let link = DummyLinkFixture::new(&backend, "nl-test-ndp0");
        let interface_index = link.index();
        let interface_id = Id::new(interface_index as u64);
        let address = IpAddress::from(net_lattice_ip::Ipv6Address::new([
            0x2001, 0xdb8, 5, 0, 0, 0, 0, 1,
        ]));
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x05, 0x01]);
        let neighbor = StaticNeighbor::new(interface_id, address, mac);

        // Recover from an interrupted prior run before attempting the add.
        let _ = backend.remove_static_neighbor(neighbor);

        let added = backend
            .add_static_neighbor(neighbor)
            .expect("add_static_neighbor failed - are you running with CAP_NET_ADMIN?");
        assert_eq!(added.interface_index, interface_index);
        assert_eq!(added.address, address);
        assert_eq!(added.mac, Some(mac));
        assert_eq!(added.state, NeighborState::Permanent);

        let present = backend
            .neighbors()
            .expect("neighbors() failed after add_static_neighbor")
            .into_iter()
            .any(|entry| entry.interface_index == interface_index && entry.address == address);

        backend
            .remove_static_neighbor(neighbor)
            .expect("remove_static_neighbor failed after successful add_static_neighbor");
        let absent = !backend
            .neighbors()
            .expect("neighbors() failed after remove_static_neighbor")
            .into_iter()
            .any(|entry| entry.interface_index == interface_index && entry.address == address);

        assert!(
            present,
            "added IPv6 static neighbor was not present in neighbors() afterward"
        );
        assert!(
            absent,
            "removed IPv6 static neighbor was still present in neighbors() afterward"
        );
        assert!(matches!(
            backend.remove_static_neighbor(neighbor),
            Err(Error::NotFound)
        ));
    }

    /// Exercises the interface-configuration path without inventing a test
    /// interface or changing its steady state: it separately submits the
    /// current administrative state, MTU, and combined patch, observes each
    /// read-after-write result, and has a full combined drop guard restore
    /// the original patch on every exit path.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux interface_configuration_round_trips_through_the_kernel -- --ignored`"]
    fn interface_configuration_round_trips_through_the_kernel() {
        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        let before = backend
            .interfaces()
            .expect("interfaces() failed before configuration")
            .into_iter()
            .find(|interface| {
                interface.kind != InterfaceKind::Loopback
                    && matches!(interface.admin_state, AdminState::Up | AdminState::Down)
                    && interface.mtu.is_some_and(|mtu| mtu != 0)
            })
            .or_else(|| {
                backend
                    .interfaces()
                    .expect("interfaces() failed while selecting fallback")
                    .into_iter()
                    .find(|interface| {
                        matches!(interface.admin_state, AdminState::Up | AdminState::Down)
                            && interface.mtu.is_some_and(|mtu| mtu != 0)
                    })
            })
            .expect(
                "this test environment has no interface with known admin state and a nonzero MTU",
            );
        let admin_state = match before.admin_state {
            AdminState::Up => DesiredAdminState::Up,
            AdminState::Down => DesiredAdminState::Down,
            _ => unreachable!("selection requires a known administrative state"),
        };
        let mtu = before.mtu.expect("selection requires a nonzero MTU");
        let combined = restore_config(&before);
        let admin_only = InterfaceConfig::new(before.id, Some(admin_state), None)
            .expect("observed administrative state forms a valid patch");
        let mtu_only = InterfaceConfig::new(before.id, None, Some(mtu))
            .expect("observed MTU forms a valid patch");

        {
            let _restore = InterfaceRestore {
                backend: &backend,
                config: combined.clone(),
            };
            for (shape, config) in [
                ("admin-only", admin_only),
                ("MTU-only", mtu_only),
                ("combined", combined),
            ] {
                let observed = backend.set_interface_config(config).unwrap_or_else(|error| {
                    panic!("{shape} set_interface_config failed - are you running with CAP_NET_ADMIN?: {error:?}")
                });
                assert_eq!(observed.id, before.id, "{shape} readback changed target");
                assert_eq!(observed.mtu, before.mtu, "{shape} readback changed MTU");
                assert_eq!(
                    observed.admin_state, before.admin_state,
                    "{shape} readback changed administrative state"
                );
            }
        }

        let restored = backend
            .interfaces()
            .expect("interfaces() failed after restoration")
            .into_iter()
            .find(|interface| interface.id == before.id)
            .expect("configured interface disappeared during the test");
        assert_eq!(restored.mtu, before.mtu);
        assert_eq!(restored.admin_state, before.admin_state);
    }

    /// End-to-end monitoring verification: a route mutation must travel from
    /// the kernel's Netlink multicast group through `watch()` to the caller.
    /// It is ignored by default because creating the route requires
    /// `CAP_NET_ADMIN`.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux watch_observes_route_changes -- --ignored`"]
    fn watch_observes_route_changes() {
        use std::time::Duration;

        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        assert!(backend.capabilities().contains(Capability::MONITORING));
        let watcher = backend
            .watch()
            .expect("failed to subscribe to Netlink events");
        #[cfg(feature = "async")]
        let mut async_watcher = backend
            .watch_tokio(EventFilter::none().routes())
            .expect("failed to subscribe to async Netlink events");
        let interface_index = loopback_interface_index(&backend);
        let destination = Network::from(Ipv4Network::new(
            Ipv4Address::new(198, 51, 100, 0),
            Ipv4PrefixLength::new(24).unwrap(),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface_index);

        // Recover from an interrupted prior run before attempting the add.
        // The test route is deliberately isolated to TEST-NET-2.
        let _ = backend.remove_route(route);
        backend
            .add_route(route)
            .expect("failed to add monitoring test route");
        // Obtain the identity from the notification itself. A concurrent
        // RTM_GETROUTE dump can be rejected with EBUSY while the multicast
        // sockets are active, whereas the notification is the authoritative
        // identity source for this monitoring test.
        let watched_id = (0..12)
            .find_map(|_| match watcher.recv_timeout(Duration::from_millis(250)) {
                Ok(Some(Event::Route { id, .. })) => Some(id),
                _ => None,
            })
            .expect("watch() did not report the route addition");
        let observed = true;
        #[cfg(feature = "async")]
        let async_observed = tokio_route_event(&mut async_watcher, watched_id);
        let selected_watcher = backend
            .watch_filtered(EventFilter::none().route(watched_id))
            .expect("failed to subscribe to selected Netlink route events");
        #[cfg(feature = "async")]
        let mut selected_async_watcher = backend
            .watch_tokio(EventFilter::none().route(watched_id))
            .expect("failed to subscribe to selected async Netlink route events");
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

    /// IPv6 counterpart of `watch_observes_route_changes`: same end-to-end
    /// monitoring verification (plain `watcher.recv_timeout` and, with the
    /// `async` feature, `watch_tokio`/`tokio_route_event`), but for an IPv6
    /// route on RFC 3849 `2001:db8:8::/64` — distinct from every other IPv6
    /// subnet already reserved by the other ignored tests in this module
    /// (`2001:db8:1::/64`, `2001:db8:2::9/64`, `2001:db8::/32` plain) so
    /// concurrent kernel state never overlaps.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux watch_observes_ipv6_route_changes -- --ignored`"]
    fn watch_observes_ipv6_route_changes() {
        use std::time::Duration;

        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        assert!(backend.capabilities().contains(Capability::MONITORING));
        let watcher = backend
            .watch()
            .expect("failed to subscribe to Netlink events");
        #[cfg(feature = "async")]
        let mut async_watcher = backend
            .watch_tokio(EventFilter::none().routes())
            .expect("failed to subscribe to async Netlink events");
        let interface_index = loopback_interface_index(&backend);
        let destination = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 8, 0, 0, 0, 0, 0]),
            net_lattice_ip::Ipv6PrefixLength::new(64).unwrap(),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface_index);

        // Recover from an interrupted prior run before attempting the add.
        // The test route is deliberately isolated to 2001:db8:8::/64.
        let _ = backend.remove_route(route);
        backend
            .add_route(route)
            .expect("failed to add monitoring test route");
        // Obtain the identity from the notification itself. A concurrent
        // RTM_GETROUTE dump can be rejected with EBUSY while the multicast
        // sockets are active, whereas the notification is the authoritative
        // identity source for this monitoring test.
        let watched_id = (0..12)
            .find_map(|_| match watcher.recv_timeout(Duration::from_millis(250)) {
                Ok(Some(Event::Route { id, .. })) => Some(id),
                _ => None,
            })
            .expect("watch() did not report the route addition");
        let observed = true;
        #[cfg(feature = "async")]
        let async_observed = tokio_route_event(&mut async_watcher, watched_id);
        let selected_watcher = backend
            .watch_filtered(EventFilter::none().route(watched_id))
            .expect("failed to subscribe to selected Netlink route events");
        #[cfg(feature = "async")]
        let mut selected_async_watcher = backend
            .watch_tokio(EventFilter::none().route(watched_id))
            .expect("failed to subscribe to selected async Netlink route events");
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

    /// Address-domain counterpart of `watch_observes_ipv6_route_changes`:
    /// same end-to-end monitoring verification (plain `watcher.recv_timeout`
    /// and, with the `async` feature, `watch_tokio`/`tokio_address_event`),
    /// but for `Event::Address` driven by `add_address`/`remove_address` on
    /// an IPv6 address on RFC 3849 `2001:db8:a::9/64` — distinct from every
    /// other IPv6 subnet already reserved by the other ignored tests in this
    /// module (`2001:db8:1::/64`, `2001:db8:2::9/64`, `2001:db8::/32` plain,
    /// `2001:db8:8::/64`). No IPv4 address-watch backend test exists yet
    /// (only the IPv4/IPv6 round-trip tests without an event assertion), so
    /// this test is the first of its kind at this level.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux watch_observes_ipv6_address_changes -- --ignored`"]
    fn watch_observes_ipv6_address_changes() {
        use std::time::Duration;

        let _guard = kernel_test_guard();
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");
        assert!(backend.capabilities().contains(Capability::MONITORING));
        let watcher = backend
            .watch()
            .expect("failed to subscribe to Netlink events");
        #[cfg(feature = "async")]
        let mut async_watcher = backend
            .watch_tokio(EventFilter::none().addresses())
            .expect("failed to subscribe to async Netlink events");
        let interface_index = loopback_interface_index(&backend);
        let network = Network::from(net_lattice_ip::Ipv6Network::new(
            net_lattice_ip::Ipv6Address::new([0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 9]),
            net_lattice_ip::Ipv6PrefixLength::new(64).unwrap(),
        ));

        // Recover from an interrupted prior run before attempting the add.
        // The test address is deliberately isolated to 2001:db8:a::9/64.
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
        let requested = NewInterfaceAddress::new(Id::new(interface_index as u64), network);
        backend
            .add_address(requested)
            .expect("failed to add monitoring test address");
        // Obtain the identity from the notification itself, matching the
        // route counterpart's rationale: a concurrent RTM_GETADDR dump can
        // be rejected with EBUSY while the multicast sockets are active.
        let watched_id = (0..12)
            .find_map(|_| match watcher.recv_timeout(Duration::from_millis(250)) {
                Ok(Some(Event::Address { id, .. })) => Some(id),
                _ => None,
            })
            .expect("watch() did not report the address addition");
        let observed = true;
        #[cfg(feature = "async")]
        let async_observed = tokio_address_event(&mut async_watcher, watched_id);
        let selected_watcher = backend
            .watch_filtered(EventFilter::none().address(watched_id))
            .expect("failed to subscribe to selected Netlink address events");
        #[cfg(feature = "async")]
        let mut selected_async_watcher = backend
            .watch_tokio(EventFilter::none().address(watched_id))
            .expect("failed to subscribe to selected async Netlink address events");
        // remove_address matches by id, so the current observed record must
        // be re-read rather than reusing `requested` (which carries no id).
        let observed_address = backend
            .addresses()
            .expect("addresses() failed before remove_address")
            .into_iter()
            .find(|address| address.id == watched_id)
            .expect("added address was not observable before removal");
        let _ = backend.remove_address(observed_address);
        let selected_observed = (0..12).any(|_| {
            matches!(
                selected_watcher.recv_timeout(Duration::from_millis(250)),
                Ok(Some(Event::Address { id, kind: ChangeKind::Removed })) if id == watched_id
            )
        });
        #[cfg(feature = "async")]
        let selected_async_observed = tokio_address_event(&mut selected_async_watcher, watched_id);
        assert!(observed, "watch() did not report the address mutation");
        assert!(
            selected_observed,
            "object address filter did not report removal"
        );
        #[cfg(feature = "async")]
        assert!(
            async_observed,
            "watch_tokio() did not report the address mutation"
        );
        #[cfg(feature = "async")]
        assert!(
            selected_async_observed,
            "async object address filter did not report removal"
        );
    }
}
