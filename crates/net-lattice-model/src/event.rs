use crate::ifaddr::InterfaceAddressId;
use crate::interface::InterfaceId;
use crate::neighbor::NeighborId;
use crate::route::RouteId;

/// What kind of change an [`Event`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChangeKind {
    /// An object matching the filter was added.
    Added,
    /// An object matching the filter was removed.
    Removed,
    /// Reserved for a future field-mask payload (`Changed { fields: ... }`)
    /// — see ARCHITECTURE.md's note on `Event`. Carries no detail yet: a
    /// consumer that needs to know what changed re-reads the object through
    /// the relevant provider.
    Changed,
}

/// A domain whose state must be re-read after an overflow notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventDomain {
    /// The routing table domain.
    Route,
    /// The network interface domain.
    Interface,
    /// The static ARP/NDP neighbor domain.
    Neighbor,
    /// The interface-address domain.
    Address,
    /// Every domain.
    All,
}

/// A composable filter for event domains and individual network objects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventFilter {
    routes: bool,
    interfaces: bool,
    neighbors: bool,
    addresses: bool,
    route_ids: Option<Vec<RouteId>>,
    interface_ids: Option<Vec<InterfaceId>>,
    neighbor_ids: Option<Vec<NeighborId>>,
    address_ids: Option<Vec<InterfaceAddressId>>,
}

impl EventFilter {
    /// A filter that selects every domain and object, with no narrowing.
    pub const ALL: Self = Self {
        routes: true,
        interfaces: true,
        neighbors: true,
        addresses: true,
        route_ids: None,
        interface_ids: None,
        neighbor_ids: None,
        address_ids: None,
    };
    /// A filter that selects nothing until narrowed with a builder method.
    pub const fn none() -> Self {
        Self {
            routes: false,
            interfaces: false,
            neighbors: false,
            addresses: false,
            route_ids: None,
            interface_ids: None,
            neighbor_ids: None,
            address_ids: None,
        }
    }
    /// Selects the route domain, delivering every route event.
    pub const fn routes(mut self) -> Self {
        self.routes = true;
        self
    }
    /// Selects the interface domain, delivering every interface event.
    pub const fn interfaces(mut self) -> Self {
        self.interfaces = true;
        self
    }
    /// Selects the neighbor domain, delivering every neighbor event.
    pub const fn neighbors(mut self) -> Self {
        self.neighbors = true;
        self
    }
    /// Selects the address domain, delivering every interface-address event.
    pub const fn addresses(mut self) -> Self {
        self.addresses = true;
        self
    }

    /// Narrows route delivery to `id`. Repeated object selectors compose as
    /// a union within their domain.
    pub fn route(mut self, id: RouteId) -> Self {
        self.routes = true;
        add_selector(&mut self.route_ids, id);
        self
    }
    /// Narrows interface delivery to `id`.
    pub fn interface(mut self, id: InterfaceId) -> Self {
        self.interfaces = true;
        add_selector(&mut self.interface_ids, id);
        self
    }
    /// Narrows neighbor delivery to `id`.
    pub fn neighbor(mut self, id: NeighborId) -> Self {
        self.neighbors = true;
        add_selector(&mut self.neighbor_ids, id);
        self
    }
    /// Narrows interface-address delivery to `id`.
    pub fn address(mut self, id: InterfaceAddressId) -> Self {
        self.addresses = true;
        add_selector(&mut self.address_ids, id);
        self
    }

    /// Whether this filter selects at least one event domain.
    pub const fn is_empty(&self) -> bool {
        !self.routes && !self.interfaces && !self.neighbors && !self.addresses
    }

    /// Whether this filter selects `domain`, regardless of any object
    /// selector within that domain.
    ///
    /// A watcher uses this to reject a requested domain when the connected
    /// backend has no native delivery path for it. [`EventDomain::All`]
    /// selects every domain only when all four domain selectors are present.
    pub const fn selects_domain(&self, domain: EventDomain) -> bool {
        match domain {
            EventDomain::Route => self.routes,
            EventDomain::Interface => self.interfaces,
            EventDomain::Neighbor => self.neighbors,
            EventDomain::Address => self.addresses,
            EventDomain::All => self.routes && self.interfaces && self.neighbors && self.addresses,
        }
    }

    /// Returns a copy of this filter with `domain` cleared, discarding any
    /// object-id narrowers scoped to that domain. Other domains are
    /// unaffected. Used to strip a domain from an already-built filter before
    /// forwarding it to a native watch call when that domain is instead being
    /// covered through an addition-tier delivery path (see
    /// `Lattice::watch_with_additions`). [`EventDomain::All`] clears every
    /// domain.
    pub fn without_domain(mut self, domain: EventDomain) -> Self {
        match domain {
            EventDomain::Route => {
                self.routes = false;
                self.route_ids = None;
            }
            EventDomain::Interface => {
                self.interfaces = false;
                self.interface_ids = None;
            }
            EventDomain::Neighbor => {
                self.neighbors = false;
                self.neighbor_ids = None;
            }
            EventDomain::Address => {
                self.addresses = false;
                self.address_ids = None;
            }
            EventDomain::All => {
                self = Self::none();
            }
        }
        self
    }

    /// Whether this filter delivers `event`. Object selectors are applied
    /// before a backend enqueues an ordinary event. A resynchronization event
    /// has no object ID, so it is selected by its affected domain.
    pub fn matches(&self, event: Event) -> bool {
        match event {
            Event::Route { id, .. } => self.routes && selected(&self.route_ids, id),
            Event::Interface { id, .. } => self.interfaces && selected(&self.interface_ids, id),
            Event::Neighbor { id, .. } => self.neighbors && selected(&self.neighbor_ids, id),
            Event::Address { id, .. } => self.addresses && selected(&self.address_ids, id),
            Event::ResyncRequired { domain } => match domain {
                EventDomain::Route => self.routes,
                EventDomain::Interface => self.interfaces,
                EventDomain::Neighbor => self.neighbors,
                EventDomain::Address => self.addresses,
                EventDomain::All => {
                    self.routes || self.interfaces || self.neighbors || self.addresses
                }
            },
        }
    }
}

fn add_selector<T: PartialEq>(selectors: &mut Option<Vec<T>>, value: T) {
    let selectors = selectors.get_or_insert_with(Vec::new);
    if !selectors.contains(&value) {
        selectors.push(value);
    }
}

fn selected<T: PartialEq>(selectors: &Option<Vec<T>>, value: T) -> bool {
    selectors
        .as_ref()
        .is_none_or(|selectors| selectors.contains(&value))
}
impl Default for EventFilter {
    fn default() -> Self {
        Self::ALL
    }
}

/// A signal that something changed in the system's networking state —
/// carrying an ID and a [`ChangeKind`], not a clone of the full domain
/// object.
///
/// Deliberately signal-shaped rather than snapshot-shaped (e.g.
/// `Event::Route { id, kind }`, not `Event::RouteAdded(Route)`): native
/// change notifications frequently don't hand over the full object in the
/// first place (an `RTM_NEWROUTE` message or a Windows route-change
/// callback can carry only what changed, not a complete record), and a
/// consumer that only cares *that* something changed before deciding
/// whether to re-query it shouldn't pay for a clone of the full object on
/// every event. A consumer that needs the current value re-reads it
/// through the relevant provider (`Lattice::routes()`, keyed by the ID
/// carried here).
///
/// `#[non_exhaustive]`: DNS resolver configuration changes are a stated
/// long-term goal for this enum (see ARCHITECTURE.md) but are not emitted
/// by any backend as of Stage 0.13. Consequently, DNS mutation has no
/// corresponding watcher-delivery guarantee. No supported
/// platform exposes a single native push signal for all resolver-manager and
/// per-adapter changes without filesystem polling, which is not a genuine
/// push signal. Adding a `Dns` variant later is not a breaking change for
/// consumers who already `match` non-exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Event {
    /// A route was added, removed, or changed.
    Route {
        /// The affected route's identity.
        id: RouteId,
        /// What kind of change occurred.
        kind: ChangeKind,
    },
    /// An interface was added, removed, or changed.
    Interface {
        /// The affected interface's identity.
        id: InterfaceId,
        /// What kind of change occurred.
        kind: ChangeKind,
    },
    /// A static neighbor entry was added, removed, or changed.
    Neighbor {
        /// The affected neighbor entry's identity.
        id: NeighborId,
        /// What kind of change occurred.
        kind: ChangeKind,
    },
    /// An interface address was added, removed, or changed.
    Address {
        /// The affected interface address's identity.
        id: InterfaceAddressId,
        /// What kind of change occurred.
        kind: ChangeKind,
    },
    /// Notifications were dropped because the bounded queue filled; re-read
    /// the indicated domain before relying on later signals.
    ResyncRequired {
        /// The domain whose state must be re-read.
        domain: EventDomain,
    },
}
impl Event {
    /// Returns a [`ResyncRequired`](Event::ResyncRequired) event covering
    /// every domain.
    pub const fn resync_all() -> Self {
        Self::ResyncRequired {
            domain: EventDomain::All,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_carry_id_and_kind() {
        let event = Event::Route {
            id: RouteId::new(1),
            kind: ChangeKind::Added,
        };
        assert_eq!(
            event,
            Event::Route {
                id: RouteId::new(1),
                kind: ChangeKind::Added,
            }
        );
        assert_ne!(
            event,
            Event::Route {
                id: RouteId::new(1),
                kind: ChangeKind::Removed,
            }
        );
    }

    #[test]
    fn object_selectors_compose_without_leaking_other_objects() {
        let filter = EventFilter::none()
            .route(RouteId::new(1))
            .route(RouteId::new(2));
        assert!(filter.matches(Event::Route {
            id: RouteId::new(1),
            kind: ChangeKind::Changed,
        }));
        assert!(filter.matches(Event::Route {
            id: RouteId::new(2),
            kind: ChangeKind::Changed,
        }));
        assert!(!filter.matches(Event::Route {
            id: RouteId::new(3),
            kind: ChangeKind::Changed,
        }));
    }

    #[test]
    fn resync_is_selected_by_domain_even_for_object_filter() {
        let filter = EventFilter::none().route(RouteId::new(1));
        assert!(filter.matches(Event::ResyncRequired {
            domain: EventDomain::Route,
        }));
        assert!(!filter.matches(Event::ResyncRequired {
            domain: EventDomain::Address,
        }));
    }

    #[test]
    fn domain_builders_default_and_empty_state_cover_every_domain() {
        let empty = EventFilter::none();
        assert!(empty.is_empty());
        assert!(!empty.matches(Event::Route {
            id: RouteId::new(1),
            kind: ChangeKind::Added,
        }));

        let domains = EventFilter::none()
            .routes()
            .interfaces()
            .neighbors()
            .addresses();
        assert!(!domains.is_empty());
        assert!(domains.matches(Event::Route {
            id: RouteId::new(1),
            kind: ChangeKind::Added,
        }));
        assert!(domains.matches(Event::Interface {
            id: InterfaceId::new(1),
            kind: ChangeKind::Removed,
        }));
        assert!(domains.matches(Event::Neighbor {
            id: NeighborId::new(1),
            kind: ChangeKind::Changed,
        }));
        assert!(domains.matches(Event::Address {
            id: InterfaceAddressId::new(1),
            kind: ChangeKind::Added,
        }));
        assert_eq!(EventFilter::default(), EventFilter::ALL);
    }

    #[test]
    fn object_selectors_cover_every_domain_and_deduplicate() {
        let filter = EventFilter::none()
            .route(RouteId::new(1))
            .route(RouteId::new(1))
            .interface(InterfaceId::new(2))
            .neighbor(NeighborId::new(3))
            .address(InterfaceAddressId::new(4));

        assert!(filter.matches(Event::Route {
            id: RouteId::new(1),
            kind: ChangeKind::Added,
        }));
        assert!(!filter.matches(Event::Route {
            id: RouteId::new(2),
            kind: ChangeKind::Added,
        }));
        assert!(filter.matches(Event::Interface {
            id: InterfaceId::new(2),
            kind: ChangeKind::Added,
        }));
        assert!(!filter.matches(Event::Interface {
            id: InterfaceId::new(3),
            kind: ChangeKind::Added,
        }));
        assert!(filter.matches(Event::Neighbor {
            id: NeighborId::new(3),
            kind: ChangeKind::Added,
        }));
        assert!(!filter.matches(Event::Neighbor {
            id: NeighborId::new(4),
            kind: ChangeKind::Added,
        }));
        assert!(filter.matches(Event::Address {
            id: InterfaceAddressId::new(4),
            kind: ChangeKind::Added,
        }));
        assert!(!filter.matches(Event::Address {
            id: InterfaceAddressId::new(5),
            kind: ChangeKind::Added,
        }));
    }

    #[test]
    fn resync_all_is_selected_only_when_a_domain_is_selected() {
        assert_eq!(
            Event::resync_all(),
            Event::ResyncRequired {
                domain: EventDomain::All
            }
        );
        assert!(!EventFilter::none().matches(Event::resync_all()));
        assert!(EventFilter::none().routes().matches(Event::resync_all()));
    }

    #[test]
    fn resync_domain_matching_covers_interface_and_neighbor() {
        assert!(
            EventFilter::none()
                .interfaces()
                .matches(Event::ResyncRequired {
                    domain: EventDomain::Interface,
                })
        );
        assert!(
            EventFilter::none()
                .neighbors()
                .matches(Event::ResyncRequired {
                    domain: EventDomain::Neighbor,
                })
        );
    }

    #[test]
    fn domain_selection_distinguishes_partial_and_all_filters() {
        let route = EventFilter::none().route(RouteId::new(1));
        assert!(route.selects_domain(EventDomain::Route));
        assert!(!route.selects_domain(EventDomain::Neighbor));
        assert!(!route.selects_domain(EventDomain::All));
        assert!(EventFilter::ALL.selects_domain(EventDomain::All));
    }

    #[test]
    fn without_domain_clears_only_the_targeted_domain_and_its_narrowers() {
        let filter = EventFilter::ALL
            .neighbor(NeighborId::new(1))
            .route(RouteId::new(2));
        let stripped = filter.without_domain(EventDomain::Neighbor);
        assert!(!stripped.selects_domain(EventDomain::Neighbor));
        assert!(!stripped.matches(Event::Neighbor {
            id: NeighborId::new(1),
            kind: ChangeKind::Added,
        }));
        assert!(stripped.selects_domain(EventDomain::Route));
        assert!(stripped.selects_domain(EventDomain::Interface));
        assert!(stripped.selects_domain(EventDomain::Address));
        assert!(stripped.matches(Event::Route {
            id: RouteId::new(2),
            kind: ChangeKind::Added,
        }));
    }

    #[test]
    fn without_domain_all_clears_everything() {
        assert_eq!(
            EventFilter::ALL.without_domain(EventDomain::All),
            EventFilter::none()
        );
    }
}
