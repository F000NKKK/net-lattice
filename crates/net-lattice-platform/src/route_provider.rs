use net_lattice_core::Result;

/// Lists routes.
///
/// Generic over an associated `Route` type rather than naming
/// `net_lattice_model::route::Route` directly — `net-lattice-platform` does not
/// depend on `net-lattice-model` (see ARCHITECTURE.md). The facade crate
/// (`lattice`) is what constrains `Route` to the concrete model type.
///
/// Mutation is deliberately separate, in [`crate::RouteMutator`]: listing is
/// normally unprivileged, while adding or removing a route requires
/// `CAP_NET_ADMIN`, an elevated Windows token, or root on BSD/macOS — the
/// same read/write split used by [`crate::AddressProvider`]/
/// [`crate::AddressMutator`], [`crate::InterfaceProvider`]/
/// [`crate::InterfaceMutator`], and [`crate::NeighborProvider`]/
/// [`crate::NeighborMutator`].
pub trait RouteProvider {
    /// The backend's observed route record.
    type Route;

    /// Returns every route currently observed in the routing table.
    fn routes(&self) -> Result<Vec<Self::Route>>;
}

/// Adds and removes routes.
///
/// A route *does* carry a backend-synthesized identity distinct from
/// caller intent: on Windows and Darwin the observed `RouteProvider::Route`
/// carries an `id` synthesized as a hash of its own observed fields, and on
/// Linux it is a kernel-issued netlink handle — on every platform, no
/// native API accepts that id back as mutation input. This mirrors
/// [`crate::NeighborProvider`]/[`crate::NeighborMutator`], which already
/// keep the observed `NeighborEntry` and the intent `StaticNeighbor` as two
/// distinct types precisely because `NeighborEntry::id` is never accepted
/// back either. `RouteMutator` therefore declares its own associated
/// `RouteConfig` type instead of reusing [`crate::RouteProvider`]'s `Route`:
/// the facade binds it to `net_lattice_model::route::RouteConfig`, a
/// distinct intent type with no id field.
pub trait RouteMutator {
    /// Caller-authored route intent, with no backend-synthesized identity.
    type RouteConfig;

    /// Adds a route matching the given intent.
    fn add_route(&self, route: Self::RouteConfig) -> Result<()>;
    /// Removes the route matching the given intent.
    fn remove_route(&self, route: Self::RouteConfig) -> Result<()>;

    /// Whether this backend's native add/remove route calls read or write a
    /// route's metric at all.
    ///
    /// `true` by default. A backend whose native route calls never consult
    /// metric (macOS/BSD's `PF_ROUTE` route socket, for example) overrides
    /// this to `false`. This is a fixed fact about the backend target, not a
    /// runtime-dependent capability: it does not vary between two processes
    /// connected to the same kind of backend, so it is a plain trait method
    /// rather than a `Capability` flag (which models facts that can differ
    /// by connected system/privilege at runtime).
    fn supports_route_metric(&self) -> bool {
        true
    }

    /// The native-call ordering this backend needs for a destination-paired
    /// route replacement (removing one route and adding another at the same
    /// destination as one logical unit).
    ///
    /// [`RouteReplaceOrder::RemoveBeforeAdd`] by default, matching a
    /// narrow native delete key (destination/gateway/metric/interface) that
    /// would otherwise ambiguously match the replacement's own add if both
    /// were present at once. A backend whose delete key cannot disambiguate
    /// the old and new route while both exist simultaneously (macOS/BSD)
    /// overrides this to [`RouteReplaceOrder::AddBeforeRemove`].
    fn route_replace_order(&self) -> RouteReplaceOrder {
        RouteReplaceOrder::RemoveBeforeAdd
    }
}

/// Native-call ordering for a destination-paired route replacement.
///
/// `#[non_exhaustive]`: a future backend may need a third ordering strategy
/// without this being a breaking change for callers who match
/// non-exhaustively, matching this crate's other capability/policy enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteReplaceOrder {
    /// Remove the old route, then add the new one. Safe whenever the
    /// backend's delete key can uniquely identify the old route even while
    /// the new route does not yet exist.
    RemoveBeforeAdd,
    /// Add the new route, then remove the old one. Required when the
    /// backend's delete key cannot disambiguate the old and new route while
    /// both exist simultaneously, so the old route must be removed only
    /// after the new one is already present.
    AddBeforeRemove,
}
