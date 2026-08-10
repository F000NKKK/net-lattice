# Architecture

**Languages**

🇺🇸 **English** | 🇷🇺 [Русский](ARCHITECTURE.ru.md)

This document describes the workspace structure for Net Lattice and the
design principles behind it. Later sections of the Incremental Delivery Plan
below describe planned, not-yet-built work; see [CHANGELOG.md](CHANGELOG.md)
and [README.md](README.md) for the dated record of what has shipped.

Net Lattice provides, and privileged Linux/Windows/macOS CI verifies:
`net-lattice-core` and `net-lattice-ip`; `net-lattice-model`'s `route`,
`interface`, `dns`, `neighbor`, `ifaddr`, and `mutation` modules;
`net-lattice-platform`'s `RouteProvider`/`RouteMutator`, `InterfaceProvider`,
`InterfaceMutator`, `DnsProvider`, `DnsMutator`, `NeighborProvider`,
`NeighborMutator`, `AddressProvider`, `AddressMutator`, `CapabilityProvider`,
synchronous `EventProvider`, feature-gated `TokioEventProvider`, and
object/domain `EventFilter` selectors; route/interface-address/DNS/neighbor
inspection and native mutation; inspectable mutation plans; the ordered
transaction executor with runtime preflight, cancellation boundaries, typed
snapshots, explicit compensation, and phase-aware reports; and whole-system
`CurrentState` snapshots through `net-lattice-platform::SnapshotProvider`.
`InterfaceConfig` and `DesiredAdminState` describe interface intent
separately from observed `Interface`; `InterfaceMutator` applies
capability-gated administrative-state and MTU patches with read-after-write
observation on all built-in backends. Native event monitoring is implemented
in `net-lattice-backend-linux`, `net-lattice-backend-windows`, and
`net-lattice-backend-darwin`, the `net-lattice-async` event stream crate, and
the feature-gated async facade. Monitoring capabilities are domain-specific:
the aggregate `MONITORING` bit means a native delivery path exists for every
currently modeled domain, while filtered watches require their selected
route/interface/neighbor/address bit. Windows has no native neighbor-change
callback and therefore rejects neighbor and all-domain subscriptions. See the
Incremental Delivery Plan table below for the full stage list and
[CHANGELOG.md](CHANGELOG.md)/[README.md](README.md) for per-release detail.

## Guiding Principle

Net Lattice separates two concerns that are easy to tangle together in
cross-platform networking code:

1. **Model** — strongly typed representations of networking concepts (IP
   addresses, routes, interfaces, DNS configuration, ...) that carry no
   operating-system dependency whatsoever.
2. **Backend** — platform-specific code that reads and writes real operating
   system state (Linux Netlink, Windows IP Helper API, macOS BSD route
   sockets) by producing and consuming the model's types.

Dependencies only ever point from backend toward model, never the reverse.
The model must never know that Linux, Windows, or macOS exist.

## Crate Boundary vs. Module Boundary

A concept gets its **own crate** only when there is a concrete reason to pull
it in isolation: independent reuse potential outside Lattice, a distinct
release cadence, or a real case for standalone publication to crates.io.
Everything else is a **module** inside a shared crate.

Applying this test:

- **IP addresses and networks** (`IPv4Address`, `IPv6Address`, `Network`,
  `Prefix`) are a real candidate for standalone use — a consumer might want
  typed IP parsing without any of the rest of Net Lattice. This justifies its own
  crate.
- **MAC addresses**, **routes**, **interfaces**, **neighbor entries (ARP/NDP)**,
  and **DNS configuration** have no independent reuse case: they are always
  used together, change together, and are meaningless without the rest of the
  networking model. These live as modules inside one model crate rather than
  as separate crates.

If a module later grows enough internal complexity to justify independent
versioning (for example, if DNS configuration grows a full resolver
implementation), it can be extracted into its own crate at that point. This
is a non-breaking workspace refactor, not an early commitment.

## Workspace Layout

```text
net-lattice-core          Error, Result, ID types
net-lattice-ip            IPv4/IPv6 addresses, networks, prefixes
net-lattice-model         mac, route, interface, neighbor, dns, event, mutation
    depends on: net-lattice-core, net-lattice-ip
net-lattice-platform      Generic provider traits, Capability
    depends on: net-lattice-core; never net-lattice-model
net-lattice-async         Runtime-independent event stream adapter
    depends on: net-lattice-core, net-lattice-platform
net-lattice-backend-*     Native Linux, Windows, and macOS implementations
    depend on: core, ip, model, platform
net-lattice               Public facade and default backend selection
    depends on: core, ip, model, platform, target backend, optional async
```

`net-lattice-core` and `net-lattice-ip` are independent foundations.
`net-lattice-model` and `net-lattice-platform` are sibling layers, not a
dependency chain. `net-lattice-platform` depends on nothing that describes what a
route or an interface actually is — it only knows that a backend produces
*something*, and defers what that something is to whoever implements or
consumes the trait. `net-lattice-model` in turn has no idea `net-lattice-platform`
exists. Neither can build the other into a `if linux { ... } else if
windows { ... }` situation, because neither has enough information about
the other's domain to do so. See the `net-lattice-platform` section below for
how this is expressed concretely.

### `net-lattice-core`

Foundational types with no networking semantics of their own: `Error`,
`Result<T>`, ID types, and shared traits used across the rest of the
workspace. No OS dependency, no networking-specific types.

**ID types are a single generic type, not one struct per domain object.**
Rather than defining `RouteId`, `InterfaceId`, `NeighborId`, ... as
independent structs, `net-lattice-core` defines one phantom-typed `Id<T>` and
each domain gets a type alias (`type InterfaceId = Id<Interface>;`). This
costs nothing extra to define and makes a whole class of mistake a compile
error instead of a runtime bug: passing a `RouteId` where an `InterfaceId`
is expected fails to compile, rather than silently looking up the wrong
object. The exact shape of `Id<T>` is a Stage 0.1 API detail; what this
document fixes is that IDs are one generic mechanism, not N hand-written
lookalike structs.

`Id<T>` must have a stable, `T`-independent serialized representation
(e.g. it serializes as its underlying value, not as a struct carrying a
phantom marker) from the moment serialization is added. IDs are exactly
the kind of type that ends up embedded in `RouteConfig`/`DesiredState`
persisted to disk or sent over a wire (see State Model below); changing
their wire format after the fact would be a breaking change to every
stored or transmitted config.

This crate is intentionally kept minimal and stays that way by construction:
anything that represents a networking concept (an address, a route, a
resolver setting) belongs in `net-lattice-ip` or `net-lattice-model`, never here.
`net-lattice-core` should never need a new module just because a new domain
(DNS, firewall, VLAN, ...) was added elsewhere in the workspace — if it does,
that is a sign something was misplaced.

### `net-lattice-ip`

IP address and network primitives: `IPv4Address`, `IPv6Address`,
`IPv4Network`, `IPv6Network`, `PrefixLength`. Pure data and arithmetic, no
OS dependency. This crate should be buildable for any target, including
`wasm32`.

### `net-lattice-model`

The domain model of operating system networking state, organized as modules:

- `mac` — `MacAddress`
- `route` — `Route`, gateway, metric
- `interface` — `Interface` and interface kind (depends on `mac`)
- `neighbor` — ARP/NDP entries (depends on `net-lattice-ip` and `mac`)
- `dns` — DNS resolver configuration (depends on `net-lattice-ip`)
- `ifaddr` — IP addresses assigned to interfaces, including observed
  `InterfaceAddress` records and `NewInterfaceAddress` assignment intent
  (depends on `net-lattice-ip`;
  named `ifaddr` rather than `address` to avoid colliding with
  `net-lattice-ip`/`net-lattice-model`'s own `IpAddress`/`Network`
  primitives — this is the distinct concept of an address *bound to an
  interface*, not another address representation)
- `event` — `Event`, the change-notification enum. This lives here, not in
  `net-lattice-platform`, because an event refers to domain data — it has no
  meaning without knowing what a route or an interface is, which is
  exactly the knowledge `net-lattice-platform` is not allowed to have.

  **Events are signals, not snapshots.** An event should carry an ID and a
  kind of change (`Added` / `Removed` / `Changed`), not a clone of the full
  domain object:

  ```rust
  pub enum Event {
      Route { id: RouteId, kind: ChangeKind },
      Interface { id: InterfaceId, kind: ChangeKind },
  }
  ```

  rather than `Event::RouteAdded(Route)`. Two reasons: native change
  notifications frequently don't hand over the full object in the first
  place (an `RTM_NEWROUTE` message or a Windows route-change callback can
  carry only what changed, not a complete record), so an `Event` that
  demands a full `Route` would force backends to reconstruct one that
  wasn't actually delivered; and cloning a full domain object on every
  change is wasted work when most consumers only want to know *that*
  something changed before deciding whether to re-query it. A consumer
  that needs the current value re-reads it through the relevant provider
  (`backend.routes()`, keyed by the ID from the event).

  `ChangeKind::Changed` should eventually carry which fields changed
  (e.g. `Changed { fields: RouteFieldMask }`), not be a bare marker.
  Without it, a consumer that only cares about gateway changes still has
  to re-fetch and diff the whole object on every unrelated metric update,
  which defeats much of the point of a signal-shaped event. The exact
  field-mask representation is a Stage 0.8 (or whenever `EventProvider`
  ships) API detail; what this document fixes is that `Changed` is
  expected to carry this information eventually, so the enum shape isn't
  designed to preclude it.

Modules within `net-lattice-model` may depend on each other and on `net-lattice-ip`,
but the crate as a whole has no OS dependency. `dns` intentionally does not
depend on `interface`; a per-interface DNS association is expressed with
`InterfaceId` from `net-lattice-core` rather than a direct module dependency, to
avoid coupling modules that should be free to evolve independently.

**Model types must be designed for extension, not for the lowest common
denominator.** The same domain concept carries a different set of fields on
each platform — a route on Linux carries a routing table, protocol, scope,
and type in addition to destination/gateway/metric; Windows and BSD expose
a narrower set. Shrinking a model type down to only the fields every
platform happens to share now would make it impossible to add
platform-specific fields later without a breaking change. The concrete
field lists are an API design decision for the Stage 0.1 draft, not this
document, but whatever shape they take must leave room for
platform-specific extension (e.g. an open-ended properties/extension
container) from the outset.

### `net-lattice-platform`

This is the crate that makes the model/backend separation real rather than
aspirational: **`net-lattice-platform` does not depend on `net-lattice-model`.**

Its provider traits describe the *shape* of a contract, not the *content*
of the model — they are generic over the domain type they operate on via
associated types, rather than naming `Route`/`Interface` from
`net-lattice-model` directly:

```rust
trait RouteProvider {
    type Route;

    fn routes(&self) -> Result<Vec<Self::Route>, Error>;
}

trait RouteMutator {
    type RouteConfig;

    fn add_route(&self, route: Self::RouteConfig) -> Result<(), Error>;
    fn remove_route(&self, route: Self::RouteConfig) -> Result<(), Error>;
}

trait InterfaceProvider {
    type Interface;

    fn interfaces(&self) -> Result<Vec<Self::Interface>, Error>;
}

trait InterfaceMutator: InterfaceProvider {
    type InterfaceConfig;

    fn set_interface_config(
        &self,
        config: Self::InterfaceConfig,
    ) -> Result<Self::Interface, Error>;
}
```

`net-lattice-platform` is satisfied by anything shaped like a route; it has no
way to know or care that the concrete type happens to come from
`net-lattice-model`. This is what "platform says *I need something
Route-shaped*; model says *I exist independently of platform*" means in
Rust terms — it is not achievable by wishing the dependency arrow away, it
requires the trait to stop naming the concrete type.

The provider traits, one per capability rather than one large trait, for
the same reason as before — a monolithic trait covering every domain would
force every backend to stub out methods for features it doesn't have:

- `RouteProvider` — list routes.
- `RouteMutator` — add and remove routes (ADR-0002; input type split from
  `RouteProvider::Route` in ADR-0008). Its input, `RouteConfig`, is distinct
  from the observed `Route`: like `StaticNeighbor`, it carries no
  backend-synthesized identity (`Route::id`, never accepted back as
  mutation input on any of the three backends). Identity for facade-level
  matching is `destination + gateway + metric + interface_index`, a
  deliberate superset of every backend's actual native match key. Route
  metric is honored on Linux/Windows only and silently ignored as a no-op
  on Darwin, mirroring the pre-existing observed-side gap.
- `InterfaceProvider` — list observed interfaces.
- `InterfaceMutator` — apply a partial desired interface configuration and
  return the read-after-write observed interface. It is separate from listing
  because it requires elevated native networking privilege.
- `NeighborProvider` — list ARP/NDP entries.
- `NeighborMutator` — add and remove static ARP/NDP neighbor entries. Its
  input, `StaticNeighbor`, is distinct from `NeighborEntry`: it carries
  neither the synthesized `NeighborId` nor the observed `NeighborState`, and
  requires a MAC address because this stage only creates static L2 mappings.
  `net-lattice-backend-linux` implements this trait (`RTM_NEWNEIGH`/
  `RTM_DELNEIGH` via `rtnetlink`, `NUD_PERMANENT`, a non-`Permanent`-entry
  deletion guard); `net-lattice-backend-windows` implements it
  (`CreateIpNetEntry2`/`DeleteIpNetEntry2` over `MIB_IPNET_ROW2`,
  `NlnsPermanent`, the same deletion guard, confirmed on live elevated
  Windows CI); `net-lattice-backend-darwin` implements it (`RTM_ADD`
  encoding a complete `sockaddr_dl` gateway with the real interface's link
  type, and a two-message `RTM_GET`-then-`RTM_DELETE` sequence over
  `PF_ROUTE`, mirroring Apple's own `arp.c`/`ndp.c`, the same deletion
  guard, confirmed on a live elevated macOS CI round trip). All three
  backends advertise `Capability::NEIGHBOR_MUTATION`. The `net-lattice`
  facade forwards `NeighborMutator` on every backend through
  `Lattice::add_static_neighbor`/`remove_static_neighbor` and
  `Mutation::{AddStaticNeighbor, RemoveStaticNeighbor}` executor dispatch
  (ADR-0001).
- `DnsProvider` — read/write DNS resolver configuration.
- `AddressProvider` — list IP addresses assigned to interfaces.
- `AddressMutator` — assign and remove IP addresses. Its input is distinct
  from its observed output: `NewInterfaceAddress` has an interface ID,
  address/prefix, and optional IPv4 broadcast, while `InterfaceAddress` has
  a backend-derived ID and any attributes reported by the OS.
- `EventProvider` — subscribe to change notifications, generic over an
  associated `Event` type for the same reason as the others.

- `Capability` — distinct from provider traits, and deliberately not the
  same axis. Provider traits (`RouteProvider`, ...) describe API surfaces
  that are fixed at compile time: a backend either implements
  `DnsProvider` or it doesn't, and that's known when the backend crate is
  built. `Capability` describes *runtime*-dependent operating system
  features that cannot be expressed through Rust trait implementation alone
  — for example, a Linux backend always implements `RouteProvider`, but
  whether the running kernel has IPv6 or VRF support enabled is a fact
  about the current machine, not the crate. Consumers query
  `backend.capabilities().contains(Capability::VRF)` at runtime rather than
  relying on a method silently failing or panicking when a feature isn't
  actually available. `Capability` is a plain enum with no domain types in
  it, so it costs `net-lattice-platform` nothing to keep here. Because
  consumers routinely need to check for combinations of capabilities
  (`caps.contains(Capability::IPV6 | Capability::VRF)`), it should be
  represented as a bitflags-style value rather than as a `Vec<Capability>`
  or `HashSet<Capability>` — combination and containment checks are then
  cheap bitwise operations instead of collection scans. The exact
  representation (`bitflags!`-generated type vs. a hand-rolled one) is a
  Stage 0.1 detail; what this document fixes is that `Capability` is a
  flag set, not a list.

This crate depends only on `net-lattice-core` (for `Error` and ID types). It
has no OS-specific code and, unlike the previous revision of this
document, no dependency on `net-lattice-model` either.

**Where the generic contract meets the concrete model.** Something has to
bind `Self::Route = net_lattice_model::route::Route` eventually, or the
associated types are never resolved to anything real. That binding
happens in the backend crates, which already depend on both
`net-lattice-platform` (for the traits) and `net-lattice-model` (for the concrete
types) — see below. `net-lattice-platform` itself never performs this binding
and never needs to.

### Platform backends: `net-lattice-backend-linux`, `net-lattice-backend-windows`, `net-lattice-backend-darwin`

Each backend implements the subset of `net-lattice-platform` provider traits it
can support, using native OS facilities:

- `net-lattice-backend-linux` — Netlink (via an existing Netlink crate as a
  dependency, not a Net Lattice-owned wrapper crate).
- `net-lattice-backend-windows` — IP Helper API via Windows bindings.
- `net-lattice-backend-darwin` — macOS BSD route sockets and related system
  APIs.

The `net-lattice-backend-*` naming (rather than bare `net-lattice-linux`, etc.)
makes each crate's role legible from its name alone when scanning the
workspace or `cargo search` results, and leaves room for names like
`net-lattice-backend-linux-networkmanager` alongside
`net-lattice-backend-linux-netlink` if a given OS ever needs more than one
competing backend crate.

`net-lattice` selects a backend crate for the current target by default via
`cfg(target_os = "...")`, but each backend is additionally gated behind a
same-named Cargo feature (`linux`, `windows`, `darwin`). This is not about
runtime backend switching (see the object safety note above — that stays
a compile-time choice) but about being able to depend on `net-lattice-backend-linux`
specifically — for example to run its unit tests, or to cross-check its
behavior — without requiring a full build for every other platform's
backend on a machine that can't target them.

Each backend binds every trait's associated type to the concrete
`net-lattice-model` type it produces:

```rust
impl RouteProvider for LinuxBackend {
    type Route = net_lattice_model::route::Route;

    fn routes(&self) -> Result<Vec<Self::Route>, Error> { /* netlink */ }
}

impl RouteMutator for LinuxBackend {
    type Route = net_lattice_model::route::Route;

    fn add_route(&self, route: Self::Route) -> Result<(), Error> { /* netlink */ }
    fn remove_route(&self, route: Self::Route) -> Result<(), Error> { /* netlink */ }
}
```

Backends are the only place in the workspace where `net-lattice-platform` and
`net-lattice-model` are both in scope at once.

Platform-specific nuances that don't map to a single native API (for
example, DNS on Linux being served by systemd-resolved, NetworkManager, or
plain `resolv.conf` depending on the system) are resolved internally within
the backend crate — via capability detection — rather than by creating
separate crates per underlying mechanism. If a single backend crate ever
grows enough competing provider implementations for one domain to become
unwieldy (e.g. a Netlink-based `RouteProvider` and a NetworkManager-based
`DnsProvider` genuinely warranting independent release cycles), that domain
can be split into its own provider crate at that point — not before.

Backends depend on `net-lattice-platform` and `net-lattice-model`. They export
nothing upward; nothing outside a backend crate depends on it directly
except `net-lattice` itself.

**Nothing stops a backend from binding a provider's associated type to
something other than the matching `net-lattice-model` type** — that is an
unavoidable consequence of `net-lattice-platform` staying generic. A backend
crate is free to write `type Route = LinuxRoute;` for some
backend-specific type instead of `net_lattice_model::route::Route`. This is
not a gap to close by making `net-lattice-platform` depend on `net-lattice-model`
(see the previous section); it is closed one layer up, in `net-lattice`. See
below.

### `net-lattice`

The public-facing facade. Re-exports the types consumers need from
`net-lattice-model` and `net-lattice-ip`, selects a default backend based on
`cfg(target_os = "...")`, and exposes the top-level API (e.g.
`Lattice::connect()`). This is the only crate most consumers depend on
directly.

**This is where model convergence is enforced.** `net-lattice-platform`'s
generic contract means a backend's associated types could, in principle,
diverge from `net-lattice-model` (see the previous section). `net-lattice` closes
that gap not by adding a `net-lattice-platform → net-lattice-model` dependency,
but by constraining the associated types to equal the concrete
`net-lattice-model` types wherever it accepts a backend:

```rust
pub trait LatticeBackend:
    RouteProvider<Route = net_lattice_model::route::Route>
    + RouteMutator<RouteConfig = net_lattice_model::route::RouteConfig>
    + InterfaceProvider<Interface = net_lattice_model::interface::Interface>
{
}

pub struct Lattice<B: LatticeBackend> {
    backend: B,
}
```

A backend whose `Route` associated type is not literally
`net_lattice_model::route::Route` simply fails to satisfy `LatticeBackend` and
cannot be used with the public `Lattice` type — a compile error at the
point the backend is wired in, not a runtime surprise. Collecting the
per-provider bounds into one named `LatticeBackend` trait (rather than
repeating a growing `where` clause on `Lattice` itself) is purely
ergonomic — it does not change where the constraint lives. This gives the
same strength of guarantee as a direct dependency would, without requiring
`net-lattice-platform` itself to know `net-lattice-model` exists: the constraint
lives with the consumer of the contract (the facade that assembles a
concrete system), not with the contract's definition. This is the same
shape used by crates like `sqlx` and `diesel`, where a generic backend
trait is paired with a concrete type binding enforced at the point of use.

**This generic design trades away object safety, deliberately, for now.**
Associated types (`RouteProvider::Route`, ...) make these traits
unimplementable as `Box<dyn RouteProvider>` — Rust cannot build a vtable
for a trait whose method signatures depend on a type that varies per
implementor. Concretely, this means backends must be selected at compile
time (`Lattice<LinuxBackend>`) rather than chosen dynamically at runtime
from a list of loaded implementations. For Net Lattice's actual delivery plan
— a fixed, statically-linked backend per target OS, selected via
`cfg(target_os = "...")` — this costs nothing. It would matter if Lattice
later needed to pick between multiple competing backends for the same
platform at runtime (e.g. Netlink vs. a NetworkManager-based backend on
the same machine); if that need materializes, an object-safe erased layer
(non-generic `dyn`-compatible traits that internally forward to the
generic ones, conventionally called `DynRouteProvider` and friends) can be
added in `net-lattice-platform` without changing the generic traits consumers
already depend on. This is a reserved extension point, not a commitment —
it is not built until a concrete use case needs it.

## Error Model

Lattice must not leak `std::io::Error` or raw OS error codes
(`EPERM`/`ENODEV` on Linux, `ERROR_ACCESS_DENIED` on Windows) as its public
error type. Different backends fail for the same logical reason through
completely different codes, and a consumer writing cross-platform code
needs to match on *why* an operation failed, not on a platform-specific
integer.

`net-lattice-core::Error` is the single error type surfaced across the
workspace, expressed as platform-independent variants such as:

- `PermissionDenied`
- `NotFound`
- `AlreadyExists`
- `Unsupported` — the operation has no meaning on this backend at all (as
  opposed to a `Capability` being absent at runtime; see below).
- `InvalidState`
- `PlatformError` — an escape hatch that preserves the raw backend-specific
  error for diagnostics, without being the primary way consumers are
  expected to match on failures.

The exact variant list is an API design decision for the Stage 0.1 draft;
what this document fixes is that such a taxonomy exists and lives in
`net-lattice-core`, and that provider trait methods return `Result<T, Error>`
using it — never a raw OS error type.

**`PlatformError`'s code cannot be a single untyped integer.** Linux errno
is a signed `i32`, Windows error codes are an unsigned `DWORD` (`u32`), and
collapsing both into one bare `i32`/`u32` field either silently truncates
one of them or gives a false impression that codes are comparable across
platforms when they are not — a Linux `13` and a Windows `13` mean nothing
alike. The code must be tagged by platform, e.g. an enum
(`PlatformErrorCode::Linux(i32)` / `Windows(u32)` / `Darwin(i32)`) or a
boxed `dyn Error`. Either resolves the ambiguity; picking between them is a
Stage 0.1 decision, but leaving the code as one plain integer type is
ruled out here.

## Privilege Model

Networking configuration is privileged on every target platform, and the
privilege boundary does not line up the same way across them:

- **Linux** — reading routes/interfaces is generally unprivileged; adding
  or removing them requires `CAP_NET_ADMIN`.
- **Windows** — reading is available to normal users; modifying typically
  requires Administrator.
- **macOS** — similar read/write asymmetry via BSD route sockets.

This is not a hypothetical concern: it is the concrete scenario behind the
`Error::PermissionDenied` variant above, and it means read operations and
write operations should be expected to fail independently and for
different reasons in consumer code and in tests. This document does not
mandate a specific privilege-check API (e.g. a pre-flight
`backend.can_modify()`) — that is again an API design decision — but the
provider trait split (read-oriented listing vs. write-oriented add/remove
methods, already separate methods on the same trait) must not obscure the
fact that a caller can plausibly have one without the other.

## Async Model

`EventProvider` is inherently push-based on every platform (Netlink
multicast sockets on Linux, `NotifyRouteChange2`-style callbacks on
Windows, BSD routing sockets on macOS). Its Stage 0.8 API is synchronous
and runtime-agnostic: `watch() -> Result<EventReceiver<Event>>`.
`EventReceiver` mirrors `std::sync::mpsc::Receiver`: it offers `recv`,
`try_recv`, and `recv_timeout`, and implements `Iterator`. This keeps the
core usable by synchronous programs and avoids imposing an async runtime.

The synchronous contract remains available without an async dependency. Stage
0.11 adds the optional `net-lattice` `async` feature, which re-exports the
single runtime-agnostic `net-lattice-async::EventStream` and adds
`Lattice::watch_async(filter)`. `EventStream` implements `futures::Stream`,
so applications remain free to choose an executor. This is not a zero-cost
wrapper around `EventReceiver`: `std::sync::mpsc::Receiver` cannot register a
waker. The separate async crate retains an explicit worker-thread bridge for
an arbitrary synchronous receiver, but the facade uses each backend's native
Tokio-aware path: Netlink is polled by Linux's existing Tokio runtime, Windows
IP Helper callbacks write to a bounded Tokio channel, and macOS's PF_ROUTE
reader thread writes directly to that channel. All native async transports use
the same bounded delivery and resynchronization semantics as `EventReceiver`.

## State Model: Imperative Now, Declarative Later

Lattice's initial API surface is imperative: `route.add()`, `route.delete()`,
mirroring what `RouteProvider`/`InterfaceProvider` naturally expose. This is
deliberate — it is the smallest useful surface and it maps directly onto
what native platform APIs provide.

However, declarative configuration is a stated long-term goal (see
README's Long-Term Goals), and it is a different way of using the same
provider traits, not a different backend contract. Retrofitting it later
would touch every provider if the concept isn't at least named now. The
architecture reserves room for it as:

- `SnapshotProvider` — a `net-lattice-platform` provider trait (generic over
  an associated `State` type, like the others) that assembles a
  `CurrentState` by reading the other providers a backend implements. This
  is the concrete mechanism behind `CurrentState` below, rather than each
  backend or the facade having to hand-assemble a snapshot ad hoc.
- `CurrentState` — the snapshot `SnapshotProvider` produces by reading
  providers (routes, interfaces, ...) for a given backend, built from
  `net-lattice-model`'s existing state types (`Route`, `Interface`, ...).
- `DesiredState` — **not the same type as `CurrentState`.** A desired route
  or interface is expressed as a distinct configuration type
  (`RouteConfig`, `InterfaceConfig`, ...) alongside the corresponding state
  type, not a reused `Route`/`Interface`. State objects carry fields that
  are read-only facts about the current system (an interface's live MTU,
  its operational state, traffic counters) which cannot be meaningfully
  "desired" — a consumer expressing intent should not be able to construct
  a `Route` with a nonsensical read-only field set, nor should the
  compiler let them try. Implemented as of Stage 0.19: `DesiredState`
  (`net-lattice-model`) is a whole-system, caller-authored aggregate with
  one `Option`-wrapped field per domain — `None` means that domain is
  unmanaged, `Some` (including an empty collection) means it is managed
  with exactly that desired content — built via `DesiredState::empty()`
  and per-domain `with_*` builder methods, with no backend/provider
  dependency (unlike `CurrentState`, it is never assembled from a
  backend read).
- `Diff` — the computed difference between a `CurrentState` and a
  `DesiredState`, comparing state and config types field-by-field where
  they overlap. Implemented as of Stage 0.19: `Diff` (`net-lattice-model`)
  is a pure, side-effect-free struct with one field per domain, computed by
  `Diff::compute(&CurrentState, &DesiredState) -> Diff`. Route, neighbor,
  and address share a natural-key set-diff shape (`Added`/`Removed`, plus
  `Changed` for neighbor/address); interface uses a distinct per-field
  patch-diff shape (`InterfaceDiff`) mirroring `InterfaceConfig`'s own
  "don't touch" semantics; DNS is a whole-value singleton comparison
  (`DnsChange`). `Diff::compute` performs no I/O and calls no
  provider/backend method — it is inspectable only, with no `ApplyPlan` or
  execution attached.
- `ApplyPlan` — an ordered sequence of provider calls (add/remove/modify)
  that would resolve a `Diff`, which can be inspected before being executed
  and rolled back if a step fails. Implemented as of Stage 0.20:
  `ApplyPlan` (`net-lattice-model`) is a pure, side-effect-free
  `#[non_exhaustive]` struct of `ApplyStep`s, compiled by
  `ApplyPlan::compile(&Diff) -> ApplyPlan` — infallible, no I/O, no
  provider/backend dependency, mirroring `Diff::compute`'s own scope
  discipline. `ApplyStep` (`#[non_exhaustive]`) wraps a `Mutation` directly
  for interface, neighbor, address, and DNS changes and any unpaired route
  `Added`/`Removed` entry (`Single`); a route `Added`/`Removed` pair sharing
  the same destination compiles instead to one `ReplaceRoute { old, new }`
  step, the concrete encoding of the route-replacement-ordering policy
  covering the native-delete-key ambiguity that varies by backend.
  Execution now exists too: `Lattice::<B>::execute_apply_plan(&ApplyPlan,
  &mut ExecutionOptions) -> ApplyPlanReport` submits the underlying native
  operations against the connected backend, reusing `execute_plan`'s own
  cancellation/snapshot/dispatch/compensation primitives for `Single`
  steps and running a dedicated state machine for `ReplaceRoute` steps:
  plan-wide capability-aware rejection before any native call (for a
  route-metric change the connected backend cannot honor, per two new
  additive `RouteMutator` methods, `supports_route_metric`/
  `route_replace_order`), precondition reuse, per-backend leg ordering,
  and mandatory read-after-write verification. `ApplyPlanReport`
  distinguishes `Applied`/`Failed`/`NotAttempted` from two further
  outcomes no `MutationOutcome` variant can express: `Rejected`
  (capability-aware, no native call attempted) and `NonConvergent` (a
  native call was attempted but the resulting state could not be
  confirmed).

`CurrentState` (the data shape, in `net-lattice-model`) and
`SnapshotProvider` (the assembly contract, in `net-lattice-platform`) exist,
and `Lattice<B>::current_state()` produces a `CurrentState` for any connected
backend with zero backend-crate code. The binding between `SnapshotProvider`'s
associated `State` and the concrete `CurrentState` type is realized as an
`impl SnapshotProvider for Lattice<B>` in the facade rather than a blanket
implementation over every raw backend type `B`: Rust's orphan rules forbid a
foreign trait (`SnapshotProvider`, defined in `net-lattice-platform`) being
blanket-implemented for a bare generic type parameter with no local type in
the impl. `Lattice<B>` is the facade's own local type, so implementing the
trait there is both legal and sufficient — no backend still needs to write
any code to get whole-system snapshots.
`DesiredState` and `Diff` (the data shapes, in `net-lattice-model`, see
above) now exist as of Stage 0.19, and `ApplyPlan`/`ApplyStep` (also
`net-lattice-model`, see above) now exist as of Stage 0.20, along with
`Lattice::<B>::execute_apply_plan` (`net-lattice`), which executes an
`ApplyPlan` against a specific connected backend and reports convergence,
non-convergence, and compensation results. A thin facade convenience,
`Lattice::<B>::apply(&self, desired: &DesiredState, options: &mut
ExecutionOptions<'_>) -> Result<ApplyPlanReport>`, chains
`current_state()` → `Diff::compute` → `ApplyPlan::compile` →
`execute_apply_plan` for the common case where a caller has no need to
inspect the compiled plan before executing it; callers that do want to
preflight or inspect a plan first still call `current_state()`/
`Diff::compute`/`ApplyPlan::compile` directly (or the now-public
`Lattice::<B>::validate_apply_plan`) instead of `apply()`. The
state/config split is named here — as a parallel `*Config` type per domain
object living alongside its state type in `net-lattice-model` — so that it
is built in from the first `*Config` type rather than retrofitted after
`CurrentState`/`DesiredState` have already been conflated into one type.

## Mutation and Event Contract Before Transactions

The current imperative API is useful, but it is not an atomic configuration
engine. Stage 0.14 turns the following observed behavior into explicit
operation metadata before a transaction API can make stronger promises.

| Domain | Current mutation contract | Required normalization before declarative apply |
|---|---|---|
| Routes | `RouteMutator` adds and removes through native acknowledgements, gated by `Capability::ROUTE_MUTATION` (ADR-0002); mutation input is the distinct `RouteConfig` intent type (ADR-0008), and deletion matching is still platform-specific. | Define duplicate, absent, and ambiguous-match outcomes on top of the now-distinct route intent and operation precondition/match rule. |
| Interface addresses | `AddressMutator::add_address` returns a re-read `InterfaceAddress`; removal accepts that observed record. IDs are synthesized from interface and network rather than kernel-issued stable identities. | Record identity scope, collision assumptions, and removal preconditions in the operation model. |
| DNS | `DnsMutator` replaces the portable resolver view and re-reads `DnsConfig`. Unix rewrites the active resolver file and drops directives outside the portable model; Windows changes global search settings and each enumerated adapter through separate calls. | Surface scope, manager ownership, persistence, and partial-application results in the operation report. Do not promise atomic DNS replacement or automatic rollback. |
| Interface configuration | `InterfaceConfig` is a partial desired patch; `InterfaceMutator` updates administrative state and/or MTU and returns an observed readback. Combined native writes may partially apply. | Retain explicit compensation and eventual native event delivery; broader declarative interface state belongs to later stages. |
| Neighbors | `NeighborMutator` adds and removes static ARP/NDP entries through `StaticNeighbor` intent, gated by `Capability::NEIGHBOR_MUTATION` (ADR-0001); removal refuses a present but non-`Permanent` entry. | Extend the same intent/mutation pattern to any future neighbor-domain fields; no further normalization required for static entries. |

Every future mutation operation must state: its target identity and matching
rule; preconditions; idempotent result; required privilege; whether the OS
acknowledges completion; whether Net Lattice re-reads observed state; whether
partial application is possible; and whether a compensating operation is safe.
`ApplyPlan` may use this metadata, but must never infer rollback safety from a
successful call alone.

Event delivery is deliberately a separate, eventually consistent signal path:

- A watcher does not provide an initial snapshot, a global order across
  domains, causal correlation with a caller's mutation, or a guarantee that a
  successful mutation produces an event. A snapshot comes from the read
  providers.
- Linux monitors routes, links, neighbors, and interface addresses through
  Netlink. Windows monitors routes, interfaces, and unicast addresses through
  IP Helper; it has no neighbor watcher. macOS monitors routes, interfaces,
  neighbors, and addresses through PF_ROUTE.
- No backend emits DNS events in Stage 0.13. DNS mutation must be followed by
  `dns_config()` when a caller needs the resulting view.
- A backend preserves its enqueue order, not a cross-domain total order. A
  full bounded queue coalesces loss into `Event::ResyncRequired`; consumers
  must re-read the indicated domain before interpreting subsequent ordinary
  events.
- Native sources frequently cannot distinguish create from modification.
  `ChangeKind::Changed` is therefore the conservative result where the OS
  does not provide an unambiguous lifecycle transition.

Stages 0.15–0.20 must build transactions and declarative apply on these
constraints rather than retroactively claiming atomicity or event guarantees
that the native sources do not provide.

## API Stability Rules

Once published, different crates in this workspace are expected to change
at different rates, and consumers need to know which promises hold at
which layer:

- **`net-lattice-core`** — the most stable crate in the workspace. `Error`,
  `Id<T>`, and shared traits are depended on by everything else; a breaking
  change here forces a breaking change everywhere. Changes require the
  strongest justification and the widest review.
- **`net-lattice-ip`** — stable once IPv4/IPv6 types are implemented; the
  domain (IP addressing) is well-understood and slow-moving.
- **`net-lattice-model`** — moderate stability. New modules (`dns`, `neighbor`,
  ...) are expected to be added over time per the delivery plan, but
  existing types should change conservatively once a domain has shipped,
  since both backends and consumers depend on their exact shape.
- **`net-lattice-platform`** — expected to evolve faster than `net-lattice-model`,
  since new provider traits are added as new domains gain backend support.
  Adding a trait is not breaking; changing an existing trait's signature
  is, and affects every backend that implements it.
- **`net-lattice-backend-*` crates** — the least stable. Internal
  implementation details may change freely; only the provider trait
  implementations they expose are a compatibility surface, and that
  surface is owned by `net-lattice-platform`, not the backend crate itself.

This ranking exists so that a change's blast radius can be reasoned about
before it's made, not so that any crate is exempt from normal semver
discipline once Lattice reaches 1.0.

## Frozen 1.0 Public API Surface

This is the consolidated, per-crate checklist of the public items that fall
under the semver discipline in the "API Stability Rules" section above once
Lattice reaches 1.0. It exists so a reviewer can check "is this item on the
frozen list" without re-deriving the workspace's public surface from source
by hand. Nearly every domain-shaped struct and enum below is already
`#[non_exhaustive]` — new fields/variants remain additive after 1.0 — so
this checklist tracks item *existence*, *name*, and *shape*, not just the
attribute.

### `net-lattice-core`

The most stable crate; every item below is depended on by every other crate
in the workspace.

- `Error` (enum; not currently `#[non_exhaustive]` — see note below) and its
  methods `is_permission_denied`, `is_not_found`, `is_already_exists`,
  `is_unsupported`, `is_invalid_state`, `is_disconnected`, `is_platform`.
- `PlatformErrorCode` (enum; not currently `#[non_exhaustive]`), variants
  `Linux(i32)`, `Windows(u32)`, `Darwin(i32)`.
- `Id<T>` (phantom-typed identifier) and its methods `new`, `value`.
- `Result<T>` (crate-level alias for `core::result::Result<T, Error>`).

Note: unlike almost every enum in `net-lattice-model`/`net-lattice-platform`,
`Error` and `PlatformErrorCode` are not yet marked `#[non_exhaustive]`.
Whether to add that attribute before the 1.0 freeze is tracked as its own
decision, not settled by this inventory.

### `net-lattice-model`

- **Interface domain** (`interface`): `Interface`, `InterfaceConfig`,
  `InterfaceId` (`= Id<Interface>`), `InterfaceKind`, `AdminState`,
  `DesiredAdminState`, `OperationalState`.
- **Route domain** (`route`): `Route`, `RouteConfig`, `RouteId`
  (`= Id<Route>`).
- **Neighbor domain** (`neighbor`): `NeighborEntry`, `NeighborId`
  (`= Id<NeighborEntry>`), `NeighborState`, `StaticNeighbor`.
- **Interface-address domain** (`ifaddr`): `InterfaceAddress`,
  `InterfaceAddressId` (`= Id<InterfaceAddress>`), `NewInterfaceAddress`.
- **DNS domain** (`dns`): `DnsConfig`, `NewDnsConfig`.
- **MAC address** (`mac`): `MacAddress`.
- **Address helpers** (`address`): `IpAddress`, `Network`.
- **Snapshot** (`snapshot`): `CurrentState`.
- **Declarative desired state** (`desired_state`): `DesiredState`.
- **Diff** (`diff`): `Diff`, `Change`, `RouteChange`, `InterfaceDiff`,
  `NeighborChange`, `AddressChange`, `DnsChange`.
- **Apply plan** (`apply`): `ApplyPlan`, `ApplyPlanReport`, `ApplyStep`,
  `ApplyStepOutcome`, `NonConvergentReason`.
- **Events** (`event`): `Event`, `EventDomain`, `EventFilter`, `ChangeKind`.
- **Mutation intent/plan/report** (`mutation`): `Mutation`, `MutationKind`,
  `MutationPlan`, `MutationPlanReport`, `MutationOperationReport`,
  `MutationOutcome`, `MutationPreflight`, `MutationPrecondition`,
  `MutationConfirmation`, `MutationSnapshot`, `MutationPrivilege`,
  `MutationReversibility`, `MutationSemantics`, `MutationIdempotency`,
  `MutationExecutionPhase`, `MutationStopReason`, `RollbackStatus`.

All of the above structs/enums are `#[non_exhaustive]` at the type or
variant level except the small alias/marker items (`InterfaceId`/`RouteId`/
`NeighborId`/`InterfaceAddressId`, which are `Id<T>` type aliases with no
attribute of their own — freeze discipline for them is `Id<T>`'s, tracked
under `net-lattice-core` above) and `RouteReplaceOrder`, which is defined in
`net-lattice-platform` (see below) though re-exported through the facade's
`mutation` module.

### `net-lattice-platform`

- **Provider/mutator trait pairs** (read unprivileged / write privileged,
  one pair per domain): `RouteProvider`/`RouteMutator`,
  `InterfaceProvider`/`InterfaceMutator`, `NeighborProvider`/
  `NeighborMutator`, `AddressProvider`/`AddressMutator`,
  `DnsProvider`/`DnsMutator`.
- `RouteMutator::add_route`, `RouteMutator::remove_route` — the two
  `Capability`-gated mutation methods.
- **`RouteMutator::supports_route_metric`** and
  **`RouteMutator::route_replace_order`** — see "Non-`Capability`
  backend-declared facts" below; these two default-provided trait methods
  are just as much frozen public surface as the type list above, but are
  easy to miss because they are not `Capability` flags.
- `RouteReplaceOrder` (`#[non_exhaustive]` enum), variants
  `RemoveBeforeAdd`, `AddBeforeRemove`.
- `Capability` (a `bitflags`-based type) and its flags: `IPV6`, `VRF`,
  `NAMESPACES`, `ROUTE_MONITORING`, `DNS_MUTATION`,
  `INTERFACE_ADMIN_STATE`, `INTERFACE_MTU`, `INTERFACE_MONITORING`,
  `NEIGHBOR_MONITORING`, `ADDRESS_MONITORING`, `NEIGHBOR_MUTATION`,
  `ROUTE_MUTATION`, and the composite `MONITORING` (the bitwise union of
  the four `*_MONITORING` flags).
- `CapabilityProvider` trait and its single method `capabilities`.
- `EventProvider`, `EventReceiver`, `EventSender` (native change-event
  delivery contract).
- `SnapshotProvider` (whole-system state assembly; blanket-implemented,
  not hand-written per backend).
- Feature-gated (`async`): `TokioEventProvider` and its method
  `watch_tokio`, `TokioEventReceiver`, `TokioEventSender`.

#### Non-`Capability` backend-declared facts

`RouteMutator::supports_route_metric() -> bool` (default `true`) and
`RouteMutator::route_replace_order() -> RouteReplaceOrder` (default
`RouteReplaceOrder::RemoveBeforeAdd`) are **not** `Capability` flags. They
are plain trait methods with defaults because they describe a fixed fact
about a backend target (e.g. "this operating system's native route-delete
key cannot disambiguate an in-flight replacement") rather than a
runtime-dependent capability that can differ between two processes
connected to the same kind of backend. A 1.0 freeze must track their
signatures and default values with the same discipline as `Capability`
itself — a reader who only checks `Capability`'s doc comment for "what does
a backend declare about itself" will miss these two methods.

### `net-lattice` (facade)

- **Crate-root re-exports**: `Error`, `Id<T>`, `PlatformErrorCode`, `Result`
  (from `net-lattice-core`); the `net-lattice-ip` address types; `Capability`,
  `CapabilityProvider` (from `net-lattice-platform`); `Lattice<B>`;
  `LatticeBackend`.
- **`model` module** (observed/read-only domain types and read-provider
  traits): `DnsConfig`, `InterfaceAddress`, `InterfaceAddressId`,
  `AdminState`, `Interface`, `InterfaceId`, `InterfaceKind`,
  `OperationalState`, `MacAddress`, `NeighborEntry`, `NeighborId`,
  `NeighborState`, `Route`, `RouteId`, `CurrentState`, `IpAddress`,
  `Network`, `AddressProvider`, `DnsProvider`, `InterfaceProvider`,
  `NeighborProvider`, `RouteProvider`, `SnapshotProvider`.
- **`mutation` module** (mutation intent, plan/execution/report machinery,
  mutator traits, declarative `DesiredState`/`Diff`): `Cancellation`,
  `Compensation`, `ExecutionOptions`, `Snapshot`, `ApplyPlan`,
  `ApplyPlanReport`, `ApplyStep`, `ApplyStepOutcome`, `NonConvergentReason`,
  `DesiredState`, `AddressChange`, `Change`, `Diff`, `DnsChange`,
  `InterfaceDiff`, `NeighborChange`, `RouteChange`, `NewDnsConfig`,
  `NewInterfaceAddress`, `DesiredAdminState`, `InterfaceConfig`, `Mutation`,
  `MutationConfirmation`, `MutationExecutionPhase`, `MutationIdempotency`,
  `MutationKind`, `MutationOperationReport`, `MutationOutcome`,
  `MutationPlan`, `MutationPlanReport`, `MutationPrecondition`,
  `MutationPreflight`, `MutationPrivilege`, `MutationReversibility`,
  `MutationSemantics`, `MutationSnapshot`, `MutationStopReason`,
  `RollbackStatus`, `StaticNeighbor`, `RouteConfig`, `AddressMutator`,
  `DnsMutator`, `InterfaceMutator`, `NeighborMutator`, `RouteMutator`,
  `RouteReplaceOrder`.
- **`monitoring` module** (change events, filters, monitoring provider
  traits): `EventStream` (feature-gated `async`), `ChangeKind`, `Event`,
  `EventDomain`, `EventFilter`, `TokioEventProvider` (feature-gated
  `async`), `EventProvider`, `EventReceiver`.
- **`backend` module** (the one-stop surface for third-party backend
  authors; re-exports items also reachable via `model`/`mutation`/
  `monitoring` above, plus `LatticeBackend` and `CapabilityProvider`):
  `LatticeBackend`, `CurrentState`, `AddressMutator`, `AddressProvider`,
  `CapabilityProvider`, `DnsMutator`, `DnsProvider`, `EventProvider`,
  `EventReceiver`, `EventSender`, `InterfaceMutator`, `InterfaceProvider`,
  `NeighborMutator`, `NeighborProvider`, `RouteMutator`, `RouteProvider`,
  `RouteReplaceOrder`, `SnapshotProvider`, plus feature-gated (`async`)
  `TokioEventProvider`, `TokioEventReceiver`, `TokioEventSender`.
- **`LatticeBackend`** — the compile-time bound a third-party backend must
  satisfy; its exact set of supertraits (`RouteProvider`/`RouteMutator`/
  `InterfaceProvider`/`InterfaceMutator`/`DnsMutator`/`NeighborProvider`/
  `NeighborMutator`/`AddressProvider`/`AddressMutator`/`EventProvider`/
  `CapabilityProvider`, each bound to the concrete `net-lattice-model`
  type) is itself part of the frozen contract: widening or narrowing it is
  a breaking change for every third-party backend implementation.
- **`Lattice<B>` public methods**: `routes`, `add_route`, `remove_route`,
  `interfaces`, `set_interface_config`, `dns_config`, `set_dns_config`,
  `neighbors`, `add_static_neighbor`, `remove_static_neighbor`,
  `addresses`, `add_address`, `remove_address`, `current_state`, `apply`,
  `diff`, `validate_plan`, `snapshot_for_mutation`, `execute_plan`,
  `execute_apply_plan`, `capabilities`, `supports`, `watch`, `watch_async`
  (feature-gated `async`), `watch_filtered`, and the per-platform
  `connect` constructors (one `#[cfg(target_os = "...")]`-gated
  implementation per supported OS, same public signature `fn connect() ->
  Result<Self>` on every platform).

This checklist is the reviewable inventory called for by the public-API
freeze audit; it does not itself change any type's shape or attribute — see
the "Non-`Capability` backend-declared facts" callout above and the `Error`/
`PlatformErrorCode` non-exhaustiveness note under `net-lattice-core` for the
two open follow-up questions it surfaced.

## Explicit Non-Goals of This Architecture

- **No crate is Linux-, Windows-, or macOS-specific except the backend
  crates themselves.** `net-lattice-core`, `net-lattice-ip`, `net-lattice-model`, and
  `net-lattice-platform` must remain free of `cfg(target_os = "...")` and OS
  bindings.
- **`net-lattice-platform` never depends on `net-lattice-model`.** Its provider
  traits must stay generic over associated types rather than growing a
  direct dependency on concrete model types, even when it would be
  momentarily convenient (e.g. adding a new provider method whose most
  obvious signature names `net_lattice_model::route::Route` directly). If a
  provider trait cannot be expressed without naming a concrete model type,
  that is a signal to revisit the trait's shape, not to add the
  dependency.
- **No command-line interface.** Consistent with the project's non-goals in
  [README.md](README.md), no `net-lattice-cli` crate is planned.
- **No premature crate creation.** Crates for future domains (VLAN, VRF,
  firewall, tunnels, declarative configuration, transactional apply/rollback)
  are described in the roadmap below but are not created until there is
  actual code to put in them.

## Incremental Delivery Plan

The full model above is a target, not a starting point. Crates and modules
are introduced only when there is real implementation work for them:

Rows through 0.20 are implemented and available today; rows from 0.21 onward
describe planned, not-yet-built work.

| Stage | Scope |
|-------|-------|
| 0.1 | `net-lattice-core`, `net-lattice-ip`, `net-lattice-model` (`route` module only), `net-lattice-platform` (`RouteProvider`), `net-lattice-backend-linux` (routes via Netlink), `net-lattice` |
| 0.2 | `net-lattice-backend-windows` (`RouteProvider`) |
| 0.3 | `net-lattice-backend-darwin` (`RouteProvider`) |
| 0.4 | `interface` module + `InterfaceProvider` across all backends |
| 0.5 | `dns` module + `DnsProvider` across all backends |
| 0.6 | `neighbor` module + `NeighborProvider` (ARP/NDP) across all backends |
| 0.7 | `ifaddr` module + `AddressProvider` (IP addresses on interfaces) across all backends |
| 0.8 | `event` module + synchronous `EventProvider`/`EventReceiver`; monitoring via Netlink multicast (Linux), PF_ROUTE (macOS), and IP Helper notifications (Windows). |
| 0.9 | `NewInterfaceAddress` + `AddressMutator`; native IPv4/IPv6 address assignment/removal via Netlink (Linux), IP Helper (Windows), and address ioctls (macOS). |
| 0.10 | Event semantics: bounded delivery, overflow/resynchronization, filtering, cancellation, and background-error propagation. |
| 0.11 | Optional `net-lattice` `async` feature; `net-lattice-async` exposes one runtime-agnostic `EventStream`, while Linux (Tokio Netlink), Windows (IP Helper callbacks), and macOS (PF_ROUTE reader) deliver directly into bounded Tokio transports. |
| 0.12 | Watcher API stabilization: composable object/domain filters applied before enqueueing, domain-specific monitoring-capability validation, and consistent synchronous/async filter semantics. `MONITORING` is the all-domain aggregate; a filter requiring an unavailable domain fails before native registration. |
| 0.13 | DNS mutation with an intent/observed-state model: `NewDnsConfig` is applied through supported system mechanisms and the resulting `DnsConfig` is re-read on Linux, Windows, and macOS. |
| 0.14 | Mutation operation model: inspectable `Mutation` values and ordered `MutationPlan`s for route/address/DNS mutations; explicit preconditions, idempotency, privilege, confirmation, partial-application, and reversibility classifications. Includes side-effect-free `MutationPreflight` analysis plus typed `MutationOutcome`, `MutationPlanReport`, and `RollbackStatus` contracts for executor reporting; plans themselves retain no execution or rollback side effects. |
| 0.15 | Transaction execution baseline: runtime capability and object-precondition preflight via `Lattice::validate_plan`, provider-backed `MutationSnapshot` capture through `snapshot_for_mutation`, ordered submission through `Lattice::execute_plan` configured by `ExecutionOptions`, per-operation outcomes, phase/timing diagnostics, first-failure stopping, operation-boundary cancellation, caller-defined prior-state capture, and an explicitly supplied reverse-order compensator. Ignored native facade route round-trip and compensation scenarios run in each privileged CI job; DNS partial-application integration remains intentionally non-destructive. |
| 0.16 | Interface configuration: separate desired `InterfaceConfig`, independent admin-state/MTU capability gates, read-after-write mutation on Linux/Windows/macOS, typed executor snapshots, native interface-change event mappings, and privileged submission/readback/restoration checks. Destructive end-to-end event proof remains isolated-topology follow-up. |
| 0.17 | Neighbor mutation plus IPv6 DNS parity and isolated cross-platform topology acceptance for destructive route/address/neighbor and facade flows. |
| 0.18 | Snapshot foundation: `CurrentState` assembled consistently from the implemented providers, with snapshot scope, consistency, and partial-read semantics made explicit. |
| 0.19 | Declarative model and diff: `DesiredState` configuration types remain distinct from observed types; produce an inspectable `Diff` without applying it. |
| 0.20 | Declarative apply: compile a `Diff` into an `ApplyPlan`, execute it through the transaction engine, and report convergence, non-convergence, and compensation results. |
| 0.21 | Pre-1.0 hardening: freeze the core model, provider extension contracts, identity rules, capability meanings, event guarantees, and platform support matrix; complete cross-platform privileged regression coverage and migration guidance. |
| 0.22+ | Capability domains, each introduced only with its read model, intent model, mutation semantics, events where the OS supports them, capabilities, and all-platform tests: VLAN first, then VRF, namespaces, firewall, and tunnels as their platform contracts mature. These domains are not prerequisites for 1.0. |
| 1.0 | Stable cross-platform foundation for the implemented inspection, monitoring, imperative mutation, transactions, and declarative apply contracts. 1.0 is gated by the 0.21 compatibility audit, not by implementing every future capability domain. |

Each stage is expected to validate the architecture before the next is
started; earlier stages may inform adjustments to later ones.

### Route to 1.0

The stage numbers above are delivery boundaries, not a promise that every
heading ships in one release. A stage may be split when platform behavior or
the public contract needs independent validation. Conversely, a small
hardening release may be issued between stages without changing this plan.

The current facade exposes complete read APIs plus imperative route, address,
and DNS mutation. That is enough to begin transactions, but not enough to
declare a stable configuration platform: interface and static-neighbor
mutation still need their own intent models, and declarative apply must be
defined in terms of explicit operations rather than by reusing observed
objects as desired state.

The 1.0 boundary intentionally does not require VLAN, VRF, namespaces,
firewall, or tunnel support. It requires that every API already advertised as
stable has a documented cross-platform contract, truthful capability and
privilege behavior, bounded event semantics, deterministic transaction
reporting, and privileged regression coverage on each supported platform.
