# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.21.2] - 2026-09-20

### Fixed

- `net-lattice-backend-linux`: `.match_name(name.into())` no longer
  type-checked against rtnetlink 0.23's generic `match_name<S:
  Into<String>>` (ambiguous `S`) after the rtnetlink dependency bump.
  `name` is already `&str`, which satisfies the bound directly; removed
  the redundant `.into()`.
- `net-lattice`: an unused-variable warning in
  `Lattice::validate_apply_plan` (`ApplyStep::ReplaceRoute { old, new }`
  never read `old`) broke `-D warnings` on every platform's CI.
- `net-lattice-model::Diff::compute`: fixed a duplicate-natural-key
  deduplication regression across all four affected domains
  (routes/interfaces/neighbors/addresses) introduced while making diff
  output order deterministic. The prior fix compared each candidate
  entry's *value* against the map's stored last-one-wins value to decide
  whether to emit it; when two duplicate entries sharing a key were also
  value-equal (guaranteed for routes, since a route's natural key is its
  whole value), every duplicate matched and was emitted instead of only
  the last one. Fixed by tracking each key's last occurrence *index*
  instead, independent of whether duplicate values happen to be equal.
  Caller order is still preserved for the surviving entries.

## [1.0.0] - Pending

Not yet published. Planned first stable release of `net-lattice`,
`net-lattice-core`, `net-lattice-ip`, `net-lattice-model`,
`net-lattice-platform`, `net-lattice-async`, and the
`net-lattice-backend-{linux,windows,darwin}` platform backends on
crates.io. The public API is frozen per the "Frozen 1.0 Public API
Surface" audit in `ARCHITECTURE.md`; within the `1.x` line, additive
changes will ship as minor releases, compatible fixes as patch releases,
and a breaking change will require an explicit major version bump.

### Added

- Stage 1.0 public-API freeze audit and rustdoc completeness: documented
  every remaining public struct/enum field, associated type, trait method,
  and module across `net-lattice-core`, `net-lattice-ip`,
  `net-lattice-model`, `net-lattice-platform`, and
  `net-lattice-backend-linux`, and added `#![warn(missing_docs)]` to all 9
  workspace crates so full rustdoc coverage is enforced going forward. No
  public API shape changed from `0.21.1`.
- VLAN, VRF, network namespaces, and firewall integration remain explicitly
  out of scope for `1.0.0` (stage 0.22+): namespaces are not symmetric
  across Linux/Windows/macOS and firewall requires a per-platform mechanism
  and abstraction-depth decision, so both need their own architecture pass
  before implementation starts. See `ARCHITECTURE.md`'s Incremental
  Delivery Plan.

## [0.21.1] - 2026-08-11

### Fixed

- `net-lattice::Lattice::<B>::watch_with_additions`: now succeeds when a
  selected event domain is covered by a requested and backend-reported
  `Addition` even without the corresponding native `Capability` — previously
  it always rejected such a call with `Error::Unsupported` before ever
  consulting the requested additions, making the neighbor-polling addition
  unreachable through its own intended entry point. The domain is now also
  correctly withheld from the underlying native watch registration so a
  backend that natively rejects that domain doesn't reject the whole call.
  Addition-sourced events are now also filtered against the caller's full
  requested `EventFilter`, including object-id narrowers, instead of always
  delivering every addition-sourced event regardless of what was requested.
  `watch`/`watch_filtered`/`watch_async` are unaffected by this fix.
- `net-lattice-model::event::EventFilter`: added `without_domain(EventDomain)
  -> Self`, returning a copy of the filter with one domain (and its object-id
  narrowers) cleared; `EventDomain::All` clears every domain.

## [0.21.0] - 2026-08-11

### Added

- `net-lattice-platform::{Addition, AdditionProvider}`: a new, disjoint
  "addition tier" of explicitly opt-in, non-native capabilities (for
  example, polling), reported through a separate `#[non_exhaustive]`
  bitflags-style `Addition` type never merged into `Capability`'s
  cross-backend-uniform meaning. `AdditionProvider: EventProvider` has two
  default-provided methods (`additions` defaults to `Addition::empty()`,
  `watch_addition` defaults to `Err(Error::Unsupported)`), so implementing
  it costs nothing for a backend with no addition to offer.
- `net-lattice::Lattice::<B>::watch_with_additions(&self, filter:
  EventFilter, additions: Addition) -> Result<EventReceiver<Event>>`: like
  `watch_filtered`, but also activates the requested `Addition`s and fans
  their synthesized events into the same merged receiver as the native,
  filter-selected events. An `additions` bit not currently reported by the
  connected backend's `AdditionProvider::additions` is silently not
  activated (no error), matching `Capability`'s own "query, don't assume"
  caller contract. Dropping the returned receiver tears down both the
  native subscription and every addition fan-in thread this call started.
  `LatticeBackend` gained `AdditionProvider` as a required supertrait;
  additive-safe for every existing and third-party backend since both of
  `AdditionProvider`'s methods are default-provided.
- `net-lattice-backend-windows`: a concrete `AdditionProvider` implementation
  reporting `Addition::NEIGHBOR_MONITORING_POLLING` — an opt-in, polling-based
  substitute for the native neighbor-change monitoring this backend still
  lacks. Diffs successive neighbor-table snapshots into synthesized
  `Added`/`Removed`/`Changed` events on the receiver returned by
  `watch_with_additions`, at a weaker latency/ordering/coalescing/
  resource-cost tier than native event delivery (documented on
  `Addition::NEIGHBOR_MONITORING_POLLING` itself).

### Changed

- `net-lattice-core::Error` is now `#[non_exhaustive]`, matching the
  `#[non_exhaustive]` posture already carried by every other domain-shaped
  public enum in the workspace (`InterfaceKind`, `Mutation`, `ApplyStep`,
  `RouteChange`/`NeighborChange`/`AddressChange`, `Event`/`ChangeKind`,
  etc.). Purely additive: no variant added or removed, no `Display`/
  `is_*` behavior changed. External crates that exhaustively `match` on
  `Error` without a wildcard arm must add one to keep compiling. Documented
  the deliberate `Option` (`Ipv4PrefixLength::new`/`Ipv6PrefixLength::new`)
  vs. `Result<Self, Error>` (`InterfaceConfig::new`) validation-failure
  convention distinction in rustdoc, rather than unifying either direction.

## [0.20.0] - 2026-08-06

### Added

- `net-lattice::Lattice::<B>::diff(&self, desired: &DesiredState) ->
  Result<Diff>`: a convenience chaining `current_state()` →
  `Diff::compute`, for callers who only want to inspect what would change
  (a dry-run / diff-preview) without compiling or executing a plan the way
  `apply()` does.
- `net-lattice-core::Error::is_permission_denied`/`is_not_found`/
  `is_already_exists`/`is_unsupported`/`is_invalid_state`/`is_disconnected`/
  `is_platform`: one matching-helper method per existing `Error` variant,
  for callers who prefer `if err.is_not_found() { ... }` over `matches!`.
- `net-lattice-model::ApplyPlan`/`ApplyStep`: a new `#[non_exhaustive]`,
  pure, side-effect-free ordered list of steps compiled from a `Diff`, via
  `ApplyPlan::compile(diff: &Diff) -> ApplyPlan` — infallible, no I/O, no
  provider/backend dependency, mirroring `Diff::compute`'s own scope
  discipline. `ApplyStep` (`#[non_exhaustive]`) wraps a `Mutation` directly
  for interface, neighbor, address, and DNS changes and for any route
  `Added`/`Removed` entry with no matching counterpart at the same
  destination (`ApplyStep::Single`); a route `Added`/`Removed` pair sharing
  one destination compiles instead to one
  `ApplyStep::ReplaceRoute { old: Route, new: RouteConfig }` step, encoding
  the route-replacement-ordering policy for the native-delete-key ambiguity
  that varies by backend. Neighbor/address `Changed` entries compile to a
  remove-then-add pair of `Single` steps, the only order compatible with
  `Mutation::AddStaticNeighbor`/`Mutation::AddAddress`'s existing `Absent`
  precondition. `ApplyStep::semantics() -> MutationSemantics` delegates to
  `Mutation::semantics()` for `Single` and synthesizes a `Replace`-flavored
  contract (mandatory read-after-write confirmation,
  `RequiresPriorState` reversibility, `may_partially_apply: true`, and a
  new, purely additive `MutationKind::ReplaceRoute` variant) for
  `ReplaceRoute`. `ApplyPlan::compile` cannot know or check which backend
  will execute the plan — capability-aware rejection and actual execution
  are a later stage's concern.
- `net-lattice::Lattice::<B>::execute_apply_plan(&self, plan: &ApplyPlan,
  options: &mut ExecutionOptions<'_>) -> ApplyPlanReport`: executes an
  `ApplyPlan` against the connected backend. `ApplyStep::Single` steps run
  through the exact same cancellation/snapshot/dispatch/compensation
  primitives `execute_plan` uses for a `MutationPlan`.
  `ApplyStep::ReplaceRoute` steps run a dedicated state machine: a
  plan-wide capability-aware rejection (before any native call) for a
  requested route-metric change the connected backend cannot honor;
  precondition reuse against the previously observed route; per-backend
  leg ordering (queried from the two new `RouteMutator` methods below);
  and mandatory read-after-write verification of both halves of the
  replacement. The caller's `.compensation(...)` callback (if supplied) is
  never invoked directly for a `ReplaceRoute` step — its `&Mutation`-typed
  signature cannot represent a replacement pairing — best-effort
  compensation for that step is instead performed internally using the
  already-captured prior route and leg-completion state; the callback
  continues to fire normally for every compensated `Single` step in the
  same plan. New report types
  `net-lattice-model::apply::{ApplyStepOutcome, NonConvergentReason,
  ApplyPlanReport}` (all re-exported from `net_lattice::mutation`)
  distinguish `Applied`/`Failed`/`NotAttempted` (mirroring
  `MutationOutcome`) from two additional outcomes no `MutationOutcome`
  variant can express: `Rejected` (capability-aware rejection, no native
  call attempted) and `NonConvergent` (a native call was attempted but the
  resulting state could not be confirmed, or a precondition no longer
  held). Two additive `MutationStopReason` variants (`CapabilityRejected`,
  `NonConvergentReplacement`) record these on
  `ApplyPlanReport::operation_reports`.
- `net-lattice-platform::RouteMutator`: two additive, default-provided
  methods, `supports_route_metric(&self) -> bool` (default `true`) and
  `route_replace_order(&self) -> RouteReplaceOrder` (default
  `RouteReplaceOrder::RemoveBeforeAdd`), plus the new
  `#[non_exhaustive]` `RouteReplaceOrder` enum
  (`RemoveBeforeAdd`/`AddBeforeRemove`). Existing backends need no code
  change unless they must override a default; `net-lattice-backend-darwin`
  overrides both (`supports_route_metric() -> false`,
  `route_replace_order() -> AddBeforeRemove`), matching its native route
  calls never reading or writing metric and its delete key being unable to
  disambiguate an old route from its replacement while both exist at once.
- `net-lattice::Lattice::<B>::apply(&self, desired: &DesiredState, options:
  &mut ExecutionOptions<'_>) -> Result<ApplyPlanReport>`: a thin facade
  convenience chaining `current_state()` → `Diff::compute` →
  `ApplyPlan::compile` → `execute_apply_plan` for callers that do not need
  to inspect the compiled plan before executing it. `Lattice::<B>::
  validate_apply_plan` (previously a private helper) is now public, for
  callers that want to preflight a compiled `ApplyPlan` without executing
  it. New `declarative_apply` example demonstrates the full
  `DesiredState` → `apply()` → `ApplyPlanReport` walkthrough.

### Changed

- Documented previously undocumented public constructor/builder methods
  across `net-lattice-model` (`Route`, `RouteConfig`, `Interface`,
  `NeighborEntry`, `StaticNeighbor`, `InterfaceAddress`,
  `NewInterfaceAddress`, `MacAddress`, `EventFilter`'s domain-selector
  methods) and `net-lattice-ip` (`Ipv4Address`, `Ipv4Network`,
  `Ipv6Address`, `Ipv6Network`), and `net-lattice`'s `Lattice::routes`/
  `interfaces`/`dns_config`/`neighbors`/`addresses` read methods. No
  behavior change; a rustdoc completeness pass only.

## [0.19.1] - 2026-08-05

### Added

- `net-lattice-model::Diff`: a new `#[non_exhaustive]`, pure, side-effect-free
  computed difference between a `CurrentState` and a `DesiredState`, one
  field per domain (`routes`, `interfaces`, `neighbors`, `addresses`, `dns`).
  Route/neighbor/address share a natural-key set-diff shape
  (`RouteChange`/`NeighborChange`/`AddressChange`, each `#[non_exhaustive]`)
  — route never produces a `Changed` variant, since its four-field natural
  key already covers every settable field. Interface uses a distinct
  per-field patch-diff shape (`InterfaceDiff` plus `Change<C, D>`) mirroring
  `InterfaceConfig`'s own "don't touch" semantics: a field is populated only
  when it was requested and differs from the observed value; an interface
  with nothing actionable does not appear in `Diff::interfaces` at all. DNS
  is a whole-value singleton comparison (`DnsChange`); `Diff::dns` is `None`
  both when DNS is unmanaged and when the desired configuration already
  matches the observed one. Computed by
  `Diff::compute(current: &CurrentState, desired: &DesiredState) -> Diff`, an
  inherent associated function with no `Result`, no I/O, and no
  provider/backend dependency — deciding whether or how to apply a `Diff` is
  out of scope for this type. If a `DesiredState` collection contains
  duplicate natural keys, the later entry in iteration order wins.
  Re-exported, along with `DesiredState` below, from `net_lattice::mutation`.
- `net-lattice-model::DesiredState`: a new `#[non_exhaustive]`, whole-system,
  caller-authored desired-state aggregate paralleling `CurrentState` — one
  `Option`-wrapped field per domain (`routes`, `interfaces`, `neighbors`,
  `addresses`, `dns`). `None` means that domain is not managed by this
  `DesiredState`; `Some` (including an empty collection) means it is managed
  with exactly that desired content — an empty `Vec` requests removal of
  every observed entry in that domain, it is not equivalent to `None`.
  Unlike `CurrentState`, it has no backend/provider dependency and is never
  assembled from a backend read; it is built via `DesiredState::empty()`
  plus `with_routes`/`with_interfaces`/`with_neighbors`/`with_addresses`/
  `with_dns` builder methods.
- `net-lattice-model::route::RouteConfig`: a new `#[non_exhaustive]` route
  mutation intent type (`destination`, `gateway`, `metric`,
  `interface_index`), distinct from the observed `Route` record, mirroring
  `StaticNeighbor`'s split from `NeighborEntry`. `RouteConfig::new` plus
  `with_gateway`/`with_metric`/`with_interface_index` builder methods
  construct it; it carries no route identifier, since no backend accepts one
  back as mutation input. `metric` is honored on Linux and Windows only and
  silently ignored as a no-op on Darwin, matching the pre-existing
  observed-side gap. Re-exported from `net_lattice::mutation`.
- `net-lattice`: facade-level tests for `DesiredState`/`Diff` (no-diff when
  desired matches observed, `Added`/`Removed` when it differs, no-diff for
  unmanaged domains), exercised through the facade crate CI actually builds,
  not only `net-lattice-model`'s own unit tests.
- `net-lattice`: a `declarative_diff` example demonstrating
  `DesiredState`/`Diff` usage.

### Changed

- **Breaking:** `net-lattice-platform::RouteMutator` now declares its own
  `type RouteConfig` associated type instead of reusing
  `RouteProvider::Route`; `add_route`/`remove_route` take `Self::RouteConfig`
  instead of `Self::Route`. `RouteProvider::Route` (the observed record) is
  unchanged. Every backend (`net-lattice-backend-linux`,
  `net-lattice-backend-windows`, `net-lattice-backend-darwin`) binds
  `type RouteConfig = net_lattice_model::route::RouteConfig`.
- **Breaking:** `net-lattice::Lattice::add_route`/`remove_route` and
  `net_lattice_model::mutation::Mutation::AddRoute`/`RemoveRoute` now take
  `RouteConfig` instead of `Route`. Callers that previously constructed a
  placeholder `Route::new(RouteId::new(0), ...)` purely to submit a mutation
  now construct `RouteConfig::new(destination)` instead, with no dummy
  identifier required.

### Fixed

- `net-lattice`: crate-level rustdoc no longer claims "this 0.18.0 release
  has not yet been published" (stale even at 0.18.0's own publish, and
  would go stale again after every future release); replaced with a
  version-independent statement.
- `net-lattice`: the transaction-plan rustdoc example no longer calls an
  add-then-remove `MutationPlan` "safe, idempotent" or claims it "leaves
  system state unchanged if executed" — contradicted by this crate's own
  documented failure semantics (execution stops after the first error, no
  automatic compensation).
- `net-lattice`: `README.md`'s interface-configuration and static-neighbor
  mutation examples no longer construct a hardcoded `InterfaceId::new(7)`;
  both now select the target interface explicitly by name at runtime and
  fail with `Error::NotFound` if it isn't present.
- `net-lattice`: the `model` module's rustdoc no longer describes itself as
  containing "desired-state domain objects" (it doesn't — that conflated
  mutation intent, which lives in `mutation`, with what `model` actually
  contains).

## [0.18.0] - 2026-08-04

### Added

- `net-lattice-model::CurrentState`: a new `#[non_exhaustive]` whole-system
  observed-state snapshot type aggregating routes, interfaces, neighbors,
  interface addresses, and DNS configuration, plus a `CurrentState::new`
  constructor (required because the type is `#[non_exhaustive]`, so a struct
  literal is unavailable outside `net-lattice-model`).
- `net-lattice-platform::SnapshotProvider`: a new generic provider trait
  (`type State`, `fn snapshot(&self) -> Result<Self::State>`) describing the
  whole-system state assembly contract, fail-fast on the first constituent
  read error. No backend implements it directly.
- `net-lattice::Lattice::current_state()`: assembles a `CurrentState` from
  routes, interfaces, neighbors, addresses, and DNS configuration in one call,
  fail-fast on the first read error, with no partial result. Implemented via
  `impl SnapshotProvider for Lattice<B>` (not a blanket implementation over
  every raw backend type `B`: Rust's orphan rules forbid implementing a
  foreign trait, `SnapshotProvider`, for a bare generic type parameter with no
  local type in the impl) — no backend crate needs any code change to gain
  this. `SnapshotProvider` and `CurrentState` are re-exported from
  `net_lattice::model` and `net_lattice::backend`.
- `net-lattice::model`, `net-lattice::mutation`, and `net-lattice::monitoring`:
  domain-scoped re-export modules for docs.rs navigation, collecting the
  observed/desired-state, mutation, and monitoring items respectively. These
  modules introduce no new type or trait, and `LatticeBackend`'s bound is
  unchanged.

### Changed

- **Breaking:** `net-lattice`'s crate-root re-export of every domain item
  (interfaces, routes, neighbors, addresses, DNS configuration, mutation
  intents and plans, change events, and their provider/mutator traits, plus
  `CurrentState`/`SnapshotProvider`) has been removed. These items now
  resolve only through the domain-scoped `net_lattice::model`,
  `net_lattice::mutation`, and `net_lattice::monitoring` modules (and, for
  backend authors, `net_lattice::backend`); a small cross-cutting set
  (`Error`, `Id`, `PlatformErrorCode`, `Result`, the `Ipv4*`/`Ipv6*`
  primitives, `Capability`, `CapabilityProvider`, `Lattice`, and
  `LatticeBackend`) still resolves at the crate root. `net-lattice` has not
  reached 1.0 and this 0.18.0 release had not yet been published, so no
  external consumer's import breaks; keeping the duplicate root re-export
  would have shipped items rendered on two or three separate docs.rs pages
  to a real audience for no benefit.

### Documentation

- Rewrote the `net-lattice` crate-root rustdoc into distinct Quick start,
  Inspection, Direct mutations, Transaction plans, Monitoring, and
  Implementing a backend sections, including a
  `Capability::NEIGHBOR_MUTATION` + `StaticNeighbor` mutation doctest and a
  `MutationPlan` build/validate/execute/report transaction doctest.
- Extended the `backend` module's doc comment to distinguish application
  code (the `model`/`mutation`/`monitoring` modules, plus a small
  cross-cutting set that still resolves at the crate root) from third-party
  backend implementers (`backend`).
- Reworded the README.md/README.ru.md `NEIGHBOR_MUTATION`/
  `NEIGHBOR_MONITORING` passage: the two are independent capabilities, and
  mutation support does not imply native change notifications; readers are
  pointed at the existing "Neighbor change monitoring" table row instead.
- Documented why the `mutation_plan` example's interface index is an
  intentional synthetic placeholder, unlike the other facade examples'
  runtime `NET_LATTICE_INTERFACE_INDEX` selection.

## [0.17.1] - 2026-08-03

### Added

- Stage 0.17 static-neighbor model and platform contracts (ADR-0001):
  `StaticNeighbor` desired-neighbor intent, `Mutation::{AddStaticNeighbor,
  RemoveStaticNeighbor}` with their semantics, `MutationSnapshot::Neighbor`,
  the `NeighborMutator` associated-type trait, and `Capability::NEIGHBOR_MUTATION`.
- Stage 0.17 Linux native static-neighbor mutation: `net-lattice-backend-linux`
  implements `NeighborMutator` (`RTM_NEWNEIGH`/`RTM_DELNEIGH` via `rtnetlink`,
  `NUD_PERMANENT`, `NDA_LLADDR`, IPv4 and IPv6) and truthfully advertises
  `Capability::NEIGHBOR_MUTATION`. Removal first re-reads the neighbor table
  and refuses to delete a present but non-`Permanent` (dynamically learned)
  entry, returning `InvalidState`; a missing target returns `NotFound`, and
  native `EEXIST`/`EPERM`/`EACCES` map to `AlreadyExists`/`PermissionDenied`.
- Stage 0.17 Windows native static-neighbor mutation: `net-lattice-backend-windows`
  implements `NeighborMutator` (`CreateIpNetEntry2`/`DeleteIpNetEntry2` over
  `MIB_IPNET_ROW2`, `NlnsPermanent`, IPv4 and IPv6) and advertises
  `Capability::NEIGHBOR_MUTATION`. Removal first re-reads the neighbor table
  and refuses to delete a present but non-`Permanent` (dynamically learned)
  entry, returning `InvalidState`; a missing target returns `NotFound`, and
  native `ERROR_ACCESS_DENIED`/`ERROR_OBJECT_ALREADY_EXISTS`/`ERROR_NOT_SUPPORTED`
  map to `PermissionDenied`/`AlreadyExists`/`Unsupported`. This implementation
  has been confirmed on a live elevated Windows CI run.
- Stage 0.17 macOS native static-neighbor mutation: `net-lattice-backend-darwin`
  implements `NeighborMutator` over `PF_ROUTE` (`RTM_ADD` for add, encoding a
  complete `sockaddr_dl` gateway with the real interface's link type read via
  `getifaddrs`; a two-message `RTM_GET`-then-`RTM_DELETE` sequence for
  remove, reusing the kernel's own `RTM_GET` reply's `sockaddr_dl` gateway,
  mirroring Apple's own `arp.tproj/arp.c`/`ndp.tproj/ndp.c`), with removal
  refusing to delete a present but non-`Permanent` (dynamically learned)
  entry (`InvalidState`), a missing target returning `NotFound`, and native
  `EEXIST`/`ESRCH`/`ENOENT`/`EPERM`/`EACCES` mapped to
  `AlreadyExists`/`NotFound`/`PermissionDenied`. Confirmed on a live elevated
  macOS CI run (add/read/remove round trip); `DarwinBackend::capabilities()`
  now advertises `Capability::NEIGHBOR_MUTATION`. The `net-lattice` facade
  forwards `NeighborMutator` on every backend through
  `Lattice::add_static_neighbor`/`remove_static_neighbor` and
  `Mutation::{AddStaticNeighbor, RemoveStaticNeighbor}` executor dispatch.
- Isolated privileged public-facade acceptance for static-neighbor add/read/
  remove and cancellation-triggered compensation, verified against real
  Linux, Windows, and macOS backends; the isolated destructive-topology
  acceptance carried over from Stage 0.16 is now complete for the route,
  address, and neighbor domains on all three platforms.
- IPv6 DNS parity: model, parser/renderer, and native-mapping tests proving
  IPv4 and IPv6 nameservers round-trip identically through `DnsConfig`/
  `NewDnsConfig` on Linux, Windows, and macOS, including public-facade
  `execute_plan` coverage. No new public API — `DnsConfig`/`NewDnsConfig`
  already accepted either address family; this closes the deferred Stage
  0.16 verification gap.
- Split `net-lattice-platform`'s `RouteProvider` into a read-only
  `RouteProvider` (`routes()`) and a new `RouteMutator` (`add_route()`,
  `remove_route()`), matching the provider/mutator split already used by
  every other domain (ADR-0002). Added `Capability::ROUTE_MUTATION`,
  truthfully advertised by all three backends, and `Lattice::validate_plan`
  now rejects `Mutation::AddRoute`/`RemoveRoute` before submission when the
  connected backend does not advertise it — closing a capability-preflight
  gap that previously let route mutations reach the backend unchecked.

### Changed

- **Breaking (pre-1.0):** `RouteProvider::add_route`/`remove_route` moved to
  a new `RouteMutator` trait; a third-party backend implementing
  `RouteProvider` must now also implement `RouteMutator` to satisfy
  `LatticeBackend`. `Lattice::add_route`/`remove_route` are unaffected at
  the call site.

## [0.16.0] - 2026-08-01

### Added

- Stage 0.16 interface configuration: `InterfaceConfig` partial desired
  patches and `DesiredAdminState`, explicitly separate from observed
  `Interface` state.
- `InterfaceMutator`, `Lattice::set_interface_config`,
  `Mutation::SetInterfaceConfig`, and `MutationSnapshot::Interface`, with
  independent `INTERFACE_ADMIN_STATE` and `INTERFACE_MTU` runtime capabilities.
- Native read-after-write interface configuration on Linux (Netlink link
  changes), Windows (IP Helper admin and per-family IP-interface MTU APIs),
  and macOS (BSD MTU/flags ioctls).
- A capability-gated `interface_configuration` example, deterministic native
  request/event fixtures, and ignored privileged submission/readback tests
  that restore their selected interface state.

### Changed

- A combined administrative-state and MTU patch is explicitly reported as
  potentially partially applied; callers retain control of compensation via
  Stage 0.15 `ExecutionOptions`.
- Monitoring capabilities now describe deliverable native event domains:
  `ROUTE_MONITORING`, `INTERFACE_MONITORING`, `NEIGHBOR_MONITORING`, and
  `ADDRESS_MONITORING`; `MONITORING` is their all-domain aggregate. Windows
  now rejects neighbor and unfiltered all-domain watchers instead of silently
  returning a stream without neighbor events.

### Documentation

- Document the interface configuration contract, platform capability gates,
  native event mappings, and the shared-runner limitation for destructive
  end-to-end interface-event testing in English and Russian project docs.
- Document the domain-specific monitoring capability matrix and the required
  migration from a coarse `MONITORING` check to a selected-domain check.
- Mark Stage 0.16 interface configuration as verified across privileged Linux,
  Windows, and macOS CI. IPv6 DNS parity and isolated destructive-topology
  acceptance are explicitly deferred to Stage 0.17.

## [0.15.2] - 2026-08-01

### Added

- Stage 0.15 transaction-execution baseline: `Lattice::execute_plan` submits
  ordered mutation plans and returns one `MutationOutcome` per operation.
- A single public `ExecutionOptions` value configures operation-boundary
  cancellation, prior-state capture, and explicit reverse-order compensation;
  the facade no longer grows one method per execution policy.
- `Lattice::validate_plan` performs side-effect-free runtime capability
  preflight; execution rejects unsupported DNS mutation before submitting any
  operation.
- `Lattice::execute_plan` captures caller-defined prior state at operation
  boundaries and supplies it to reverse-order compensation when configured.
- Public `MutationSnapshot` values cover observed route, interface-address,
  and DNS state through provider-backed reads.
- Runtime plan validation now checks DNS capability, interface/address/route
  preconditions, and ordered add/remove effects before native submission.
- `MutationPlanReport::operation_reports` now exposes phase, duration, and
  stop-reason metadata without changing the existing `MutationOutcome` values.
- Validation, snapshot, execution, cancellation, and compensation boundaries
  are represented by `MutationExecutionPhase` and `MutationStopReason`.

### Tests

- Add an ignored native facade transaction round-trip and run it in the
  privileged Linux, Windows, and macOS CI coverage jobs alongside backend
  integration tests.
- Add an ignored native compensation scenario that verifies first-failure
  stopping and reverse-order route cleanup through the facade.

### Documentation

- Give every published crate a standalone crate-local README with its purpose,
  intended audience, usage example, and platform or privilege constraints.
- Keep the repository README focused on the workspace overview and link to the
  individual crate guides; synchronize English/Russian capability status and
  community health documents with the Stage 0.15 executor contract.

## [0.14.1] - 2026-08-01

### Added

- Stage 0.14 mutation operation model: inspectable `Mutation` values and
  ordered `MutationPlan`s for the existing route, interface-address, and DNS
  mutations.
- Explicit `MutationSemantics` for preconditions, idempotency, elevated
  privilege, completion confirmation, reversibility, and partial-application
  risk. Plans are data only; execution remains Stage 0.15 work.
- Side-effect-free `MutationPreflight` analysis classifies operations that
  require prior observed state or may be partially applied.
- Typed `MutationOutcome`, `MutationPlanReport`, and `RollbackStatus` contracts
  describe execution and compensation boundaries without executing mutations.
- Plan-local operation and outcome accessors preserve the ordered association
  between a requested mutation and its eventual report entry.

### Documentation

- Document Stage 0.14 planning, preflight, partial-application, prior-state,
  and compensation boundaries in the English and Russian project guides.

### Tests

- Add coverage for preflight risk classification and partial-failure report
  states.

## [0.13.0] - 2026-08-01

### Added

- Stage 0.13 DNS mutation: `NewDnsConfig`, `DnsMutator`,
  `Lattice::set_dns_config`, and `Capability::DNS_MUTATION`.
- Linux and macOS resolver-file replacement with a resulting observed
  `DnsConfig`; Windows resolver replacement through IP Helper DNS settings.
- `net_lattice::backend` as the documented third-party backend extension
  namespace; provider traits are an official extension API.

### Changed

- `EventReceiver` now implements `Iterator<Item = Result<E>>`, preserving
  background errors instead of silently ending iteration; use
  `EventReceiver::from_channel_receiver` for backend-owned channel receivers;
  the ambiguous `EventReceiver::new` constructor was removed before 1.0.

## [0.12.3] - 2026-07-31

### Added

- Stage 0.12 watcher API stabilization: `EventFilter` object selectors for
  routes, interfaces, neighbors, and interface addresses; filters are applied
  before ordinary events enter backend queues.
- Stage 0.11 `Lattice::watch_async(filter)` now shares the object/domain
  filter semantics of `Lattice::watch_filtered(filter)` without a duplicate
  async watcher entry point.

### Tests

- Add lifecycle and regression coverage for subscription-guard replacement,
  receiver drop, iterator error termination, and zero-capacity rejection.

### Changed

- Facade watcher entry points now validate `Capability::MONITORING` before
  opening a native subscription and return `Error::Unsupported` when absent.

### Documentation

- Document `EventReceiver` bounded delivery, cancellation, timeout,
  disconnection, constructor, subscription-guard, and iterator semantics.
- Clarify backend-facing native Tokio watcher integration through
  `TokioEventProvider`, including associated types and receiver ownership.
- Update `EventStream` documentation to cover both native async delivery and
  synchronous receiver adaptation; add watcher-oriented rustdoc examples.
- Clarify the observed resolver-view semantics of `DnsConfig` and the
  portable-runtime contract of `Capability`.

## [0.11.0] - 2026-07-31

### Added

- Optional `net-lattice` `async` feature and `Lattice::watch_async(filter)`.
  The feature re-exports one runtime-agnostic `net-lattice-async::EventStream`
  without adding Tokio code to the default facade.
- Native async event delivery in every backend: Linux polls Netlink through
  its existing Tokio runtime, Windows IP Helper callbacks feed a Tokio
  transport, and the macOS PF_ROUTE reader feeds that transport directly.
  All three use bounded delivery with the existing resynchronization semantics.
- `net-lattice-async` 0.1.0: the single `futures::Stream` type used by the
  facade. It also retains an explicit worker-thread bridge for callers that
  adapt an arbitrary synchronous `EventReceiver` themselves.

## [0.10.0] - 2026-07-31

### Added

- Bounded event delivery (256 entries), `Event::ResyncRequired` overflow
  signalling, `EventFilter`, and `Lattice::watch_filtered()` across Linux,
  Windows, and macOS native watchers.

## [0.9.1] - 2026-07-31

### Fixed

- `net-lattice-backend-darwin`: write IPv4 octets to `sockaddr_in` in the
  correct network byte order for native address ioctls. The previous encoding
  could make a successful `SIOCAIFADDR` assignment unreadable through the
  requested `InterfaceAddress`, causing `add_address()` to return
  `Error::InvalidState` on macOS. A regression test now verifies the exact
  `sockaddr_in` round trip.

## [0.9.0] - 2026-07-31

### Added

- `net-lattice-model`: `NewInterfaceAddress`, a separate, typed intent for
  assigning an interface address. It accepts an interface ID, address/prefix,
  and optional IPv4 broadcast; the caller never constructs an observed
  `InterfaceAddressId`.
- `net-lattice-platform`: `AddressMutator`, separate from read-only
  `AddressProvider`, with `add_address` returning the canonical observed
  address and `remove_address` accepting that observed record.
- `net-lattice-backend-linux`: native IPv4/IPv6 address assignment and
  removal through Netlink.
- `net-lattice-backend-windows`: native IPv4/IPv6 address assignment and
  removal through `CreateUnicastIpAddressEntry` and
  `DeleteUnicastIpAddressEntry`. Windows rejects an explicit IPv4 broadcast,
  because IP Helper derives it from the prefix instead of accepting an
  override.
- `net-lattice-backend-darwin`: native IPv4/IPv6 address assignment and
  removal through BSD address ioctls; no `ifconfig` subprocess is used.
- `net-lattice` facade: `Lattice::add_address()` and
  `Lattice::remove_address()`, with model convergence enforced for
  `AddressMutator` as well as `AddressProvider`.

### Testing

- Privileged end-to-end add/read/remove address tests for Linux, Windows, and
  BSD/macOS, using a dedicated TEST-NET-1 address on the loopback interface.

## [0.8.0] - 2026-07-30

### Added

- `net-lattice-platform`: `CapabilityProvider`, reporting the runtime-
  dependent `Capability` flags (previously only a bare bitflags type with
  no way for a caller to actually query it) the connected backend
  currently has available.
- `net-lattice-backend-linux`/`-windows`/`-darwin`: `CapabilityProvider`
  implementation, reporting `Capability::IPV6` (every provider these
  backends implement already handles both address families).
  `VRF`/`NAMESPACES`/`MONITORING` are left unset — not implemented yet.
- `net-lattice` facade: `Lattice::capabilities()` and
  `Lattice::supports(capability)`, and `LatticeBackend` now additionally
  requires `CapabilityProvider`.
- `net-lattice-model`: `event` module with signal-shaped `Event` and
  `ChangeKind` values for routes, interfaces, neighbors, and interface
  addresses.
- `net-lattice-platform`: synchronous `EventProvider` and `EventReceiver`.
  The receiver provides `recv`, `try_recv`, `recv_timeout`, and `Iterator`,
  without adding an async-runtime dependency to the core API.
- `net-lattice-backend-linux`: monitoring through an independent Netlink
  multicast socket for link, route, neighbor, and address notifications.
- `net-lattice-backend-windows`: monitoring through IP Helper route,
  interface, and unicast-address change registrations.
- `net-lattice-backend-darwin`: monitoring through an independent PF_ROUTE
  socket for route, interface, address, and neighbor notifications.
- All backends advertise `Capability::MONITORING` and retain native watcher
  cancellation state in the returned `EventReceiver`.
- `net-lattice` facade: `Lattice::watch()` plus event-related re-exports.

### Changed

- `net-lattice-core`: `Error::Disconnected` distinguishes a stopped watcher
  from an empty event queue or a timeout.

## [0.7.0] - 2026-07-30

### Added

- `net-lattice-model`: the `ifaddr` module (`InterfaceAddress`,
  `InterfaceAddressId` — an IP address assigned to an interface, plus its
  prefix length and, for IPv4, its broadcast address). Named `ifaddr`
  rather than `address` to avoid colliding with the existing
  `IpAddress`/`Network` primitives.
- `net-lattice-platform`: `AddressProvider`, with no dependency on
  `net-lattice-model`.
- `net-lattice-backend-linux`: `AddressProvider` implementation via
  Netlink's `RTM_GETADDR` (`rtnetlink`'s `address()` handle).
- `net-lattice-backend-darwin`: `AddressProvider` implementation via
  `getifaddrs`'s `AF_INET`/`AF_INET6` entries, reusing the interface
  backend's existing traversal.
- `net-lattice-backend-windows`: `AddressProvider` implementation via
  `GetUnicastIpAddressTable`.
- `net-lattice` facade: `Lattice::addresses()`, and `LatticeBackend` now
  additionally requires `AddressProvider<InterfaceAddress = InterfaceAddress>`.

## [0.6.0] - 2026-07-30

### Added

- `net-lattice-model`: the `neighbor` module (`NeighborEntry`, `NeighborId`,
  `NeighborState` — mirroring Linux's `NUD_*`/BSD's route-socket flags/
  Windows's `NL_NEIGHBOR_STATE`).
- `net-lattice-platform`: `NeighborProvider`, with no dependency on
  `net-lattice-model`.
- `net-lattice-backend-linux`: `NeighborProvider` implementation via
  Netlink's `RTM_GETNEIGH` (`rtnetlink`'s `neighbours()` handle).
- `net-lattice-backend-darwin`: `NeighborProvider` implementation via
  `sysctl(NET_RT_FLAGS, RTF_LLINFO)` over `AF_INET`/`AF_INET6` — the same
  mechanism `arp -a`/`ndp -an` use — reusing the `rt_msghdr` parsing
  already in place for route dumps.
- `net-lattice-backend-windows`: `NeighborProvider` implementation via
  `GetIpNetTable2`.
- `net-lattice` facade: `Lattice::neighbors()`, and `LatticeBackend` now
  additionally requires `NeighborProvider<NeighborEntry = NeighborEntry>`.

## [0.5.0] - 2026-07-30

### Added

- `net-lattice-model`: the `dns` module (`DnsConfig`: nameservers and
  search domains).
- `net-lattice-platform`: `DnsProvider`, with no dependency on
  `net-lattice-model`.
- `net-lattice-backend-linux` and `net-lattice-backend-darwin`:
  `DnsProvider` implementation via parsing `/etc/resolv.conf`
  (`nameserver`/`search`/`domain` directives — identical format on both
  platforms, so the parser is shared verbatim between the two crates).
- `net-lattice-backend-windows`: `DnsProvider` implementation via
  `GetAdaptersAddresses`, aggregating each adapter's DNS servers and
  suffix, deduplicated across the machine.
- `net-lattice` facade: `Lattice::dns_config()`, and `LatticeBackend` now
  additionally requires `DnsProvider<DnsConfig = DnsConfig>`.

### Fixed

- `scripts/release.sh`: the root `Cargo.toml` `[workspace.dependencies]`
  version reference for a crate could silently fail to update on a
  minor/major bump. The check required the crate's *current* version to
  match, character-for-character, whatever was already pinned in root
  `Cargo.toml` — but patch bumps intentionally never touch root (they're
  semver-compatible via caret), so after enough patch bumps accumulated,
  root's pinned version drifted behind the crate's real version, and the
  match silently failed on the next minor/major bump, leaving root stale
  (observed live: `net-lattice-backend-darwin` bumped 0.2.11 → 0.3.0 while
  root Cargo.toml kept referencing 0.2.10). Fixed by replacing whatever
  version is present for that dependency, unconditionally, instead of
  requiring an exact match against the old version.
- `scripts/release.sh`: the crates.io "is this version already published?"
  guard (which exists to avoid skipping past a version that was bumped in
  git but never actually published) only ran when the *current* version
  was "round" relative to the requested bump (e.g. patch `0` before a
  `--minor`). A non-round current version (e.g. `0.2.11`) skipped the
  check entirely and bumped straight past it even if unpublished. Fixed:
  the publication check now runs before every `--minor`/`--major` bump
  regardless of whether the current version is round; `--patch` still
  skips it, since a patch bump is always semver-compatible with what it
  replaces.

## [0.4.10] - 2026-07-30

### Added

- `net-lattice-model`: the `mac` module (`MacAddress`) and the `interface`
  module (`Interface`, `InterfaceId`, `InterfaceKind`, `AdminState`,
  `OperationalState`).
- `net-lattice-platform`: `InterfaceProvider`, with no dependency on
  `net-lattice-model`.
- `net-lattice-backend-linux`: `InterfaceProvider` implementation via
  Netlink (`RTM_GETLINK`), covered by a real, unprivileged `interfaces()`
  test asserting the `lo` interface is present and classified as
  `Loopback`.
- `net-lattice-backend-windows`: `InterfaceProvider` implementation via the
  Windows IP Helper API (`GetIfTable2`).
- `net-lattice-backend-darwin`: `InterfaceProvider` implementation via
  `getifaddrs`, reading `AF_LINK` entries for name, index, hardware type,
  and MAC address, plus MTU via `ioctl(SIOCGIFMTU)`.
- `net-lattice` facade: `Lattice::interfaces()`, and `LatticeBackend` now
  additionally requires `InterfaceProvider<Interface = Interface>`.
- CI: `.github/workflows/ci.yml` runs fmt/clippy/test/doc on native Linux,
  Windows, and macOS GitHub-hosted runners (not cross-compiled), so each
  platform's backend crate is actually built and clippy-checked on its own
  OS instead of only ever compiling on Linux, plus a follow-up step per OS
  running each backend's `#[ignore]`d privileged round-trip test (`sudo` for
  `CAP_NET_ADMIN`/root on Linux/macOS; Windows runners are Administrator
  already). `dependabot.yml` gained a `github-actions` ecosystem entry now
  that a workflow exists for it to scan; both ecosystems' PRs run through
  this same CI.

This is Stage 0.4 of [ARCHITECTURE.md](ARCHITECTURE.md)'s Incremental
Delivery Plan: listing network interfaces on Linux, Windows, and
BSD/macOS.

### Fixed

- `net-lattice-backend-darwin`: route parsing (`message_to_route`) always
  reported destinations as `/32`/`/128` regardless of the actual route,
  since `RTA_NETMASK` was never parsed. Non-host routes (subnets, the
  default route) now get their real prefix length from the netmask.
- `net-lattice-backend-windows`: `RouteProvider` used field/type names that
  don't exist on the real `windows` crate bindings (`MIB_IPADDRESS_STRING`,
  `Metric1`, raw `u16`/`u32` casts of `WIN32_ERROR`/`ADDRESS_FAMILY`) and
  never actually compiled for `target_os = "windows"`.
- `net-lattice-backend-darwin`: `routes()` sent `RTM_GET` with no
  destination over the `PF_ROUTE` socket to try to dump the whole table —
  the kernel rejects that with `EINVAL` (`RTM_GET` looks up one specific
  destination's route; it isn't Netlink's dump-via-empty-request idiom).
  Caught by CI's first real run on a macOS runner. Replaced with
  `sysctl(CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0)`, the standard
  BSD mechanism for reading the entire routing table at once.
- `net-lattice-backend-darwin`: `add_route` failed with `EINVAL` for any
  route with an interface index but no IP gateway (the common case —
  e.g. `route.with_interface_index(...)` alone). `RTM_ADD` requires an
  address in the `RTA_GATEWAY` slot to determine the outgoing path;
  `rtm_index` in the request header is not honored for `ADD` (the kernel
  only fills it in on the reply). Caught by CI's privileged round-trip
  test on a macOS runner. Fixed by supplying a link-layer (`AF_LINK`)
  `sockaddr_dl` gateway naming the interface when there's no IP gateway —
  the same shape `route add -interface` uses — without setting
  `RTF_GATEWAY` (that flag means "real next hop", not "no next hop, just
  this wire").
- `net-lattice-backend-darwin`: `add_route`/`remove_route` always wrapped
  the routing socket's errno in `Error::Platform`, even for errno values
  that map directly onto Net Lattice's error taxonomy per ARCHITECTURE.md's
  Error Model (`EEXIST` on `RTM_ADD` for a route that already exists,
  `ESRCH`/`ENOENT` on `RTM_DELETE` for no matching route, `EPERM`/`EACCES`
  for missing privilege) — callers had to pattern-match a raw Darwin errno
  instead of `Error::AlreadyExists`/`NotFound`/`PermissionDenied`. The
  privileged round-trip test also now cleans up any route left over from a
  prior interrupted run before adding, rather than surfacing that stale
  state as a fresh `AlreadyExists` failure.
- `net-lattice-backend-darwin`'s privileged round-trip test assumed `lo0`
  is always ifindex `1`; GitHub-hosted macOS runners carry enough virtual
  interfaces (Docker, VPN, `utun*`, ...) that this doesn't hold, so the
  test added a route on the wrong interface and never found it in
  `routes()` afterward. Looked up `lo0`'s real index via `InterfaceProvider`
  instead, same as the Linux/Windows equivalents of this test already did.
- `net-lattice-backend-darwin`: `add_route`/`remove_route` trusted a
  successful `send()` on the `PF_ROUTE` socket as proof the kernel actually
  performed the change. `send()` only confirms the message was accepted
  into the socket buffer — routing sockets echo the processed request back
  (with `rtm_errno` filled in) to every open routing socket on the system,
  and a caller is expected to read that reply to learn the real outcome.
  Diagnostics added for the previous two fixes proved this was live: the
  route was entirely absent afterward (not merely misfiled under the wrong
  interface or prefix), meaning `add_route` was reporting success for a
  request the kernel had silently rejected. Added `send_route_request`,
  which sends and then reads the socket until it sees the reply matching
  this request's `rtm_pid`/`rtm_seq` (filtering out other processes'
  traffic on the same shared socket), returning `Err` from a nonzero
  `rtm_errno` instead of assuming success.
- `net-lattice-backend-darwin`: the `AF_LINK` `sockaddr_dl` gateway used
  for interface-only routes (no IP next hop) declared `sdl_len` as
  `sizeof(struct sockaddr_dl)` (20 bytes, including a 12-byte `sdl_data`
  array left entirely unused). Compared against `golang.org/x/net/route`
  (the reference BSD routing-socket implementation)'s `LinkAddr.marshal`,
  the on-wire `sdl_len` for a name-less, address-less link address must be
  just the significant header (8 bytes) — not the padded struct size. The
  kernel accepted the malformed request (`rtm_errno == 0`) but never
  actually created the route, which is why `routes()` found nothing under
  that destination at all afterward, on any interface. `sdl_len` and the
  bytes actually written are now both 8. This alone didn't fix the round
  trip, though — see the next entry.
- `net-lattice-backend-darwin`: the `AF_LINK` gateway for interface-only
  routes carried only `sdl_index`, an empty name (`sdl_nlen = 0`). Checked
  against `route.tproj/route.c` (Apple's own `route(8)` source, via
  `apple-oss-distributions/network_cmds`) — `route add -interface`
  resolves the interface's real `sockaddr_dl` via `getifaddrs` and copies
  it *whole*, name included, into the gateway slot. An index-only
  `sockaddr_dl` is accepted by the kernel (`rtm_errno == 0`, matching what
  CI observed) but doesn't resolve to a usable interface reference, so no
  route is actually created. `push_link_gateway` now looks up the
  interface's name via `if_indextoname` and includes it (`sdl_nlen`/
  `sdl_data`), matching what a real, working `sockaddr_dl` for that
  interface looks like. Still didn't fix the round trip — see the next
  entry, which turned out to be the actual root cause of every `add_route`
  failure so far in this stage.
- `net-lattice-backend-darwin`: `build_add_message`/`build_delete_message`
  wrote the destination's sockaddrs to the message body in `DST, NETMASK,
  GATEWAY` order. BSD routing-socket messages require sockaddrs in
  ascending `RTAX_*` index order (`DST`=0, `GATEWAY`=1, `NETMASK`=2, ...) —
  confirmed against `golang.org/x/net/route`'s `marshalAddrs`, which
  iterates addresses strictly by that index when building the wire
  format. Every previous fix in this stage (netmask parsing, the link
  gateway's shape, its `sdl_len`, its name) was individually correct but
  moot: with gateway and netmask swapped, the kernel was reading the
  netmask sockaddr as the gateway and the gateway/link-layer sockaddr as
  the netmask, on every `RTM_ADD`/`RTM_DELETE` this backend ever sent.
  Reordered to `DST, GATEWAY, NETMASK` in both functions.
- `net-lattice-backend-darwin`: `push_link_gateway` returned the
  unrounded `sdl_len` (e.g. 11 for an 8-byte header plus a 3-byte
  interface name like `lo0`) as the buffer space it consumed, instead of
  that value rounded up to the routing socket's 4-byte alignment (12).
  Every subsequent sockaddr in the message (`NETMASK`, in this backend's
  case) then landed at a misaligned offset, corrupting how the kernel
  parsed everything after the link-layer gateway. Confirmed by hex-dumping
  the exact bytes sent and the kernel's own reply in CI: the reply's
  `rtm_errno` was `17` (`EEXIST`) — a real error the round-trip test's
  `if matches!(..., Err(PermissionDenied) | Err(Platform(_)))` guard
  didn't catch, since `EEXIST` correctly maps to `Error::AlreadyExists`,
  silently letting a genuinely failed `add_route` continue as if nothing
  had gone wrong. Fixed `push_link_gateway` to return the rounded-up
  length, and hardened the test to fail on *any* `add_route` error rather
  than only those two variants.

## [0.3.0] -  2026-07-29

### Added

- `net-lattice-backend-darwin`: `RouteProvider` implementation via BSD/macOS
  route sockets (`RTM_GET`/`RTM_ADD`/`RTM_DELETE`), gated to
  `target_os = "macos"`. Covered by a real, unprivileged `routes()` test
  and a root-gated add/remove round-trip test (`#[ignore]`, run manually
  with elevated privileges).
- macOS platform support in the `net-lattice` facade (`Lattice::connect()`
  on `cfg(target_os = "macos")`), wired to `DarwinBackend`.

This is Stage 0.3 of [ARCHITECTURE.md](ARCHITECTURE.md)'s Incremental
Delivery Plan: listing, adding, and removing IPv4/IPv6 routes on BSD/macOS.


## [0.2.0] - 2026-07-29

### Added

- `net-lattice-backend-windows`: `RouteProvider` implementation via the
  Windows IP Helper API (`GetIpForwardTable2`, `CreateIpForwardEntry2`,
  `DeleteIpForwardEntry2`), gated to `target_os = "windows"`.
- Windows platform support in the `net-lattice` facade (`Lattice::connect()`
  on `cfg(target_os = "windows")`), wired to `WindowsBackend`.

This is Stage 0.2 of [ARCHITECTURE.md](ARCHITECTURE.md)'s Incremental
Delivery Plan: listing, adding, and removing IPv4/IPv6 routes on Windows.


## [0.1.0] - 2026-07-28

### Added


- Repository bootstrap: workspace `Cargo.toml`, licensing, community health
  files, and GitHub configuration.
- `net-lattice-core`: `Error`, `PlatformErrorCode`, and `Id<T>`.
- `net-lattice-ip`: `Ipv4Address`/`Ipv6Address`, `Ipv4Network`/`Ipv6Network`,
  `Ipv4PrefixLength`/`Ipv6PrefixLength`.
- `net-lattice-model`: the `route` module (`Route`, `RouteId`, `IpAddress`,
  `Network`), including `Route::interface_index` for specifying the
  outgoing interface by raw ifindex.
- `net-lattice-platform`: `RouteProvider` and `Capability`, with no
  dependency on `net-lattice-model`.
- `net-lattice-backend-linux`: `RouteProvider` implementation via Netlink
  (`rtnetlink`), gated to `target_os = "linux"`. Covered by a real,
  unprivileged `routes()` test and a `CAP_NET_ADMIN`-gated add/remove
  round-trip test (`#[ignore]`, run manually with elevated privileges).
- `net-lattice` facade: `LatticeBackend`, `Lattice<B>`, and
  `Lattice::connect()` (Linux default), plus a `list_routes` example.
- `scripts/release.sh` and `scripts/gh_release.sh` for versioning,
  publishing, and tagging workspace crates.

This is Stage 0.1 of [ARCHITECTURE.md](ARCHITECTURE.md)'s Incremental
Delivery Plan: listing, adding, and removing IPv4/IPv6 routes on Linux.
