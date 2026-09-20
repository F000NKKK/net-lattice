# net-lattice

Cross-platform network inspection and configuration through one strongly typed
Rust API. This is the application-facing Net Lattice crate.

## What it provides

- automatic native backend selection on Linux, Windows, and macOS;
- inspection of interfaces, addresses, routes, neighbors, and DNS;
- `current_state()`, a single call returning a whole-system `CurrentState`
  snapshot (routes, interfaces, neighbors, addresses, DNS, and firewall
  rules) assembled from the same per-domain reads, with zero extra backend
  code required;
- imperative route, address, resolver, and static ARP/NDP neighbor mutation;
- native-firewall policy management (`firewall_rules`/`set_firewall_policy`/
  `clear_firewall_policy`) — atomic whole-policy replacement on Linux
  (nftables), Windows (WFP), and macOS (`pf`), also reachable declaratively
  through `DesiredState::with_firewall`/`Diff::firewall`/`ApplyPlan`;
- partial interface MTU and administrative-state configuration;
- filtered native change monitoring, plus an opt-in `watch_with_additions`
  entry point that merges native events with any backend-reported
  `Addition`s — explicitly opt-in, lesser-quality workarounds (for example,
  polling) for a gap a platform has no native mechanism for;
- ordered `MutationPlan` execution with runtime validation, cancellation,
  snapshots, explicit compensation, and per-operation reports;
- declarative `ApplyPlan` execution (compiled from a `DesiredState`/`Diff`
  pair) with capability-aware rejection, per-backend route-replacement
  ordering, mandatory read-after-write verification, and convergence/
  non-convergence reporting.

Enable the optional `async` feature for a runtime-independent
`futures::Stream` watcher surface.

## Quick start

```rust,no_run
use net_lattice::{Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    for interface in lattice.interfaces()? {
        println!("{interface:?}");
    }
    Ok(())
}
```

## Whole-system snapshot

`current_state()` reads routes, interfaces, neighbors, addresses, DNS, and
firewall rules in one call and returns them as a single `CurrentState`. Each
domain is still an independent backend read — there is no lock or
transaction spanning them, so treat the result as several closely timed
reads, not one atomic capture. If any one read fails, the whole call fails
and returns no partial state.

```rust,no_run
use net_lattice::{Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    let state = lattice.current_state()?;
    println!("{} routes, {} interfaces", state.routes.len(), state.interfaces.len());
    Ok(())
}
```

## Transaction execution

`MutationPlan` is data only. Pass a plan and one `ExecutionOptions` value to
`Lattice::execute_plan`; callbacks can request cancellation, capture prior
state, and perform explicit compensation without multiplying facade methods.
The returned report preserves plan indices and distinguishes validation,
snapshot, execution, cancellation, and compensation boundaries.

## Declarative apply execution

`DesiredState` and `Diff::compute` produce a pure, side-effect-free `Diff`;
`ApplyPlan::compile(&diff)` compiles it into an ordered list of `ApplyStep`s,
still with no side effects. `Lattice::execute_apply_plan` executes that plan
against the connected backend, given one `ExecutionOptions` value the same
way `execute_plan` is. Most steps (`ApplyStep::Single`) run through the exact
same cancellation/snapshot/compensation primitives `execute_plan` uses. A
destination-paired route replacement (`ApplyStep::ReplaceRoute`) runs a
dedicated path instead: it is rejected before any native call if the
connected backend cannot honor a requested route-metric change, submits its
two native calls in the backend's own required order, and requires a
read-after-write re-read to confirm both the new route is present and the
old one is gone before it counts as converged.

**Compensation nuance:** a caller-supplied `.compensation(...)` callback
(typed for a single `Mutation`) is never invoked directly for a
`ReplaceRoute` step — its shape cannot represent a replacement pairing. If a
plan stops at or after a `ReplaceRoute` step and a compensation callback was
supplied, `execute_apply_plan` performs that step's best-effort reversal
internally instead; the callback still fires normally for every compensated
`Single` step in the same plan. The returned `ApplyPlanReport` distinguishes
`Applied`/`Failed`/`NotAttempted` (as `MutationOutcome` does) plus two
further outcomes: `Rejected` (a capability-aware rejection before any native
call) and `NonConvergent` (a native call was attempted but the resulting
state could not be confirmed, or a precondition no longer held).

For the common case — no need to inspect the compiled plan before
executing it — `Lattice::apply(&self, desired: &DesiredState, options: &mut
ExecutionOptions<'_>) -> Result<ApplyPlanReport>` is a thin convenience that
chains `current_state()` → `Diff::compute` → `ApplyPlan::compile` →
`execute_apply_plan` in one call. Callers that do want to preflight or
inspect the compiled plan first should call those steps directly (or the
public `Lattice::validate_apply_plan`) instead of `apply()`. See the
`declarative_apply` example for a runnable walkthrough.

For the common "what would change" case — no need to execute anything —
`Lattice::diff(&self, desired: &DesiredState) -> Result<Diff>` chains
`current_state()` → `Diff::compute` without compiling or executing a plan.
See the `declarative_diff` example.

## Interface configuration

`InterfaceConfig` is desired intent, distinct from the observed `Interface`.
Build a patch with at least one requested setting, check the matching runtime
capabilities, then submit it. A successful call returns an observed interface
read after the native update.

```rust,no_run
use net_lattice::mutation::{DesiredAdminState, InterfaceConfig};
use net_lattice::{Capability, Error, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    // Replace "eth0" with the actual name of the interface you intend to
    // change — never select the first/loopback interface for a mutation.
    let target_name = "eth0";
    let interface = lattice
        .interfaces()?
        .into_iter()
        .find(|interface| interface.name == target_name)
        .ok_or(Error::NotFound)?;

    if lattice.supports(Capability::INTERFACE_ADMIN_STATE) {
        let config = InterfaceConfig::new(interface.id, Some(DesiredAdminState::Up), None)?;
        let observed = lattice.set_interface_config(config)?;
        println!("{observed:?}");
    }
    Ok(())
}
```

When one patch asks for both MTU and administrative state, a native backend
may use separate writes. Treat errors as potentially partially applied and use
an explicit `MutationPlan` compensator if restoration is needed.

## Static neighbor mutation

`StaticNeighbor` is desired intent, distinct from the observed `NeighborEntry`:
it carries neither the synthesized `NeighborId` nor the observed
`NeighborState`, and requires a MAC address because only static L2 mappings
can be created this way. Check `Capability::NEIGHBOR_MUTATION` first. A
successful add returns the observed entry read back from the OS; removing a
present but non-`Permanent` (dynamically learned) entry is refused with
`Error::InvalidState` rather than silently evicting it.

```rust,no_run
use net_lattice::model::{IpAddress, MacAddress};
use net_lattice::mutation::StaticNeighbor;
use net_lattice::{Capability, Error, Ipv4Address, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    // Replace "eth0" with the actual name of the interface you intend to
    // change — never select the first/loopback interface for a mutation.
    let target_name = "eth0";
    let interface = lattice
        .interfaces()?
        .into_iter()
        .find(|interface| interface.name == target_name)
        .ok_or(Error::NotFound)?;

    if lattice.supports(Capability::NEIGHBOR_MUTATION) {
        let neighbor = StaticNeighbor::new(
            interface.id,
            IpAddress::from(Ipv4Address::new(192, 0, 2, 250)),
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xfa]),
        );
        let observed = lattice.add_static_neighbor(neighbor)?;
        println!("{observed:?}");
    }
    Ok(())
}
```

## Firewall policy management

`FirewallPolicy` is an ordered list of `FirewallRule`s plus a default
verdict, evaluated first-match-wins. `set_firewall_policy` replaces the
connected backend's entire managed policy atomically — there is no
incremental add/remove, unlike routes or static neighbors. `firewall_rules`
reads the policy's rules directly from the backend (a live kernel/engine
dump on every shipped backend, not a cache).

```rust,no_run
use net_lattice::model::{Direction, FirewallRule, PortRange, Protocol, Verdict};
use net_lattice::mutation::FirewallPolicy;
use net_lattice::{Capability, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    if lattice.supports(Capability::FIREWALL_MUTATION) {
        let allow_dns = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Udp)
            .with_port(PortRange::single(53));
        let policy = FirewallPolicy::new(Verdict::Deny).with_rule(allow_dns);
        lattice.set_firewall_policy(policy)?;
        println!("{:?}", lattice.firewall_rules()?);
    }
    Ok(())
}
```

See `firewall_policy` for a runnable example and
`net-lattice-backend-linux`'s `kill_switch` example for a more elaborate
usage pattern built on this same API.

## Monitoring capabilities

Select only event domains the connected backend advertises. The aggregate
`Capability::MONITORING` means all route, interface, neighbor, and address
domains are deliverable, so it is required by `watch()`. For a filtered watch,
check the matching domain capability. Windows supports route, interface, and
address notifications, but rejects neighbor and all-domain subscriptions with
`Error::Unsupported` rather than returning a stream that omits neighbors.

```rust,no_run
use net_lattice::monitoring::EventFilter;
use net_lattice::{Capability, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    if lattice.supports(Capability::ROUTE_MONITORING) {
        let _routes = lattice.watch_filtered(EventFilter::none().routes())?;
    }
    Ok(())
}
```

## Platform and privilege notes

Read-only APIs are generally unprivileged. Network mutations require the
native privileges and policy allowed by the operating system. Runtime
capabilities describe implemented surfaces, not a guarantee that the current
process is authorized. Prefer a read-after-write check when the operation's
confirmation contract requires it.
