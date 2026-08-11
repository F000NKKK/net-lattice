# Security Policy

## Supported Versions

Net Lattice follows a rolling support policy. Security fixes are provided only
for the latest stable release series. The current supported line is 0.21.x,
and support for the 0.1.x-0.20.x series has ended (see
[CHANGELOG.md](CHANGELOG.md) for what changed in 0.21.0).

| Version | Supported |
| ------- | --------- |
| 0.21.x | ✅ |
| 0.1.x - 0.20.x | ❌ |

## Reporting a Vulnerability

If you discover a security vulnerability in Net Lattice, please **do not** open a
public GitHub issue.

Instead, report it privately using [GitHub's private vulnerability reporting](https://github.com/F000NKKK/net-lattice/security/advisories/new)
feature for this repository.

Please include as much of the following information as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected versions or commits, if known
- Any suggested mitigations

We will make a best effort to acknowledge reports promptly and to keep you
informed as the issue is investigated and resolved.

## Scope

Net Lattice provides route inspection and mutation, interface inspection,
DNS resolver inspection and mutation, neighbor inspection and static ARP/NDP
neighbor mutation, interface-address inspection and mutation,
capability-gated interface configuration, and whole-system `CurrentState`
snapshot assembly (`net-lattice-platform::SnapshotProvider`,
`Lattice::current_state()`, fail-fast on the first constituent read error, no
partial result) on Linux
(`net-lattice-backend-linux`, via Netlink and `/etc/resolv.conf`), Windows
(`net-lattice-backend-windows`, via the IP Helper API), and macOS
(`net-lattice-backend-darwin`, via BSD routing sockets, `getifaddrs`, address
ioctls, and `/etc/resolv.conf`). Monitoring is bounded with explicit overflow
resynchronization: Linux observes routes, links, neighbors, and addresses via
Netlink multicast; Windows observes routes, interfaces, and unicast addresses
via IP Helper; macOS observes routes, interfaces, neighbors, and addresses via
PF_ROUTE. DNS and static-neighbor changes do not currently produce watcher
events (static-neighbor mutation is a request/response native call, not an
event subscription). The model publishes inspectable, data-only mutation
plans for route, interface-address, DNS, and static-neighbor operations,
side-effect-free `MutationPreflight` analysis, and typed `MutationOutcome`,
`MutationPlanReport`, and `RollbackStatus` contracts. The executor adds
ordered plan submission, runtime preflight, operation-boundary cancellation,
typed prior-state snapshots, phase/timing reports, and explicit reverse-order
compensation. The executor never infers inverse operations or elevates
privileges on the caller's behalf.

Route, interface-address, DNS-mutation, and static-neighbor-mutation
operations are privileged (see [ARCHITECTURE.md](ARCHITECTURE.md)'s Privilege
Model), gated by `Capability::ROUTE_MUTATION`/`NEIGHBOR_MUTATION` respectively
(`net-lattice-platform`'s `RouteMutator`/`NeighborMutator`, distinct from the
read-only `RouteProvider` — see `ARCHITECTURE.md`'s Provider trait section).
Removing a static neighbor refuses to delete a present but
non-`Permanent` (dynamically learned) entry, returning `InvalidState`, so a
removal request cannot silently evict a dynamically learned ARP/NDP cache
entry. Reports involving unintended network mutation, partial DNS
application, privilege confusion, or memory-safety issues in route,
interface, DNS, neighbor, address, or monitoring message/data handling are
in scope. Firewall, VLAN, VRF, namespace, isolated destructive topology
orchestration, and tunnel domains do not exist yet.

The model also publishes a declarative desired-state layer built on top of
the same providers above: a whole-system `DesiredState` aggregate, a pure
`Diff` computed between an observed `CurrentState` and a `DesiredState`, and
a pure `ApplyPlan` compiled from that `Diff`. Both `Diff` and `ApplyPlan` are
inspectable, side-effect-free values — computing or compiling one performs
no I/O and calls no provider or native API, so building and reviewing either
before deciding whether to act on it carries no privilege or mutation risk.
Only executing a compiled `ApplyPlan` (via the executor's plan-execution
entry point, or the facade convenience that chains snapshot, diff, compile,
and execute in one call) is privileged, and it is privileged exactly like
the underlying route, interface, DNS, neighbor, and address mutations it
lowers to — the declarative layer introduces no new privilege surface and no
new capability gate beyond the ones already covering those mutations.
Before any native call is attempted, plan execution rejects a desired field
a given backend cannot honor at all (for example, a route metric on a
backend whose native route calls never read or write it) rather than
silently building a step that can never converge. Route replacement — an
added route and a removed route that resolve to the same destination — is
sequenced per backend according to how precisely that backend's native
delete call can distinguish the old route from its replacement, always
followed by a mandatory read-after-write check confirming both that the new
route is present and that the old route is gone. If that check cannot
confirm the expected before/after state, the affected step is treated as
failed rather than assumed successful, is reported distinctly from an
ordinary native error, and is eligible for the same best-effort compensation
behavior as any other failed step in a plan. Reports involving a declarative
plan converging to an unintended state, a route replacement leaving both the
old and new route present (or neither present), silent application of a
desired field a backend cannot actually honor, or partial-apply/rollback
behavior that does not match the reported outcome are in scope.
