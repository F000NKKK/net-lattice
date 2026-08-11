# Support

Thank you for your interest in Net Lattice.

## Getting Help

- **Questions and discussion:** Use [GitHub Discussions](https://github.com/F000NKKK/net-lattice/discussions) for general questions, ideas, and design discussion.
- **Bug reports and feature requests:** Use [GitHub Issues](https://github.com/F000NKKK/net-lattice/issues) with the appropriate issue template.
- **Security issues:** See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Do not report security issues via public issues or discussions.

## Project Status

Net Lattice provides cross-platform network inspection, route, interface,
interface-address, DNS resolver, and static ARP/NDP neighbor mutation,
interface administrative-state and MTU configuration, inspectable data-only
mutation plans, side-effect-free preflight analysis, ordered transaction
execution with runtime preflight, operation-boundary cancellation, typed
prior-state snapshots, phase/timing reports and explicit compensation, bounded
object/domain-filterable monitoring with optional native async event
delivery, and whole-system `CurrentState` snapshot assembly
(`net-lattice-model::CurrentState`, `net-lattice-platform::SnapshotProvider`,
`Lattice::current_state()`) aggregating routes, interfaces, neighbors,
interface addresses, and DNS configuration in one fail-fast call with no
partial result. `RouteProvider`/`RouteMutator` and every other domain follow
the same read-only provider / mutator pattern, gated by explicit
`Capability` flags. `InterfaceConfig` remains a partial imperative patch, but
a declarative desired-state layer now sits alongside it: `DesiredState`
expresses whole-system intent, `Diff::compute` computes a pure, side-effect-
free difference against an observed `CurrentState`, `ApplyPlan::compile`
compiles that difference into a pure, inspectable plan (including
backend-aware route-replacement ordering), and `Lattice::execute_apply_plan`/
`Lattice::apply` execute that plan against the connected backend, reporting
convergence, non-convergence, and capability-aware rejection distinctly.
This surface is verified by privileged Linux, Windows, and macOS CI and is
part of the published support surface. Alongside the uniform `Capability`
tier, an explicitly opt-in Addition tier now covers non-native, disjoint
capabilities that never merge into `Capability`'s cross-backend-uniform
meaning: `net-lattice-platform::{Addition, AdditionProvider}` describe them,
`Lattice::watch_with_additions` activates requested `Addition`s alongside
`watch_filtered`'s domain filtering and fans their synthesized events into
the same merged receiver, and this release ships one concrete instance,
Windows neighbor-monitoring-via-polling
(`Addition::NEIGHBOR_MONITORING_POLLING`), as an opt-in substitute where
native neighbor-change monitoring is still unavailable on that platform.
This release also completed the pre-1.0 API freeze and hardening pass:
the public surface is now frozen, the platform-support-matrix and event-
delivery-guarantee documentation is consolidated, and privileged regression
coverage is complete across all three backends. See [README.md](README.md)'s
Current Status for the full capability matrix; questions about usage,
direction, and design are all welcome.
