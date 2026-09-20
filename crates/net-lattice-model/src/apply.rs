//! The compiled, inspectable list of steps needed to converge a
//! [`CurrentState`] toward a [`DesiredState`], derived from a [`Diff`].
//!
//! [`ApplyPlan::compile`] is pure and side-effect-free, mirroring
//! [`Diff::compute`]'s own scope discipline: it reads only its `&Diff`
//! argument, performs no I/O, calls no provider/backend method, and cannot
//! know (or check) which backend will eventually execute the plan. Deciding
//! *whether* a step is acceptable for a specific backend (capability-aware
//! rejection) and actually executing a plan are later stages' concerns.
//!
//! [`CurrentState`]: crate::snapshot::CurrentState
//! [`DesiredState`]: crate::desired_state::DesiredState

use std::collections::HashMap;

use net_lattice_core::Error;

use crate::address::Network;
use crate::diff::{AddressChange, Diff, NeighborChange, RouteChange};
use crate::interface::InterfaceId;
use crate::mac::MacAddress;
use crate::mutation::{
    Mutation, MutationConfirmation, MutationIdempotency, MutationKind, MutationOperationReport,
    MutationPrecondition, MutationPrivilege, MutationReversibility, MutationSemantics,
    RollbackStatus,
};
use crate::neighbor::{NeighborEntry, StaticNeighbor};
use crate::route::{Route, RouteConfig};

/// An ordered, inspectable list of steps compiled from a [`Diff`].
///
/// Compiling a plan has no side effects. Executing it (submitting the
/// underlying native operations, honoring [`ApplyStep::ReplaceRoute`]'s
/// internal ordering and read-after-write/compensation contract) is a later
/// stage's concern, out of this crate's scope entirely — mirroring how
/// [`crate::mutation::MutationPlan`] is itself only ever constructed and
/// inspected here.
///
/// `#[non_exhaustive]`: a later stage may add a field without this being a
/// breaking change for callers who do not construct an `ApplyPlan` via a
/// struct literal, matching [`Diff`]/[`crate::snapshot::CurrentState`]/
/// [`crate::desired_state::DesiredState`]'s own rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApplyPlan {
    steps: Vec<ApplyStep>,
}

/// One compiled unit of work in an [`ApplyPlan`].
///
/// `#[non_exhaustive]`: a later stage may add a variant (e.g. a dedicated
/// replace step for another domain, should one ever need per-backend
/// ordering the way routes do) without breaking callers who don't match
/// exhaustively, matching [`crate::mutation::Mutation`]'s own convention.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyStep {
    /// A single mutation with no replacement pairing: interface, neighbor,
    /// address, DNS, and any route `Added`/`Removed` entry with no matching
    /// counterpart at the same destination (see [`ApplyPlan::compile`]).
    Single(Mutation),
    /// A destination-paired route replacement: the observed route `old` is
    /// removed and the desired route `new` is added, treated as one logical
    /// unit whose internal ordering, mandatory read-after-write
    /// verification, and fail-closed/best-effort-compensation behavior are
    /// execution-time concerns this type only carries the data for.
    ReplaceRoute {
        /// The observed route being replaced.
        old: Route,
        /// The desired replacement.
        new: RouteConfig,
    },
}

impl ApplyStep {
    /// Returns the static contract of this step's native operation.
    ///
    /// [`Self::Single`] delegates to [`Mutation::semantics`] unchanged.
    /// [`Self::ReplaceRoute`] synthesizes a `Replace`-flavored contract no
    /// single [`Mutation`] variant expresses alone: mandatory read-after-write
    /// confirmation, compensation that requires the captured prior route, and
    /// a partial-application risk (the remove may succeed while the add
    /// fails, or vice versa).
    pub const fn semantics(&self) -> MutationSemantics {
        match self {
            Self::Single(mutation) => mutation.semantics(),
            Self::ReplaceRoute { .. } => MutationSemantics {
                kind: MutationKind::ReplaceRoute,
                precondition: MutationPrecondition::Any,
                idempotency: MutationIdempotency::Replace,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::ReadAfterWrite,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: true,
            },
        }
    }
}

/// The result recorded for one [`ApplyStep`] in an executed [`ApplyPlan`].
///
/// This mirrors [`crate::mutation::MutationOutcome`]'s shape but adds two
/// outcomes that no [`crate::mutation::MutationOutcome`] variant can
/// distinguish: a capability-aware rejection decided before any native call
/// was attempted, and a native call that completed without confirming the
/// resulting state matched what was requested. Constructing or inspecting
/// this type never changes operating-system state.
///
/// `#[non_exhaustive]`: a later stage may add an outcome without breaking
/// callers who don't match exhaustively, matching
/// [`crate::mutation::MutationOutcome`]'s own convention.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyStepOutcome {
    /// The step's native operation(s) completed and, for
    /// [`ApplyStep::ReplaceRoute`], read-after-write confirmed the expected
    /// end state.
    Applied,
    /// A native operation returned an error.
    Failed {
        /// Backend error returned by the operation.
        error: Error,
        /// Whether the operation may have changed state before failing. For
        /// [`ApplyStep::ReplaceRoute`], this reflects exactly which leg of
        /// the replacement completed before the failing leg was attempted.
        may_have_applied: bool,
    },
    /// The executor did not attempt this step because an earlier step
    /// failed, was rejected, or execution was cancelled.
    NotAttempted,
    /// Rejected before any native call was attempted, because the
    /// connected backend cannot honor a field this step's replacement
    /// requires (for example, a route metric change on a backend whose
    /// native route calls never read or write metric).
    Rejected {
        /// The rejection error.
        error: Error,
    },
    /// A native call reported success but the expected end state could not
    /// be confirmed by a subsequent read, or a precondition this step
    /// required no longer held when re-checked immediately before
    /// execution. Distinguishes non-convergence — an operation that was
    /// attempted but whose effect on observed state is unconfirmed or
    /// blocked — from an ordinary native failure ([`Self::Failed`]).
    NonConvergent {
        /// Why this step's outcome could not be confirmed as convergent.
        reason: NonConvergentReason,
    },
}

/// Why an [`ApplyStepOutcome::NonConvergent`] outcome was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NonConvergentReason {
    /// The precondition snapshot this step depended on (the observed route
    /// being replaced, for [`ApplyStep::ReplaceRoute`]) no longer matched
    /// when re-checked immediately before execution.
    StalePrecondition,
    /// Read-after-write could not confirm both halves of a
    /// [`ApplyStep::ReplaceRoute`] replacement: the desired route present
    /// and the observed route it replaces absent.
    AmbiguousReplacementUnverifiable,
}

/// Executor report for an ordered [`ApplyPlan`].
///
/// Mirrors [`crate::mutation::MutationPlanReport`]'s shape and accessor set:
/// the outcome at index `n` corresponds to [`ApplyPlan::step`]`(n)`, one
/// outcome is recorded per [`ApplyStep`] (a [`ApplyStep::ReplaceRoute`]'s two
/// native calls are reported as one logical unit, not two), and
/// [`RollbackStatus`]/[`MutationOperationReport`]/
/// [`crate::mutation::MutationExecutionPhase`] are reused unchanged rather
/// than duplicated for this report family.
#[derive(Debug)]
pub struct ApplyPlanReport {
    outcomes: Vec<ApplyStepOutcome>,
    rollback: RollbackStatus,
    operation_reports: Vec<MutationOperationReport>,
}

impl ApplyPlanReport {
    /// Creates a report for outcomes in the plan's declared order.
    pub fn new(
        outcomes: impl IntoIterator<Item = ApplyStepOutcome>,
        rollback: RollbackStatus,
    ) -> Self {
        let outcomes: Vec<_> = outcomes.into_iter().collect();
        Self {
            operation_reports: vec![MutationOperationReport::not_attempted(); outcomes.len()],
            outcomes,
            rollback,
        }
    }

    /// Creates a report with phase and timing metadata aligned to outcomes.
    pub fn with_operation_reports(
        outcomes: impl IntoIterator<Item = ApplyStepOutcome>,
        rollback: RollbackStatus,
        operation_reports: impl IntoIterator<Item = MutationOperationReport>,
    ) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            rollback,
            operation_reports: operation_reports.into_iter().collect(),
        }
    }

    /// Returns one outcome for each step attempted or skipped.
    pub fn outcomes(&self) -> &[ApplyStepOutcome] {
        &self.outcomes
    }

    /// Returns the outcome at a plan-local step index, if present.
    pub fn outcome(&self, index: usize) -> Option<&ApplyStepOutcome> {
        self.outcomes.get(index)
    }

    /// Returns the number of recorded outcomes.
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    /// Whether no outcomes have been recorded.
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// Returns the rollback status recorded by the executor.
    pub fn rollback(&self) -> &RollbackStatus {
        &self.rollback
    }

    /// Returns phase and timing metadata aligned with [`Self::outcomes`].
    pub fn operation_reports(&self) -> &[MutationOperationReport] {
        &self.operation_reports
    }

    /// Returns phase and timing metadata for one plan-local step.
    pub fn operation_report(&self, index: usize) -> Option<&MutationOperationReport> {
        self.operation_reports.get(index)
    }

    /// Whether every recorded step was applied successfully.
    pub fn is_success(&self) -> bool {
        self.outcomes
            .iter()
            .all(|outcome| matches!(outcome, ApplyStepOutcome::Applied))
    }

    /// Number of steps recorded as applied.
    pub fn applied_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ApplyStepOutcome::Applied))
            .count()
    }

    /// Number of steps the executor did not attempt.
    pub fn not_attempted_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ApplyStepOutcome::NotAttempted))
            .count()
    }

    /// Number of steps rejected before any native call was attempted.
    pub fn rejected_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ApplyStepOutcome::Rejected { .. }))
            .count()
    }

    /// Number of steps recorded as non-convergent.
    pub fn non_convergent_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ApplyStepOutcome::NonConvergent { .. }))
            .count()
    }
}

impl ApplyPlan {
    /// Compiles a [`Diff`] into an [`ApplyPlan`].
    ///
    /// Pure and side-effect-free: reads only `diff`, performs no I/O, calls
    /// no provider/backend method, and cannot fail — every branch this
    /// function can reach is provably safe from the shape [`Diff::compute`]
    /// guarantees for its output (see the per-domain notes below).
    ///
    /// Per-domain lowering:
    /// - `routes`: grouped by destination (see the module's destination-
    ///   grouping algorithm); exactly one `Added` and one `Removed` entry at
    ///   the same destination compile to one [`ApplyStep::ReplaceRoute`]; any
    ///   other count at that destination (zero, or multipath — two or more of
    ///   either) compiles to independent [`ApplyStep::Single`] steps, one per
    ///   entry, in `diff.routes`'s original order.
    /// - `interfaces`: each [`crate::diff::InterfaceDiff`] compiles to one
    ///   `Single(Mutation::SetInterfaceConfig(patch))`, where `patch`
    ///   forwards only the fields the `InterfaceDiff` actually populated —
    ///   a field that was never requested (or already matched) is never
    ///   resent, preserving [`crate::interface::InterfaceConfig`]'s
    ///   "don't touch" contract end to end.
    /// - `neighbors`/`addresses`: `Added`/`Removed` map 1:1 to
    ///   `Single(Add.../Remove...)`; `Changed` compiles to two steps, a
    ///   `Single(Remove...)` immediately followed by a `Single(Add...)` —
    ///   remove-then-add is the only order compatible with
    ///   [`Mutation::AddStaticNeighbor`]/[`Mutation::AddAddress`]'s existing
    ///   `Absent` precondition.
    /// - `dns`: `Some(change)` compiles to one
    ///   `Single(Mutation::SetDnsConfig(change.desired))`; `None` compiles to
    ///   no step at all.
    ///
    /// An unmanaged or already-matching [`Diff`] (every field empty/`None`)
    /// compiles to an empty `ApplyPlan`.
    pub fn compile(diff: &Diff) -> ApplyPlan {
        let mut steps = compile_routes(&diff.routes);

        for interface_diff in &diff.interfaces {
            let patch = crate::interface::InterfaceConfig::new(
                interface_diff.interface_id,
                interface_diff
                    .admin_state
                    .as_ref()
                    .map(|change| change.desired),
                interface_diff.mtu.as_ref().map(|change| change.desired),
            )
            .expect(
                "InterfaceDiff invariant: at least one field populated with a non-zero mtu — \
                 enforced by Diff::compute and the source InterfaceConfig",
            );
            steps.push(ApplyStep::Single(Mutation::SetInterfaceConfig(patch)));
        }

        for neighbor_change in &diff.neighbors {
            match neighbor_change {
                NeighborChange::Added(desired) => {
                    steps.push(ApplyStep::Single(Mutation::AddStaticNeighbor(*desired)));
                }
                NeighborChange::Removed(entry) => {
                    steps.push(ApplyStep::Single(Mutation::RemoveStaticNeighbor(
                        static_neighbor_from_entry(entry),
                    )));
                }
                NeighborChange::Changed { current, desired } => {
                    steps.push(ApplyStep::Single(Mutation::RemoveStaticNeighbor(
                        static_neighbor_from_entry(current),
                    )));
                    steps.push(ApplyStep::Single(Mutation::AddStaticNeighbor(*desired)));
                }
            }
        }

        for address_change in &diff.addresses {
            match address_change {
                AddressChange::Added(desired) => {
                    steps.push(ApplyStep::Single(Mutation::AddAddress(desired.clone())));
                }
                AddressChange::Removed(observed) => {
                    steps.push(ApplyStep::Single(Mutation::RemoveAddress(observed.clone())));
                }
                AddressChange::Changed { current, desired } => {
                    steps.push(ApplyStep::Single(Mutation::RemoveAddress(current.clone())));
                    steps.push(ApplyStep::Single(Mutation::AddAddress(desired.clone())));
                }
            }
        }

        if let Some(dns_change) = &diff.dns {
            steps.push(ApplyStep::Single(Mutation::SetDnsConfig(
                dns_change.desired.clone(),
            )));
        }

        if let Some(firewall_change) = &diff.firewall {
            steps.push(ApplyStep::Single(Mutation::SetFirewallPolicy(
                firewall_change.desired.clone(),
            )));
        }

        ApplyPlan { steps }
    }

    /// Creates a plan from steps in execution order.
    pub fn from_steps(steps: impl IntoIterator<Item = ApplyStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
        }
    }

    /// Returns the steps in their declared order.
    pub fn steps(&self) -> &[ApplyStep] {
        &self.steps
    }

    /// Returns the step at `index`, if present.
    pub fn step(&self, index: usize) -> Option<&ApplyStep> {
        self.steps.get(index)
    }

    /// Number of steps in the plan.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the plan has no steps.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

impl IntoIterator for ApplyPlan {
    type Item = ApplyStep;
    type IntoIter = std::vec::IntoIter<ApplyStep>;

    fn into_iter(self) -> Self::IntoIter {
        self.steps.into_iter()
    }
}

/// The destination this [`RouteChange`] would occupy.
fn route_change_destination(change: &RouteChange) -> Network {
    match change {
        RouteChange::Added(config) => config.destination,
        RouteChange::Removed(route) => route.destination,
    }
}

/// Converts an observed [`Route`] into the [`RouteConfig`] a
/// [`Mutation::RemoveRoute`] needs, carrying forward only the fields the
/// observed route actually populated.
fn route_config_from_route(route: &Route) -> RouteConfig {
    let mut config = RouteConfig::new(route.destination);
    if let Some(gateway) = route.gateway {
        config = config.with_gateway(gateway);
    }
    if let Some(metric) = route.metric {
        config = config.with_metric(metric);
    }
    if let Some(interface_index) = route.interface_index {
        config = config.with_interface_index(interface_index);
    }
    config
}

/// Lowers one unpaired [`RouteChange`] to an independent [`Mutation`].
fn single_route_mutation(change: &RouteChange) -> Mutation {
    match change {
        RouteChange::Added(config) => Mutation::AddRoute(*config),
        RouteChange::Removed(route) => Mutation::RemoveRoute(route_config_from_route(route)),
    }
}

/// Reconstructs the [`StaticNeighbor`] a [`Mutation::RemoveStaticNeighbor`]
/// needs from an observed [`NeighborEntry`].
///
/// Every backend's `remove_static_neighbor` matches solely on
/// `(interface_id, address)` and never inspects `mac` when deleting (`mac` is
/// used only by `add_static_neighbor`), so a `None` observed `mac` (an entry
/// still being resolved) is filled with the all-zero placeholder rather than
/// threading an `Option`/failure path through this otherwise-infallible
/// function for a field the removal path structurally ignores.
fn static_neighbor_from_entry(entry: &NeighborEntry) -> StaticNeighbor {
    StaticNeighbor::new(
        InterfaceId::new(u64::from(entry.interface_index)),
        entry.address,
        entry
            .mac
            .unwrap_or_else(|| MacAddress::new([0, 0, 0, 0, 0, 0])),
    )
}

/// Groups `changes` by destination and pairs each destination with exactly
/// one `Added` and one `Removed` entry into an [`ApplyStep::ReplaceRoute`];
/// every other destination (zero, or multipath — two or more of either)
/// falls back to independent [`ApplyStep::Single`] steps, never treated as a
/// replacement candidate. Preserves `changes`'s original order for
/// deterministic step emission.
fn compile_routes(changes: &[RouteChange]) -> Vec<ApplyStep> {
    let mut by_destination: HashMap<Network, (Vec<usize>, Vec<usize>)> = HashMap::new();
    for (index, change) in changes.iter().enumerate() {
        let destination = route_change_destination(change);
        let entry = by_destination.entry(destination).or_default();
        match change {
            RouteChange::Added(_) => entry.0.push(index),
            RouteChange::Removed(_) => entry.1.push(index),
        }
    }

    let mut steps = Vec::with_capacity(changes.len());
    let mut consumed = vec![false; changes.len()];
    for (index, change) in changes.iter().enumerate() {
        if consumed[index] {
            continue;
        }
        let (added, removed) = &by_destination[&route_change_destination(change)];
        if added.len() == 1 && removed.len() == 1 {
            let (new_index, old_index) = (added[0], removed[0]);
            let RouteChange::Added(new_config) = &changes[new_index] else {
                unreachable!("by_destination.0 only ever indexes RouteChange::Added entries");
            };
            let RouteChange::Removed(old_route) = &changes[old_index] else {
                unreachable!("by_destination.1 only ever indexes RouteChange::Removed entries");
            };
            steps.push(ApplyStep::ReplaceRoute {
                old: old_route.clone(),
                new: *new_config,
            });
            consumed[new_index] = true;
            consumed[old_index] = true;
        } else {
            for &idx in added.iter().chain(removed.iter()) {
                if !consumed[idx] {
                    steps.push(ApplyStep::Single(single_route_mutation(&changes[idx])));
                    consumed[idx] = true;
                }
            }
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpAddress;
    use crate::desired_state::DesiredState;
    use crate::diff::{Change, DnsChange, InterfaceDiff};
    use crate::dns::{DnsConfig, NewDnsConfig};
    use crate::ifaddr::{InterfaceAddress, InterfaceAddressId, NewInterfaceAddress};
    use crate::interface::{AdminState, DesiredAdminState, Interface, InterfaceKind};
    use crate::neighbor::NeighborId;
    use crate::route::RouteId;
    use crate::snapshot::CurrentState;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

    fn network(octet: u8) -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, octet),
            Ipv4PrefixLength::new(32).expect("valid prefix"),
        ))
    }

    fn empty_diff() -> Diff {
        Diff {
            routes: Vec::new(),
            interfaces: Vec::new(),
            neighbors: Vec::new(),
            addresses: Vec::new(),
            dns: None,
            firewall: None,
        }
    }

    // ---- empty/unmanaged diff ----

    #[test]
    fn empty_diff_compiles_to_empty_plan() {
        let plan = ApplyPlan::compile(&empty_diff());
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert!(plan.steps().is_empty());
    }

    #[test]
    fn unmanaged_diff_from_compute_compiles_to_empty_plan() {
        let current = CurrentState::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DnsConfig::new(),
            Vec::new(),
        );
        let desired = DesiredState::empty();
        let diff = Diff::compute(&current, &desired);
        let plan = ApplyPlan::compile(&diff);
        assert!(plan.is_empty());
    }

    // ---- routes: destination-grouping algorithm ----

    #[test]
    fn matched_pair_at_one_destination_compiles_to_one_replace_route() {
        let old = Route::new(RouteId::new(1), network(0)).with_interface_index(1);
        let new = RouteConfig::new(network(0)).with_interface_index(2);
        let diff = Diff {
            routes: vec![RouteChange::Removed(old.clone()), RouteChange::Added(new)],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.step(0), Some(&ApplyStep::ReplaceRoute { old, new }));
    }

    #[test]
    fn unmatched_bare_added_produces_an_independent_single_step() {
        let new = RouteConfig::new(network(0));
        let diff = Diff {
            routes: vec![RouteChange::Added(new)],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::AddRoute(new)))
        );
    }

    #[test]
    fn unmatched_bare_removed_produces_an_independent_single_step() {
        let old = Route::new(RouteId::new(1), network(0))
            .with_gateway(IpAddress::from(Ipv4Address::new(192, 0, 2, 254)));
        let diff = Diff {
            routes: vec![RouteChange::Removed(old.clone())],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::RemoveRoute(
                route_config_from_route(&old)
            )))
        );
    }

    #[test]
    fn multipath_destination_with_two_added_never_produces_a_replace_route() {
        // Two Added entries at the same destination (multipath): neither may
        // be treated as a replacement candidate, even though zero Removed
        // entries exist at that destination.
        let first = RouteConfig::new(network(0)).with_interface_index(1);
        let second = RouteConfig::new(network(0)).with_interface_index(2);
        let diff = Diff {
            routes: vec![RouteChange::Added(first), RouteChange::Added(second)],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 2);
        assert!(
            plan.steps()
                .iter()
                .all(|step| matches!(step, ApplyStep::Single(Mutation::AddRoute(_))))
        );
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::AddRoute(first)))
        );
        assert_eq!(
            plan.step(1),
            Some(&ApplyStep::Single(Mutation::AddRoute(second)))
        );
    }

    #[test]
    fn multipath_destination_with_two_added_and_two_removed_never_produces_a_replace_route() {
        let old_a = Route::new(RouteId::new(1), network(0)).with_interface_index(1);
        let old_b = Route::new(RouteId::new(2), network(0)).with_interface_index(2);
        let new_a = RouteConfig::new(network(0)).with_interface_index(3);
        let new_b = RouteConfig::new(network(0)).with_interface_index(4);
        let diff = Diff {
            routes: vec![
                RouteChange::Removed(old_a.clone()),
                RouteChange::Removed(old_b.clone()),
                RouteChange::Added(new_a),
                RouteChange::Added(new_b),
            ],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 4);
        assert!(
            plan.steps()
                .iter()
                .all(|step| matches!(step, ApplyStep::Single(_)))
        );
    }

    #[test]
    fn route_grouping_preserves_original_order_for_independent_steps() {
        let unrelated_added = RouteConfig::new(network(1));
        let old = Route::new(RouteId::new(1), network(0));
        let new = RouteConfig::new(network(0)).with_metric(9);
        let diff = Diff {
            routes: vec![
                RouteChange::Added(unrelated_added),
                RouteChange::Removed(old.clone()),
                RouteChange::Added(new),
            ],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        // unrelated_added (destination 1) stays independent; old/new
        // (destination 0) pair into one ReplaceRoute, emitted at the
        // position of the first unconsumed entry sharing that destination.
        assert_eq!(plan.len(), 2);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::AddRoute(unrelated_added)))
        );
        assert_eq!(plan.step(1), Some(&ApplyStep::ReplaceRoute { old, new }));
    }

    // ---- routes: ApplyStep::semantics ----

    #[test]
    fn single_route_step_semantics_delegates_to_mutation_semantics() {
        let config = RouteConfig::new(network(0));
        let step = ApplyStep::Single(Mutation::AddRoute(config));
        assert_eq!(step.semantics(), Mutation::AddRoute(config).semantics());
    }

    #[test]
    fn replace_route_step_semantics_synthesizes_a_replace_contract() {
        let old = Route::new(RouteId::new(1), network(0));
        let new = RouteConfig::new(network(0)).with_metric(1);
        let step = ApplyStep::ReplaceRoute { old, new };
        let semantics = step.semantics();
        assert_eq!(semantics.kind, MutationKind::ReplaceRoute);
        assert_eq!(semantics.precondition, MutationPrecondition::Any);
        assert_eq!(semantics.idempotency, MutationIdempotency::Replace);
        assert_eq!(semantics.privilege, MutationPrivilege::Elevated);
        assert_eq!(semantics.confirmation, MutationConfirmation::ReadAfterWrite);
        assert_eq!(
            semantics.reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(semantics.may_partially_apply);
    }

    // ---- interfaces ----

    #[test]
    fn interface_diff_compiles_to_set_interface_config_forwarding_only_populated_fields() {
        let diff = Diff {
            interfaces: vec![InterfaceDiff {
                interface_id: InterfaceId::new(1),
                admin_state: Some(Change {
                    current: AdminState::Down,
                    desired: DesiredAdminState::Up,
                }),
                mtu: None,
            }],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 1);
        let ApplyStep::Single(Mutation::SetInterfaceConfig(patch)) = plan.step(0).unwrap() else {
            panic!("expected a SetInterfaceConfig step");
        };
        assert_eq!(patch.interface_id(), InterfaceId::new(1));
        assert_eq!(patch.admin_state(), Some(DesiredAdminState::Up));
        // mtu was never requested/differing on the InterfaceDiff: it must
        // never be forwarded onto the compiled InterfaceConfig either,
        // preserving the "don't touch" contract end to end.
        assert_eq!(patch.mtu(), None);
    }

    #[test]
    fn interface_diff_with_both_fields_forwards_both() {
        let diff = Diff {
            interfaces: vec![InterfaceDiff {
                interface_id: InterfaceId::new(1),
                admin_state: Some(Change {
                    current: AdminState::Down,
                    desired: DesiredAdminState::Up,
                }),
                mtu: Some(Change {
                    current: 1500,
                    desired: 9000,
                }),
            }],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        let ApplyStep::Single(Mutation::SetInterfaceConfig(patch)) = plan.step(0).unwrap() else {
            panic!("expected a SetInterfaceConfig step");
        };
        assert_eq!(patch.admin_state(), Some(DesiredAdminState::Up));
        assert_eq!(patch.mtu(), Some(9000));
    }

    #[test]
    fn interface_diff_via_diff_compute_end_to_end_never_forwards_unrequested_fields() {
        let interface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet)
            .with_admin_state(AdminState::Down)
            .with_mtu(1500);
        let config = crate::interface::InterfaceConfig::new(
            InterfaceId::new(1),
            Some(DesiredAdminState::Up),
            None,
        )
        .expect("valid patch");
        let current = CurrentState {
            interfaces: vec![interface],
            ..CurrentState::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                DnsConfig::new(),
                Vec::new(),
            )
        };
        let desired = DesiredState::empty().with_interfaces(vec![config]);
        let diff = Diff::compute(&current, &desired);
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 1);
        let ApplyStep::Single(Mutation::SetInterfaceConfig(patch)) = plan.step(0).unwrap() else {
            panic!("expected a SetInterfaceConfig step");
        };
        assert_eq!(patch.mtu(), None);
    }

    // ---- neighbors ----

    fn neighbor_address() -> IpAddress {
        IpAddress::from(Ipv4Address::new(192, 0, 2, 1))
    }

    #[test]
    fn neighbor_added_compiles_to_add_static_neighbor() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let desired = StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac);
        let diff = Diff {
            neighbors: vec![NeighborChange::Added(desired)],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::AddStaticNeighbor(desired)))
        );
    }

    #[test]
    fn neighbor_removed_compiles_to_remove_static_neighbor() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let entry = NeighborEntry::new(NeighborId::new(1), 1, neighbor_address()).with_mac(mac);
        let diff = Diff {
            neighbors: vec![NeighborChange::Removed(entry)],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::RemoveStaticNeighbor(
                StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac)
            )))
        );
    }

    #[test]
    fn neighbor_changed_compiles_to_remove_then_add_in_that_order() {
        let mac_a = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mac_b = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let current = NeighborEntry::new(NeighborId::new(1), 1, neighbor_address()).with_mac(mac_a);
        let desired = StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac_b);
        let diff = Diff {
            neighbors: vec![NeighborChange::Changed { current, desired }],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::RemoveStaticNeighbor(
                StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac_a)
            )))
        );
        assert_eq!(
            plan.step(1),
            Some(&ApplyStep::Single(Mutation::AddStaticNeighbor(desired)))
        );
    }

    // ---- addresses ----

    #[test]
    fn address_added_compiles_to_add_address() {
        let desired = NewInterfaceAddress::new(InterfaceId::new(1), network(0));
        let diff = Diff {
            addresses: vec![AddressChange::Added(desired.clone())],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::AddAddress(desired)))
        );
    }

    #[test]
    fn address_removed_compiles_to_remove_address() {
        let observed = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network(0));
        let diff = Diff {
            addresses: vec![AddressChange::Removed(observed.clone())],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::RemoveAddress(observed)))
        );
    }

    #[test]
    fn address_changed_compiles_to_remove_then_add_in_that_order() {
        let current = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network(0))
            .with_broadcast(IpAddress::from(Ipv4Address::new(192, 0, 2, 255)));
        let desired = NewInterfaceAddress::new(InterfaceId::new(1), network(0))
            .with_broadcast(Ipv4Address::new(192, 0, 2, 254));
        let diff = Diff {
            addresses: vec![AddressChange::Changed {
                current: current.clone(),
                desired: desired.clone(),
            }],
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::RemoveAddress(current)))
        );
        assert_eq!(
            plan.step(1),
            Some(&ApplyStep::Single(Mutation::AddAddress(desired)))
        );
    }

    // ---- dns ----

    #[test]
    fn dns_change_compiles_to_set_dns_config() {
        let current = DnsConfig::new();
        let desired = NewDnsConfig::with(
            vec![IpAddress::from(Ipv4Address::new(1, 1, 1, 1))],
            Vec::new(),
        );
        let diff = Diff {
            dns: Some(DnsChange {
                current,
                desired: desired.clone(),
            }),
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::SetDnsConfig(desired)))
        );
    }

    #[test]
    fn dns_none_produces_no_step() {
        let diff = Diff {
            dns: None,
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert!(plan.is_empty());
    }

    // ---- firewall ----

    #[test]
    fn firewall_change_compiles_to_set_firewall_policy() {
        let desired_policy = crate::firewall::FirewallPolicy::new(crate::firewall::Verdict::Allow);
        let diff = Diff {
            firewall: Some(crate::diff::FirewallChange {
                current: Vec::new(),
                desired: desired_policy.clone(),
            }),
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert_eq!(
            plan.step(0),
            Some(&ApplyStep::Single(Mutation::SetFirewallPolicy(
                desired_policy
            )))
        );
    }

    #[test]
    fn firewall_none_produces_no_step() {
        let diff = Diff {
            firewall: None,
            ..empty_diff()
        };
        let plan = ApplyPlan::compile(&diff);
        assert!(plan.is_empty());
    }

    // ---- from_steps / iteration ----

    #[test]
    fn from_steps_and_into_iter_round_trip_declared_order() {
        let first = ApplyStep::Single(Mutation::AddRoute(RouteConfig::new(network(0))));
        let second = ApplyStep::Single(Mutation::RemoveRoute(RouteConfig::new(network(1))));
        let plan = ApplyPlan::from_steps([first.clone(), second.clone()]);
        assert_eq!(plan.steps(), [first.clone(), second.clone()]);
        assert_eq!(plan.into_iter().collect::<Vec<_>>(), vec![first, second]);
    }

    // ---- ApplyPlanReport ----

    #[test]
    fn apply_plan_report_counts_every_outcome_kind() {
        let report = ApplyPlanReport::new(
            [
                ApplyStepOutcome::Applied,
                ApplyStepOutcome::Failed {
                    error: Error::PermissionDenied,
                    may_have_applied: true,
                },
                ApplyStepOutcome::NotAttempted,
                ApplyStepOutcome::Rejected {
                    error: Error::Unsupported,
                },
                ApplyStepOutcome::NonConvergent {
                    reason: NonConvergentReason::StalePrecondition,
                },
            ],
            RollbackStatus::NotAttempted,
        );

        assert!(!report.is_success());
        assert_eq!(report.len(), 5);
        assert!(!report.is_empty());
        assert_eq!(report.applied_count(), 1);
        assert_eq!(report.not_attempted_count(), 1);
        assert_eq!(report.rejected_count(), 1);
        assert_eq!(report.non_convergent_count(), 1);
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
        assert_eq!(report.operation_reports().len(), 5);
        assert!(report.operation_report(4).is_some());
        assert!(report.outcome(5).is_none());
        assert!(matches!(
            report.outcome(1),
            Some(ApplyStepOutcome::Failed {
                may_have_applied: true,
                ..
            })
        ));
    }

    #[test]
    fn apply_plan_report_with_operation_reports_preserves_supplied_metadata() {
        let operation_reports = [
            MutationOperationReport {
                phase: crate::mutation::MutationExecutionPhase::Execution,
                duration: std::time::Duration::from_millis(3),
                stop_reason: None,
            },
            MutationOperationReport::not_attempted(),
        ];
        let report = ApplyPlanReport::with_operation_reports(
            [ApplyStepOutcome::Applied, ApplyStepOutcome::NotAttempted],
            RollbackStatus::NotNeeded,
            operation_reports,
        );

        assert!(!report.is_success());
        assert_eq!(report.applied_count(), 1);
        assert_eq!(report.not_attempted_count(), 1);
        assert_eq!(report.operation_reports(), operation_reports);
    }

    #[test]
    fn apply_plan_report_all_applied_is_success() {
        let report = ApplyPlanReport::new(
            [ApplyStepOutcome::Applied, ApplyStepOutcome::Applied],
            RollbackStatus::NotNeeded,
        );
        assert!(report.is_success());
        assert_eq!(report.applied_count(), 2);
        assert_eq!(report.rejected_count(), 0);
        assert_eq!(report.non_convergent_count(), 0);
    }
}
