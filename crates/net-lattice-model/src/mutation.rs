//! Typed, inspectable descriptions of imperative network mutations.
//!
//! These types describe work and its execution report. The model remains
//! operating-system independent; the facade's Stage 0.15 executor consumes a
//! [`MutationPlan`] only after the caller has inspected each operation's
//! preconditions and limits.

use std::time::Duration;

use crate::dns::DnsConfig;
use crate::dns::NewDnsConfig;
use crate::firewall::{FirewallPolicy, FirewallRule};
use crate::ifaddr::{InterfaceAddress, NewInterfaceAddress};
use crate::interface::{Interface, InterfaceConfig};
use crate::neighbor::{NeighborEntry, StaticNeighbor};
use crate::route::{Route, RouteConfig};
use net_lattice_core::Error;

/// One existing imperative network mutation expressed as data.
///
/// Operations deliberately use the same input types accepted by today's
/// provider methods. Stage 0.14 makes their current semantics inspectable;
/// later stages may add more specific intent types where an observed type is
/// still being used as a mutation input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mutation {
    /// Adds a route using the route's currently supported defining fields.
    AddRoute(RouteConfig),
    /// Removes a route according to the backend's current matching rules.
    RemoveRoute(RouteConfig),
    /// Assigns an interface address.
    AddAddress(NewInterfaceAddress),
    /// Removes an observed interface address.
    RemoveAddress(InterfaceAddress),
    /// Replaces the portable resolver configuration.
    SetDnsConfig(NewDnsConfig),
    /// Applies a partial desired configuration to one network interface.
    ///
    /// The requested MTU and administrative state can require separate native
    /// writes, so callers must treat a failure as potentially partially
    /// applied and re-read the observed interface state.
    SetInterfaceConfig(InterfaceConfig),
    /// Adds a static ARP/NDP neighbor entry.
    AddStaticNeighbor(StaticNeighbor),
    /// Removes a static ARP/NDP neighbor entry.
    ///
    /// The backend must confirm the target is presently a `Permanent`
    /// (static) entry before removal; a non-permanent matching entry is
    /// rejected rather than silently deleting dynamically learned state.
    RemoveStaticNeighbor(StaticNeighbor),
    /// Atomically replaces the managed native-firewall policy.
    ///
    /// Unlike every other variant above, this has no separate add/remove
    /// pair: a native-firewall rule carries no backend-synthesized identity
    /// to add or remove individually, so the whole policy is always
    /// replaced. Clearing the managed policy back to default-allow is
    /// expressed as `SetFirewallPolicy(FirewallPolicy::new(Verdict::Allow))`
    /// (an empty rule list), not a separate variant.
    SetFirewallPolicy(FirewallPolicy),
}

/// Observed state captured immediately before a mutation is submitted.
///
/// The snapshot is intentionally scoped to the mutation's domain. `None`
/// means that no matching route, interface address, or interface was
/// observed; it is not a promise that the object cannot appear concurrently.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MutationSnapshot {
    /// The matching route, if one was observed.
    Route(Option<Route>),
    /// The matching interface address, if one was observed.
    InterfaceAddress(Option<InterfaceAddress>),
    /// The resolver view observed before replacement.
    Dns(DnsConfig),
    /// The interface observed before a configuration patch, if it was still
    /// present when the snapshot was captured.
    Interface(Option<Interface>),
    /// The matching observed neighbor entry, if one was observed.
    Neighbor(Option<NeighborEntry>),
    /// The managed firewall policy's rules observed before replacement.
    ///
    /// This is **not** a full [`FirewallPolicy`] snapshot: `firewall_rules()`
    /// exposes only the ordered rule list, never the default verdict that
    /// was in effect, so restoring this snapshot cannot faithfully recreate
    /// the previous policy's default verdict. This is the same reason
    /// [`Mutation::SetFirewallPolicy`]'s reversibility is
    /// [`MutationReversibility::NotGuaranteed`].
    Firewall(Vec<FirewallRule>),
}

/// The broad effect an operation requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationKind {
    /// Adds a route.
    AddRoute,
    /// Removes a route.
    RemoveRoute,
    /// Adds an interface address.
    AddAddress,
    /// Removes an interface address.
    RemoveAddress,
    /// Replaces the resolver configuration.
    SetDnsConfig,
    /// Patches an interface's configuration.
    SetInterfaceConfig,
    /// Adds a static ARP/NDP neighbor entry.
    AddStaticNeighbor,
    /// Removes a static ARP/NDP neighbor entry.
    RemoveStaticNeighbor,
    /// A destination-paired route replacement ([`crate::apply::ApplyStep::ReplaceRoute`]):
    /// one logical unit removing an observed route and adding its desired
    /// replacement, distinct from a bare [`MutationKind::AddRoute`] so
    /// preflight/report code inspecting `kind` does not mislabel it.
    ReplaceRoute,
    /// Replaces the managed native-firewall policy.
    SetFirewallPolicy,
}

/// State that must hold for an operation to be meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationPrecondition {
    /// The target must not already exist.
    Absent,
    /// The target must exist and match the backend's removal rule.
    Present,
    /// The operation replaces configuration regardless of its previous value.
    Any,
}

/// Whether repeating an operation with the same input is expected to succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationIdempotency {
    /// Repetition is not a successful no-op: duplicate or absent-object
    /// errors remain observable.
    Strict,
    /// Repetition requests the same replacement state.
    Replace,
}

/// How much completion evidence the current imperative API returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationConfirmation {
    /// The native platform operation acknowledged the request.
    NativeAcknowledgement,
    /// Net Lattice re-read the corresponding observed state after mutation.
    ReadAfterWrite,
}

/// Privilege level required by the current native operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationPrivilege {
    /// The operation changes operating-system network configuration and
    /// requires the platform's elevated networking privilege.
    Elevated,
}

/// Whether an operation can be safely compensated without prior state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationReversibility {
    /// A compensating operation needs a captured prior observed state and is
    /// still subject to concurrent external changes.
    RequiresPriorState,
    /// The current primitive may affect multiple native settings or lose
    /// unmodelled state, so no rollback promise is made.
    NotGuaranteed,
}

/// Static metadata describing one [`Mutation`]'s current contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MutationSemantics {
    /// The requested effect.
    pub kind: MutationKind,
    /// Required state before execution.
    pub precondition: MutationPrecondition,
    /// Repetition behavior.
    pub idempotency: MutationIdempotency,
    /// Privilege required to submit the operation.
    pub privilege: MutationPrivilege,
    /// How successful completion is confirmed.
    pub confirmation: MutationConfirmation,
    /// Whether rollback can be promised by this primitive.
    pub reversibility: MutationReversibility,
    /// Whether a failed operation may already have changed some state.
    pub may_partially_apply: bool,
}

impl Mutation {
    /// Returns the static contract of this operation in the current API.
    pub const fn semantics(&self) -> MutationSemantics {
        match self {
            Self::AddRoute(_) => MutationSemantics {
                kind: MutationKind::AddRoute,
                precondition: MutationPrecondition::Absent,
                idempotency: MutationIdempotency::Strict,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::NativeAcknowledgement,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: false,
            },
            Self::RemoveRoute(_) => MutationSemantics {
                kind: MutationKind::RemoveRoute,
                precondition: MutationPrecondition::Present,
                idempotency: MutationIdempotency::Strict,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::NativeAcknowledgement,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: false,
            },
            Self::AddAddress(_) => MutationSemantics {
                kind: MutationKind::AddAddress,
                precondition: MutationPrecondition::Absent,
                idempotency: MutationIdempotency::Strict,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::ReadAfterWrite,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: false,
            },
            Self::RemoveAddress(_) => MutationSemantics {
                kind: MutationKind::RemoveAddress,
                precondition: MutationPrecondition::Present,
                idempotency: MutationIdempotency::Strict,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::NativeAcknowledgement,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: false,
            },
            Self::SetDnsConfig(_) => MutationSemantics {
                kind: MutationKind::SetDnsConfig,
                precondition: MutationPrecondition::Any,
                idempotency: MutationIdempotency::Replace,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::ReadAfterWrite,
                reversibility: MutationReversibility::NotGuaranteed,
                may_partially_apply: true,
            },
            Self::SetInterfaceConfig(_) => MutationSemantics {
                kind: MutationKind::SetInterfaceConfig,
                precondition: MutationPrecondition::Present,
                idempotency: MutationIdempotency::Replace,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::ReadAfterWrite,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: true,
            },
            Self::AddStaticNeighbor(_) => MutationSemantics {
                kind: MutationKind::AddStaticNeighbor,
                precondition: MutationPrecondition::Absent,
                idempotency: MutationIdempotency::Strict,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::ReadAfterWrite,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: false,
            },
            Self::RemoveStaticNeighbor(_) => MutationSemantics {
                kind: MutationKind::RemoveStaticNeighbor,
                precondition: MutationPrecondition::Present,
                idempotency: MutationIdempotency::Strict,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::NativeAcknowledgement,
                reversibility: MutationReversibility::RequiresPriorState,
                may_partially_apply: false,
            },
            Self::SetFirewallPolicy(_) => MutationSemantics {
                kind: MutationKind::SetFirewallPolicy,
                precondition: MutationPrecondition::Any,
                idempotency: MutationIdempotency::Replace,
                privilege: MutationPrivilege::Elevated,
                confirmation: MutationConfirmation::ReadAfterWrite,
                // Every shipped backend replaces the whole policy in one
                // native transaction (an nftables batch, a WFP transaction,
                // or a pf DIOCXBEGIN/DIOCXCOMMIT pair) -- unlike DNS or
                // interface configuration, there is no known partial-write
                // case here.
                reversibility: MutationReversibility::NotGuaranteed,
                may_partially_apply: false,
            },
        }
    }
}

/// An ordered, inspectable list of mutations.
///
/// Creating a plan has no side effects. Stage 0.15 executes it through a
/// backend and records outcomes, cancellation boundaries, and rollback status
/// in [`MutationPlanReport`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct MutationPlan {
    operations: Vec<Mutation>,
}

/// Static preflight facts derived from a [`MutationPlan`].
///
/// Preflight is deliberately backend-independent: it does not inspect the
/// operating system, capabilities, privileges, or current state. A plan can
/// pass this analysis and still fail when an executor submits it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MutationPreflight {
    prior_state_indices: Vec<usize>,
    partial_application_indices: Vec<usize>,
}

impl MutationPreflight {
    /// Returns plan-local indices whose compensation needs a prior snapshot.
    pub fn prior_state_indices(&self) -> &[usize] {
        &self.prior_state_indices
    }

    /// Returns plan-local indices whose operation may change state before an
    /// error is returned.
    pub fn partial_application_indices(&self) -> &[usize] {
        &self.partial_application_indices
    }

    /// Whether any operation requires a prior observed state for compensation.
    pub fn requires_prior_state(&self) -> bool {
        !self.prior_state_indices.is_empty()
    }

    /// Whether any operation carries a partial-application risk.
    pub fn may_partially_apply(&self) -> bool {
        !self.partial_application_indices.is_empty()
    }
}

/// The result recorded for one operation in an applied mutation plan.
///
/// These values describe an executor's report; constructing a plan or a
/// report never changes operating-system state. `Failed` deliberately keeps
/// whether the operation may have taken effect separate from the error so a
/// caller can decide whether a fresh read is required.
#[derive(Debug)]
#[non_exhaustive]
pub enum MutationOutcome {
    /// The backend acknowledged the operation according to its contract.
    Applied,
    /// The operation returned an error.
    Failed {
        /// Backend error returned by the operation.
        error: Error,
        /// Whether the operation may have changed state before failing.
        may_have_applied: bool,
    },
    /// The executor did not attempt this operation because an earlier
    /// operation failed or execution was cancelled.
    NotAttempted,
}

/// Status of compensation attempted after a plan failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum RollbackStatus {
    /// No operation failed, so rollback was not needed.
    NotNeeded,
    /// A rollback boundary exists, but compensation was not attempted.
    NotAttempted,
    /// Compensation completed for the operations selected by the executor.
    Completed,
    /// Compensation itself failed.
    Failed {
        /// Index of the operation whose compensation failed.
        operation_index: usize,
        /// Error returned by the compensation attempt.
        error: Error,
    },
}

/// Execution phase associated with an operation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationExecutionPhase {
    /// The plan or operation is being checked before submission.
    Validation,
    /// Prior state is being captured for an operation.
    Snapshot,
    /// The mutation is being submitted to the platform backend.
    Execution,
    /// An explicitly supplied compensator is being run.
    Compensation,
    /// Execution stopped at an operation boundary because cancellation was requested.
    Cancellation,
}

/// Why an operation or plan stopped progressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationStopReason {
    /// Plan or operation preconditions were rejected.
    ValidationFailed,
    /// Prior-state capture failed before submission.
    SnapshotFailed,
    /// The platform backend rejected or could not complete the operation.
    ExecutionFailed,
    /// The caller requested cancellation before this operation was submitted.
    Cancelled,
    /// An explicitly supplied compensator failed.
    CompensationFailed,
    /// The operation was rejected before any native call was attempted
    /// because the connected backend cannot honor a field the operation's
    /// intent requires (for example, a route metric change on a backend
    /// whose native route calls never read or write metric).
    CapabilityRejected,
    /// A native call was attempted but the resulting state could not be
    /// confirmed to match the requested replacement, or a precondition the
    /// operation required no longer held when re-checked immediately before
    /// execution.
    NonConvergentReplacement,
}

/// Timing and phase metadata for one plan-local operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MutationOperationReport {
    /// Last phase reached by this operation.
    pub phase: MutationExecutionPhase,
    /// Time spent in snapshot and native execution callbacks.
    pub duration: Duration,
    /// Why execution stopped at this operation, if it stopped abnormally.
    pub stop_reason: Option<MutationStopReason>,
}

impl MutationOperationReport {
    /// Returns metadata for an operation that was not submitted.
    pub const fn not_attempted() -> Self {
        Self {
            phase: MutationExecutionPhase::Validation,
            duration: Duration::ZERO,
            stop_reason: None,
        }
    }
}

/// Executor report for an ordered [`MutationPlan`].
///
/// A report is intentionally not called a transaction: operations may have
/// been partially applied, and rollback is reported separately rather than
/// implied. The outcome at index `n` corresponds to
/// `MutationPlan::operation(n)`. Callers should re-read affected state
/// whenever an outcome says that application was possible or rollback was not
/// completed.
#[derive(Debug)]
pub struct MutationPlanReport {
    outcomes: Vec<MutationOutcome>,
    rollback: RollbackStatus,
    operation_reports: Vec<MutationOperationReport>,
}

impl MutationPlanReport {
    /// Creates a report for outcomes in the plan's declared order.
    pub fn new(
        outcomes: impl IntoIterator<Item = MutationOutcome>,
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
        outcomes: impl IntoIterator<Item = MutationOutcome>,
        rollback: RollbackStatus,
        operation_reports: impl IntoIterator<Item = MutationOperationReport>,
    ) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            rollback,
            operation_reports: operation_reports.into_iter().collect(),
        }
    }

    /// Returns one outcome for each operation attempted or skipped.
    pub fn outcomes(&self) -> &[MutationOutcome] {
        &self.outcomes
    }

    /// Returns the outcome at a plan-local operation index, if present.
    pub fn outcome(&self, index: usize) -> Option<&MutationOutcome> {
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

    /// Returns phase and timing metadata for one plan-local operation.
    pub fn operation_report(&self, index: usize) -> Option<&MutationOperationReport> {
        self.operation_reports.get(index)
    }

    /// Whether every recorded operation was applied successfully.
    pub fn is_success(&self) -> bool {
        self.outcomes
            .iter()
            .all(|outcome| matches!(outcome, MutationOutcome::Applied))
    }

    /// Number of operations recorded as applied.
    pub fn applied_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, MutationOutcome::Applied))
            .count()
    }

    /// Number of operations the executor did not attempt.
    pub fn not_attempted_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, MutationOutcome::NotAttempted))
            .count()
    }
}

impl MutationPlan {
    /// Creates an empty plan.
    pub const fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Creates a plan from operations in execution order.
    pub fn from_operations(operations: impl IntoIterator<Item = Mutation>) -> Self {
        Self {
            operations: operations.into_iter().collect(),
        }
    }

    /// Appends an operation after all existing operations.
    pub fn push(&mut self, operation: Mutation) {
        self.operations.push(operation);
    }

    /// Returns the operations in their declared order.
    pub fn operations(&self) -> &[Mutation] {
        &self.operations
    }

    /// Returns the operation at `index`, if present.
    ///
    /// Executors use this stable plan-local index to associate an operation
    /// with the corresponding entry in [`MutationPlanReport::outcomes`].
    pub fn operation(&self, index: usize) -> Option<&Mutation> {
        self.operations.get(index)
    }

    /// Computes backend-independent execution risks for this plan.
    ///
    /// This method has no side effects and does not validate capabilities,
    /// privileges, or current networking state. Those checks belong to the
    /// executor at submission time.
    pub fn preflight(&self) -> MutationPreflight {
        let mut prior_state_indices = Vec::new();
        let mut partial_application_indices = Vec::new();

        for (index, operation) in self.operations.iter().enumerate() {
            let semantics = operation.semantics();
            if matches!(
                semantics.reversibility,
                MutationReversibility::RequiresPriorState
            ) {
                prior_state_indices.push(index);
            }
            if semantics.may_partially_apply {
                partial_application_indices.push(index);
            }
        }

        MutationPreflight {
            prior_state_indices,
            partial_application_indices,
        }
    }

    /// Whether the plan has no operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Number of operations in the plan.
    pub fn len(&self) -> usize {
        self.operations.len()
    }
}

impl IntoIterator for MutationPlan {
    type Item = Mutation;
    type IntoIter = std::vec::IntoIter<Mutation>;

    fn into_iter(self) -> Self::IntoIter {
        self.operations.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighbor::StaticNeighbor;
    use crate::{DesiredAdminState, InterfaceConfig, InterfaceId, IpAddress, MacAddress, Network};
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

    fn network() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        ))
    }

    #[test]
    fn dns_replacement_exposes_partial_application_risk() {
        let operation = Mutation::SetDnsConfig(NewDnsConfig::with(
            vec![IpAddress::from(Ipv4Address::new(1, 1, 1, 1))],
            Vec::new(),
        ));
        assert_eq!(
            operation.semantics().precondition,
            MutationPrecondition::Any
        );
        assert_eq!(
            operation.semantics().idempotency,
            MutationIdempotency::Replace
        );
        assert!(operation.semantics().may_partially_apply);
        assert_eq!(
            operation.semantics().confirmation,
            MutationConfirmation::ReadAfterWrite
        );
        assert_eq!(
            operation.semantics().reversibility,
            MutationReversibility::NotGuaranteed
        );
    }

    #[test]
    fn address_addition_has_an_observed_readback_contract() {
        let operation = Mutation::AddAddress(NewInterfaceAddress::new(
            crate::interface::InterfaceId::new(2),
            network(),
        ));
        assert_eq!(
            operation.semantics().confirmation,
            MutationConfirmation::ReadAfterWrite
        );
        assert_eq!(
            operation.semantics().precondition,
            MutationPrecondition::Absent
        );
        assert_eq!(
            operation.semantics().reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(!operation.semantics().may_partially_apply);
    }

    #[test]
    fn plan_keeps_declared_order_without_executing_operations() {
        let first = Mutation::AddRoute(RouteConfig::new(network()));
        let second = Mutation::RemoveRoute(RouteConfig::new(network()).with_interface_index(2));
        let plan = MutationPlan::from_operations([first.clone(), second.clone()]);
        assert_eq!(plan.operations(), [first, second]);
        assert!(plan.operation(0).is_some());
        assert!(plan.operation(2).is_none());
        assert_eq!(plan.len(), 2);
        assert!(!plan.is_empty());
    }

    #[test]
    fn route_operations_expose_strict_native_acknowledgement_contracts() {
        let route = RouteConfig::new(network());

        let added = Mutation::AddRoute(route).semantics();
        assert_eq!(added.kind, MutationKind::AddRoute);
        assert_eq!(added.precondition, MutationPrecondition::Absent);
        assert_eq!(added.idempotency, MutationIdempotency::Strict);
        assert_eq!(added.privilege, MutationPrivilege::Elevated);
        assert_eq!(
            added.confirmation,
            MutationConfirmation::NativeAcknowledgement
        );
        assert_eq!(
            added.reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(!added.may_partially_apply);

        let removed = Mutation::RemoveRoute(route).semantics();
        assert_eq!(removed.kind, MutationKind::RemoveRoute);
        assert_eq!(removed.precondition, MutationPrecondition::Present);
        assert_eq!(removed.idempotency, MutationIdempotency::Strict);
        assert_eq!(removed.privilege, MutationPrivilege::Elevated);
        assert_eq!(
            removed.confirmation,
            MutationConfirmation::NativeAcknowledgement
        );
        assert_eq!(
            removed.reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(!removed.may_partially_apply);
    }

    #[test]
    fn address_removal_exposes_its_observed_record_contract() {
        let address =
            InterfaceAddress::new(crate::ifaddr::InterfaceAddressId::new(1), 1, network());
        let semantics = Mutation::RemoveAddress(address).semantics();

        assert_eq!(semantics.kind, MutationKind::RemoveAddress);
        assert_eq!(semantics.precondition, MutationPrecondition::Present);
        assert_eq!(semantics.idempotency, MutationIdempotency::Strict);
        assert_eq!(semantics.privilege, MutationPrivilege::Elevated);
        assert_eq!(
            semantics.confirmation,
            MutationConfirmation::NativeAcknowledgement
        );
        assert_eq!(
            semantics.reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(!semantics.may_partially_apply);
    }

    #[test]
    fn empty_plan_can_be_built_appended_and_consumed() {
        let mut plan = MutationPlan::new();
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);

        let operation = Mutation::AddRoute(RouteConfig::new(network()));
        plan.push(operation.clone());
        assert_eq!(plan.operations(), std::slice::from_ref(&operation));
        assert_eq!(plan.into_iter().collect::<Vec<_>>(), vec![operation]);
    }

    #[test]
    fn plan_report_preserves_partial_failure_and_rollback_boundary() {
        let report = MutationPlanReport::new(
            [
                MutationOutcome::Applied,
                MutationOutcome::Failed {
                    error: Error::PermissionDenied,
                    may_have_applied: true,
                },
                MutationOutcome::NotAttempted,
            ],
            RollbackStatus::NotAttempted,
        );

        assert!(!report.is_success());
        assert_eq!(report.applied_count(), 1);
        assert_eq!(report.not_attempted_count(), 1);
        assert_eq!(report.len(), 3);
        assert_eq!(report.operation_reports().len(), 3);
        assert!(report.operation_report(2).is_some());
        assert!(!report.is_empty());
        assert!(report.outcome(3).is_none());
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
        assert!(matches!(
            &report.outcomes()[1],
            MutationOutcome::Failed {
                may_have_applied: true,
                ..
            }
        ));
    }

    #[test]
    fn preflight_identifies_snapshot_and_partial_application_risks() {
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(RouteConfig::new(network())),
            Mutation::SetDnsConfig(NewDnsConfig::new()),
        ]);
        let preflight = plan.preflight();

        assert_eq!(preflight.prior_state_indices(), &[0]);
        assert_eq!(preflight.partial_application_indices(), &[1]);
        assert!(preflight.requires_prior_state());
        assert!(preflight.may_partially_apply());
    }

    #[test]
    fn interface_configuration_exposes_readback_and_partial_application_contracts() {
        let operation = Mutation::SetInterfaceConfig(
            InterfaceConfig::new(InterfaceId::new(7), Some(DesiredAdminState::Up), Some(1500))
                .expect("valid configuration"),
        );
        let semantics = operation.semantics();

        assert_eq!(semantics.kind, MutationKind::SetInterfaceConfig);
        assert_eq!(semantics.precondition, MutationPrecondition::Present);
        assert_eq!(semantics.idempotency, MutationIdempotency::Replace);
        assert_eq!(semantics.privilege, MutationPrivilege::Elevated);
        assert_eq!(semantics.confirmation, MutationConfirmation::ReadAfterWrite);
        assert_eq!(
            semantics.reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(semantics.may_partially_apply);

        let plan = MutationPlan::from_operations([operation]);
        let preflight = plan.preflight();
        assert_eq!(preflight.prior_state_indices(), &[0]);
        assert_eq!(preflight.partial_application_indices(), &[0]);
    }

    fn static_neighbor() -> StaticNeighbor {
        StaticNeighbor::new(
            InterfaceId::new(4),
            IpAddress::from(Ipv4Address::new(192, 168, 1, 9)),
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x09]),
        )
    }

    #[test]
    fn add_static_neighbor_requires_absent_target_and_read_after_write() {
        let operation = Mutation::AddStaticNeighbor(static_neighbor());
        let semantics = operation.semantics();

        assert_eq!(semantics.kind, MutationKind::AddStaticNeighbor);
        assert_eq!(semantics.precondition, MutationPrecondition::Absent);
        assert_eq!(semantics.idempotency, MutationIdempotency::Strict);
        assert_eq!(semantics.privilege, MutationPrivilege::Elevated);
        assert_eq!(semantics.confirmation, MutationConfirmation::ReadAfterWrite);
        assert_eq!(
            semantics.reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(!semantics.may_partially_apply);
    }

    #[test]
    fn remove_static_neighbor_requires_present_target_and_native_acknowledgement() {
        let operation = Mutation::RemoveStaticNeighbor(static_neighbor());
        let semantics = operation.semantics();

        assert_eq!(semantics.kind, MutationKind::RemoveStaticNeighbor);
        assert_eq!(semantics.precondition, MutationPrecondition::Present);
        assert_eq!(semantics.idempotency, MutationIdempotency::Strict);
        assert_eq!(semantics.privilege, MutationPrivilege::Elevated);
        assert_eq!(
            semantics.confirmation,
            MutationConfirmation::NativeAcknowledgement
        );
        assert_eq!(
            semantics.reversibility,
            MutationReversibility::RequiresPriorState
        );
        assert!(!semantics.may_partially_apply);
    }

    #[test]
    fn neighbor_snapshot_variant_holds_the_matched_observed_entry() {
        let snapshot = MutationSnapshot::Neighbor(None);
        assert!(matches!(snapshot, MutationSnapshot::Neighbor(None)));
    }

    #[test]
    fn static_neighbor_operations_require_prior_state_for_compensation() {
        let plan = MutationPlan::from_operations([
            Mutation::AddStaticNeighbor(static_neighbor()),
            Mutation::RemoveStaticNeighbor(static_neighbor()),
        ]);
        let preflight = plan.preflight();

        assert_eq!(preflight.prior_state_indices(), &[0, 1]);
        assert!(preflight.partial_application_indices().is_empty());
    }
}
