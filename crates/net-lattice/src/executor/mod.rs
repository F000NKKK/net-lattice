//! Internal Stage 0.15 transaction orchestration helpers, plus (`apply`) the
//! Stage 0.20 [`net_lattice_model::apply::ApplyPlan`] execution engine.
//!
//! The mutation model remains in `net-lattice-model`. This module owns only
//! execution policy shared by the facade methods and deliberately has no
//! dependency on a concrete operating-system backend.

pub(crate) mod apply;

use net_lattice_core::{Error, Result};
use net_lattice_model::{
    Mutation, MutationExecutionPhase, MutationOperationReport, MutationOutcome, MutationPlan,
    MutationPlanReport, MutationSnapshot, MutationStopReason, RollbackStatus,
};

/// Borrowed operation-boundary cancellation callback.
pub type Cancellation<'a> = &'a mut dyn FnMut(usize, &Mutation) -> bool;
/// Borrowed callback used to capture typed prior state.
pub type Snapshot<'a> = &'a mut dyn FnMut(usize, &Mutation) -> Result<MutationSnapshot>;
/// Borrowed callback used for explicit reverse-order compensation.
pub type Compensation<'a> =
    &'a mut dyn FnMut(usize, &Mutation, Option<&MutationSnapshot>) -> Result<()>;

/// Options controlling one ordered plan execution.
pub struct ExecutionOptions<'a> {
    pub(crate) cancellation: Option<Cancellation<'a>>,
    pub(crate) snapshot: Option<Snapshot<'a>>,
    pub(crate) compensation: Option<Compensation<'a>>,
}

impl<'a> ExecutionOptions<'a> {
    /// Creates options with no cancellation, snapshot, or compensation hooks.
    pub fn new() -> Self {
        Self {
            cancellation: None,
            snapshot: None,
            compensation: None,
        }
    }

    /// Installs an operation-boundary cancellation hook.
    pub fn cancellation(mut self, callback: Cancellation<'a>) -> Self {
        self.cancellation = Some(callback);
        self
    }

    /// Installs a typed prior-state capture hook.
    pub fn snapshot(mut self, callback: Snapshot<'a>) -> Self {
        self.snapshot = Some(callback);
        self
    }

    /// Installs explicit reverse-order compensation.
    pub fn compensation(mut self, callback: Compensation<'a>) -> Self {
        self.compensation = Some(callback);
        self
    }
}

impl Default for ExecutionOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns whether an operation requires the resolver mutation capability.
pub(crate) fn requires_dns_capability(operation: &Mutation) -> bool {
    matches!(operation, Mutation::SetDnsConfig(_))
}

/// Returns whether an operation requires the static-neighbor mutation
/// capability, per ADR-0001.
pub(crate) fn requires_neighbor_capability(operation: &Mutation) -> bool {
    matches!(
        operation,
        Mutation::AddStaticNeighbor(_) | Mutation::RemoveStaticNeighbor(_)
    )
}

/// Returns whether an operation requires the route mutation capability, per
/// ADR-0002.
pub(crate) fn requires_route_capability(operation: &Mutation) -> bool {
    matches!(operation, Mutation::AddRoute(_) | Mutation::RemoveRoute(_))
}

/// Returns whether an operation requires the firewall mutation capability.
pub(crate) fn requires_firewall_capability(operation: &Mutation) -> bool {
    matches!(operation, Mutation::SetFirewallPolicy(_))
}

/// Builds the complete report for a plan rejected before native submission.
pub(crate) fn unsupported_plan_report(plan: &MutationPlan, error: Error) -> MutationPlanReport {
    let mut outcomes = Vec::with_capacity(plan.len());
    let mut reports = vec![MutationOperationReport::not_attempted(); plan.len()];
    if !plan.is_empty() {
        outcomes.push(MutationOutcome::Failed {
            error,
            may_have_applied: false,
        });
        outcomes.extend((0..plan.len() - 1).map(|_| MutationOutcome::NotAttempted));
        reports[0] = MutationOperationReport {
            phase: MutationExecutionPhase::Validation,
            duration: std::time::Duration::ZERO,
            stop_reason: Some(MutationStopReason::ValidationFailed),
        };
    }
    MutationPlanReport::with_operation_reports(outcomes, RollbackStatus::NotNeeded, reports)
}
