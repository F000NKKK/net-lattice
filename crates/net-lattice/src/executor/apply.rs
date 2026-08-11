//! [`ApplyPlan`] execution: the Stage 0.20 counterpart to
//! [`crate::Lattice::execute_plan`].
//!
//! [`ApplyStep::Single`] steps are executed through the exact same
//! per-operation primitives `execute_plan` uses
//! (`Lattice::execute_one_mutation`/`Lattice::validate_one_mutation`,
//! defined in the crate root alongside `execute_plan`/`validate_plan`
//! themselves). [`ApplyStep::ReplaceRoute`] cannot be expressed as a single
//! [`Mutation`], so it gets its own bounded state machine here: per-backend
//! leg ordering, mandatory read-after-write verification, and best-effort
//! compensation performed by this module itself rather than the caller's
//! [`crate::executor::Compensation`] callback (see
//! [`crate::Lattice::execute_apply_plan`]'s rustdoc for the exact contract).

use std::time::{Duration, Instant};

use net_lattice_core::{Error, Result};
use net_lattice_model::apply::{ApplyPlan, ApplyPlanReport, ApplyStep, ApplyStepOutcome};
use net_lattice_model::mutation::{
    MutationExecutionPhase, MutationOperationReport, MutationOutcome, MutationSnapshot,
    MutationStopReason, RollbackStatus,
};
use net_lattice_model::route::{Route, RouteConfig};
use net_lattice_model::{Mutation, NonConvergentReason};
use net_lattice_platform::{Capability, RouteReplaceOrder};

use crate::executor::ExecutionOptions;
use crate::{Lattice, LatticeBackend, PlanAccumulators};

/// Builds the complete report for an [`ApplyPlan`] rejected before native
/// submission, mirroring [`crate::executor::unsupported_plan_report`]'s own
/// index-0-attribution simplification: [`Lattice::validate_apply_plan`]
/// returns `Result<()>` with no failing index, so (as with
/// `unsupported_plan_report`) the rejection is attributed to plan index 0
/// regardless of which step actually failed preflight. This is a
/// pre-existing limitation inherited unchanged from `execute_plan`'s own
/// gate, not a new defect introduced by `ApplyPlan` execution.
pub(crate) fn unsupported_apply_plan_report(plan: &ApplyPlan, error: Error) -> ApplyPlanReport {
    let mut outcomes = Vec::with_capacity(plan.len());
    let mut reports = vec![MutationOperationReport::not_attempted(); plan.len()];
    if !plan.is_empty() {
        outcomes.push(ApplyStepOutcome::Rejected { error });
        outcomes.extend((0..plan.len() - 1).map(|_| ApplyStepOutcome::NotAttempted));
        reports[0] = MutationOperationReport {
            phase: MutationExecutionPhase::Validation,
            duration: Duration::ZERO,
            stop_reason: Some(MutationStopReason::CapabilityRejected),
        };
    }
    ApplyPlanReport::with_operation_reports(outcomes, RollbackStatus::NotNeeded, reports)
}

/// Converts an observed [`Route`] into the [`RouteConfig`] a native
/// remove/re-add call needs, carrying forward only the fields the observed
/// route actually populated.
///
/// Duplicated from `net-lattice-model::apply`'s private helper of the same
/// shape rather than shared across the crate boundary: that crate is
/// deliberately backend-blind (no `net-lattice-platform`/`net-lattice`
/// dependency), so this conversion is re-derived here for the one call site
/// that needs it during execution.
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

/// What a [`ApplyStep::ReplaceRoute`] step's native execution attempt
/// actually completed, captured independently of the step's own outcome so
/// best-effort compensation (performed only when the caller supplied
/// `.compensation(...)`) knows exactly what to reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaceRouteProgress {
    /// Neither leg was attempted: rejected before execution, or the
    /// precondition was found stale before any native call.
    NoLegsAttempted,
    /// Only the first leg (per [`RouteMutator::route_replace_order`])
    /// completed; the second leg was never attempted or failed.
    FirstLegOnly,
    /// Both legs completed (both native calls returned `Ok`), but
    /// read-after-write could not confirm the resulting state.
    BothLegsUnverified,
    /// Both legs completed and read-after-write confirmed success.
    BothLegsConfirmed,
}

/// One step whose native effect may need reverse-order compensation if a
/// later step in the same [`ApplyPlan`] stops execution.
enum AppliedApplyStep {
    Single {
        index: usize,
        operation: Mutation,
        prior: Option<MutationSnapshot>,
    },
    ReplaceRoute {
        index: usize,
        old: Route,
        new: RouteConfig,
        progress: ReplaceRouteProgress,
    },
}

impl<B: LatticeBackend> Lattice<B> {
    /// Performs the runtime portion of [`ApplyPlan`] preflight: the same
    /// per-[`Mutation`] capability/precondition checks
    /// [`Lattice::validate_plan`] runs internally for every
    /// [`ApplyStep::Single`] step, plus a capability-aware rejection for
    /// every [`ApplyStep::ReplaceRoute`] step (and every bare
    /// `Single(Mutation::AddRoute(_))` requesting a metric) whose requested
    /// metric the connected backend cannot honor
    /// (`RouteMutator::supports_route_metric` `== false`).
    ///
    /// Evaluated plan-wide before any step executes, mirroring
    /// [`Lattice::validate_plan`]'s existing preflight-rejects-the-whole-
    /// plan-before-any-native-call contract.
    ///
    /// Public for the same reason [`Lattice::validate_plan`] is: a caller
    /// that wants to preflight-check a compiled [`ApplyPlan`] (for example
    /// one built via [`Self::current_state`]/[`net_lattice_model::diff::Diff::compute`]/
    /// [`ApplyPlan::compile`], the same steps [`Self::apply`] chains
    /// internally) without submitting any native call can call this
    /// directly instead of going through [`Self::execute_apply_plan`],
    /// exactly mirroring the existing `validate_plan`/`execute_plan` pair
    /// for [`net_lattice_model::mutation::MutationPlan`]. This check is
    /// side-effect free; native privilege and current-state checks can
    /// still fail at execution time.
    pub fn validate_apply_plan(&self, plan: &ApplyPlan) -> Result<()> {
        let mut accumulators = PlanAccumulators::default();
        for step in plan.steps() {
            match step {
                ApplyStep::Single(operation) => {
                    if let Mutation::AddRoute(config) = operation
                        && config.metric.is_some()
                        && !self.backend.supports_route_metric()
                    {
                        return Err(Error::Unsupported);
                    }
                    self.validate_one_mutation(operation, &mut accumulators)?;
                }
                ApplyStep::ReplaceRoute { old, new } => {
                    if !self.supports(Capability::ROUTE_MUTATION) {
                        return Err(Error::Unsupported);
                    }
                    if !self.backend.supports_route_metric()
                        && old.gateway == new.gateway
                        && old.interface_index == new.interface_index
                        && new.metric.is_some()
                        && old.metric != new.metric
                    {
                        return Err(Error::Unsupported);
                    }
                }
                // `ApplyStep` is `#[non_exhaustive]`: a future variant this
                // crate does not yet know how to execute is rejected
                // whole-plan, the same fail-closed default
                // `validate_one_mutation`'s own trailing `_` arm applies to
                // an unrecognized `Mutation` variant.
                _ => return Err(Error::Unsupported),
            }
        }
        Ok(())
    }

    /// Executes an ordered [`ApplyPlan`] through this backend.
    ///
    /// [`ApplyStep::Single`] steps run through the exact same primitives
    /// [`Self::execute_plan`] uses for a [`net_lattice_model::mutation::MutationPlan`]:
    /// the caller's `options.cancellation`/`options.snapshot` hooks are
    /// invoked with that step's own [`Mutation`], and a failed/cancelled
    /// step's prior state is compensated via `options.compensation`
    /// exactly as it would be for a plain [`net_lattice_model::mutation::MutationPlan`].
    ///
    /// [`ApplyStep::ReplaceRoute`] steps run a dedicated state machine
    /// instead, since no single [`Mutation`] can express a destination-
    /// paired replacement:
    ///
    /// - `options.cancellation` is still invoked at this step's boundary,
    ///   for cancellation-boundary parity with `Single` steps, but since
    ///   `Cancellation`'s existing signature takes a `&Mutation` and a
    ///   `ReplaceRoute` step is not one, it is invoked with a synthesized
    ///   `Mutation::AddRoute(new)` standing in for the step's desired end
    ///   state — this synthesized value is used **only** for this
    ///   boundary check, never submitted as a native operation on its own.
    /// - `options.snapshot` is **not** invoked for a `ReplaceRoute` step:
    ///   the precondition/snapshot reuse this step needs re-reads
    ///   [`Self::routes`] directly against the step's own captured `old`
    ///   route, which the caller-supplied snapshot hook (typed for a
    ///   single [`Mutation`]) cannot express.
    /// - `options.compensation`, the caller's callback, is **not** invoked
    ///   for a `ReplaceRoute` step, because its `&Mutation`-typed signature
    ///   cannot represent a replacement pairing either. When the plan stops
    ///   at or after a `ReplaceRoute` step and the caller *did* supply
    ///   `.compensation(...)` (compensation is never inferred without one,
    ///   unchanged from [`Self::execute_plan`]'s existing contract), this
    ///   method performs that step's best-effort reversal itself, using the
    ///   already-captured `old`/leg-completion state — no caller callback
    ///   fires for it. The caller's callback continues to fire normally for
    ///   every compensated `Single` step in the same plan.
    ///
    /// The returned report always contains one outcome per plan step (a
    /// `ReplaceRoute` step's two native calls are reported as one logical
    /// unit). Execution stops after the first step that is not
    /// [`ApplyStepOutcome::Applied`].
    pub fn execute_apply_plan(
        &self,
        plan: &ApplyPlan,
        options: &mut ExecutionOptions<'_>,
    ) -> ApplyPlanReport {
        if let Err(error) = self.validate_apply_plan(plan) {
            return unsupported_apply_plan_report(plan, error);
        }

        let mut outcomes = Vec::with_capacity(plan.len());
        let mut operation_reports = vec![MutationOperationReport::not_attempted(); plan.len()];
        let mut applied: Vec<AppliedApplyStep> = Vec::new();
        let mut stopped = false;

        for (index, step) in plan.steps().iter().enumerate() {
            if stopped {
                outcomes.push(ApplyStepOutcome::NotAttempted);
                continue;
            }

            match step {
                ApplyStep::Single(operation) => {
                    let (outcome, report, prior) =
                        self.execute_one_mutation(index, operation, options);
                    operation_reports[index] = report;

                    let step_outcome = match outcome {
                        MutationOutcome::Applied => {
                            applied.push(AppliedApplyStep::Single {
                                index,
                                operation: operation.clone(),
                                prior,
                            });
                            ApplyStepOutcome::Applied
                        }
                        MutationOutcome::Failed {
                            error,
                            may_have_applied,
                        } => {
                            stopped = true;
                            ApplyStepOutcome::Failed {
                                error,
                                may_have_applied,
                            }
                        }
                        MutationOutcome::NotAttempted => {
                            stopped = true;
                            ApplyStepOutcome::NotAttempted
                        }
                        // `MutationOutcome` is `#[non_exhaustive]`, but
                        // `Self::execute_one_mutation` is this crate's own
                        // private method and only ever constructs
                        // `Applied`/`Failed`/`NotAttempted`.
                        _ => unreachable!(
                            "execute_one_mutation only returns Applied/Failed/NotAttempted"
                        ),
                    };
                    outcomes.push(step_outcome);
                }
                ApplyStep::ReplaceRoute { old, new } => {
                    let (outcome, report, progress) =
                        self.execute_replace_route_step(index, old, new, options);
                    operation_reports[index] = report;

                    let is_applied = matches!(outcome, ApplyStepOutcome::Applied);
                    if !matches!(progress, ReplaceRouteProgress::NoLegsAttempted) {
                        applied.push(AppliedApplyStep::ReplaceRoute {
                            index,
                            old: old.clone(),
                            new: *new,
                            progress,
                        });
                    }
                    if !is_applied {
                        stopped = true;
                    }
                    outcomes.push(outcome);
                }
                // `ApplyStep` is `#[non_exhaustive]`: `validate_apply_plan`
                // already rejects the whole plan for any variant this
                // match doesn't handle, so execution never reaches here.
                _ => unreachable!(
                    "validate_apply_plan already rejects any ApplyStep variant this match \
                     doesn't handle"
                ),
            }
        }

        let rollback = if !stopped {
            RollbackStatus::NotNeeded
        } else if applied.is_empty() {
            RollbackStatus::NotAttempted
        } else {
            let Some(compensate) = options.compensation.as_mut() else {
                return ApplyPlanReport::with_operation_reports(
                    outcomes,
                    RollbackStatus::NotAttempted,
                    operation_reports,
                );
            };

            let mut status = RollbackStatus::Completed;

            for applied_step in applied.into_iter().rev() {
                let (index, result) = match applied_step {
                    AppliedApplyStep::Single {
                        index,
                        operation,
                        prior,
                    } => {
                        let started = Instant::now();
                        let result = compensate(index, &operation, prior.as_ref());
                        operation_reports[index].phase = MutationExecutionPhase::Compensation;
                        operation_reports[index].duration += started.elapsed();
                        (index, result)
                    }
                    AppliedApplyStep::ReplaceRoute {
                        index,
                        old,
                        new,
                        progress,
                    } => {
                        let started = Instant::now();
                        let result = self.compensate_replace_route(&old, &new, progress);
                        operation_reports[index].phase = MutationExecutionPhase::Compensation;
                        operation_reports[index].duration += started.elapsed();
                        (index, result)
                    }
                };

                if let Err(error) = result {
                    operation_reports[index].stop_reason =
                        Some(MutationStopReason::CompensationFailed);
                    status = RollbackStatus::Failed {
                        operation_index: index,
                        error,
                    };
                    break;
                }
            }

            status
        };

        ApplyPlanReport::with_operation_reports(outcomes, rollback, operation_reports)
    }

    /// Runs one [`ApplyStep::ReplaceRoute`] step's 6-step algorithm:
    /// cancellation, precondition/snapshot reuse, per-backend leg ordering,
    /// and mandatory read-after-write verification. See
    /// [`Self::execute_apply_plan`]'s rustdoc for exactly which
    /// `ExecutionOptions` hooks are (and are not) invoked for this step
    /// kind.
    fn execute_replace_route_step(
        &self,
        index: usize,
        old: &Route,
        new: &RouteConfig,
        options: &mut ExecutionOptions<'_>,
    ) -> (
        ApplyStepOutcome,
        MutationOperationReport,
        ReplaceRouteProgress,
    ) {
        // Step 1: cancellation boundary parity with `execute_one_mutation`.
        // `Cancellation` is `&Mutation`-typed; synthesize a stand-in value
        // representing this step's desired end state for the boundary
        // check only (never submitted as a native operation on its own).
        let cancellation_stand_in = Mutation::AddRoute(*new);
        if options
            .cancellation
            .as_mut()
            .is_some_and(|callback| callback(index, &cancellation_stand_in))
        {
            return (
                ApplyStepOutcome::NotAttempted,
                MutationOperationReport {
                    phase: MutationExecutionPhase::Cancellation,
                    duration: Duration::ZERO,
                    stop_reason: Some(MutationStopReason::Cancelled),
                },
                ReplaceRouteProgress::NoLegsAttempted,
            );
        }

        // Step 3: precondition/snapshot reuse — re-read `routes()` and
        // confirm `old`'s full four-field identity is still present.
        let snapshot_started = Instant::now();
        let old_config = route_config_from_route(old);
        let observed_routes = match self.routes() {
            Ok(routes) => routes,
            Err(error) => {
                return (
                    ApplyStepOutcome::Failed {
                        error,
                        may_have_applied: false,
                    },
                    MutationOperationReport {
                        phase: MutationExecutionPhase::Snapshot,
                        duration: snapshot_started.elapsed(),
                        stop_reason: Some(MutationStopReason::SnapshotFailed),
                    },
                    ReplaceRouteProgress::NoLegsAttempted,
                );
            }
        };
        let precondition_holds = observed_routes
            .iter()
            .any(|candidate| Self::same_route(candidate, &old_config));
        if !precondition_holds {
            return (
                ApplyStepOutcome::NonConvergent {
                    reason: NonConvergentReason::StalePrecondition,
                },
                MutationOperationReport {
                    phase: MutationExecutionPhase::Snapshot,
                    duration: snapshot_started.elapsed(),
                    stop_reason: Some(MutationStopReason::NonConvergentReplacement),
                },
                ReplaceRouteProgress::NoLegsAttempted,
            );
        }

        // Step 4: per-backend ordering.
        let execution_started = Instant::now();
        // `RouteReplaceOrder` is `#[non_exhaustive]`; any future ordering
        // strategy this crate does not yet know falls back to the trait's
        // own documented default (`RemoveBeforeAdd`).
        let add_before_remove = matches!(
            self.backend.route_replace_order(),
            RouteReplaceOrder::AddBeforeRemove
        );
        let (first_leg_error, second_leg_result) = if add_before_remove {
            match self.add_route(*new) {
                Err(error) => (Some(error), None),
                Ok(()) => (None, Some(self.remove_route(old_config))),
            }
        } else {
            match self.remove_route(old_config) {
                Err(error) => (Some(error), None),
                Ok(()) => (None, Some(self.add_route(*new))),
            }
        };
        let execution_duration = execution_started.elapsed();

        if let Some(error) = first_leg_error {
            return (
                ApplyStepOutcome::Failed {
                    error,
                    may_have_applied: false,
                },
                MutationOperationReport {
                    phase: MutationExecutionPhase::Execution,
                    duration: execution_duration,
                    stop_reason: Some(MutationStopReason::ExecutionFailed),
                },
                ReplaceRouteProgress::NoLegsAttempted,
            );
        }
        if let Some(Err(error)) = second_leg_result {
            return (
                ApplyStepOutcome::Failed {
                    error,
                    may_have_applied: true,
                },
                MutationOperationReport {
                    phase: MutationExecutionPhase::Execution,
                    duration: execution_duration,
                    stop_reason: Some(MutationStopReason::ExecutionFailed),
                },
                ReplaceRouteProgress::FirstLegOnly,
            );
        }

        // Step 5: mandatory read-after-write.
        let verify_started = Instant::now();
        let converged = matches!(self.routes(), Ok(routes) if
            routes.iter().any(|candidate| Self::same_route(candidate, new))
                && !routes.iter().any(|candidate| Self::same_route(candidate, &old_config)));
        let total_duration = execution_duration + verify_started.elapsed();

        if converged {
            (
                ApplyStepOutcome::Applied,
                MutationOperationReport {
                    phase: MutationExecutionPhase::Execution,
                    duration: total_duration,
                    stop_reason: None,
                },
                ReplaceRouteProgress::BothLegsConfirmed,
            )
        } else {
            (
                ApplyStepOutcome::NonConvergent {
                    reason: NonConvergentReason::AmbiguousReplacementUnverifiable,
                },
                MutationOperationReport {
                    phase: MutationExecutionPhase::Execution,
                    duration: total_duration,
                    stop_reason: Some(MutationStopReason::NonConvergentReplacement),
                },
                ReplaceRouteProgress::BothLegsUnverified,
            )
        }
    }

    /// Best-effort reversal of one [`ApplyStep::ReplaceRoute`] step's
    /// native progress, performed internally rather than via the caller's
    /// `Compensation` callback (see [`Self::execute_apply_plan`]'s
    /// rustdoc). Only reached when the caller supplied
    /// `options.compensation`, matching `execute_plan`'s existing
    /// "compensation is not inferred" contract.
    fn compensate_replace_route(
        &self,
        old: &Route,
        new: &RouteConfig,
        progress: ReplaceRouteProgress,
    ) -> Result<()> {
        let old_config = route_config_from_route(old);
        // `RouteReplaceOrder` is `#[non_exhaustive]`; any future ordering
        // strategy this crate does not yet know falls back to the trait's
        // own documented default (`RemoveBeforeAdd`), same as
        // `Self::execute_replace_route_step`.
        let add_before_remove = matches!(
            self.backend.route_replace_order(),
            RouteReplaceOrder::AddBeforeRemove
        );
        match progress {
            ReplaceRouteProgress::NoLegsAttempted => Ok(()),
            ReplaceRouteProgress::FirstLegOnly if add_before_remove => {
                // Only the add leg completed: undo it.
                self.remove_route(*new)
            }
            ReplaceRouteProgress::FirstLegOnly => {
                // Only the remove leg completed: restore `old`.
                self.add_route(old_config)
            }
            ReplaceRouteProgress::BothLegsUnverified | ReplaceRouteProgress::BothLegsConfirmed => {
                // Both legs completed (confirmed or not): undo the add,
                // then restore `old`. Best-effort — if undoing the add
                // fails, `old` is not re-added and the failure is reported
                // as this step's compensation failure.
                self.remove_route(*new)?;
                self.add_route(old_config)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use net_lattice_core::Error;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};
    use net_lattice_model::Network;
    use net_lattice_model::apply::NonConvergentReason;
    use net_lattice_model::dns::{DnsConfig, NewDnsConfig};
    use net_lattice_model::event::{Event, EventFilter};
    use net_lattice_model::ifaddr::{InterfaceAddress, NewInterfaceAddress};
    use net_lattice_model::interface::{Interface, InterfaceConfig, InterfaceKind};
    use net_lattice_model::mutation::MutationPlan;
    use net_lattice_model::neighbor::{NeighborEntry, StaticNeighbor};
    use net_lattice_model::route::RouteId;
    use net_lattice_platform::{
        AdditionProvider, AddressMutator, AddressProvider, CapabilityProvider, DnsMutator,
        DnsProvider, EventProvider, EventReceiver, InterfaceMutator, InterfaceProvider,
        NeighborMutator, NeighborProvider, RouteMutator, RouteProvider,
    };

    use super::*;
    use crate::executor::ExecutionOptions;

    /// A fake backend with mutable interior route state, so `ReplaceRoute`
    /// tests can exercise precondition re-checks and read-after-write
    /// verification against state that actually changes as `add_route`/
    /// `remove_route` are called — unlike the crate root's `TestBackend`,
    /// whose `routes()` is a fixed constant.
    struct FakeRouteBackend {
        routes: RefCell<Vec<Route>>,
        capabilities: Capability,
        supports_route_metric: bool,
        route_replace_order: RouteReplaceOrder,
        fail_add: bool,
        fail_remove: bool,
        /// Fails only the *second* leg attempted, regardless of ordering,
        /// so both `RemoveBeforeAdd` and `AddBeforeRemove` can exercise a
        /// second-leg failure independent of which native call that is.
        fail_second_leg: bool,
        /// If set, `routes()` returns this error instead of the observed
        /// list, to exercise a snapshot-read failure.
        fail_routes_read: bool,
        /// If set, `routes()` always reports the plan's original `old`
        /// route only, ignoring whatever `add_route`/`remove_route` have
        /// actually done — simulating a backend whose native
        /// acknowledgement is not yet reflected in a subsequent read, so
        /// read-after-write cannot confirm a completed replacement.
        stale_readback: bool,
        /// Counts every `add_route`/`remove_route` call, in call order
        /// (not native-op-kind order), so `fail_second_leg` can fail
        /// exactly the second mutating call regardless of which leg
        /// (add or remove) that happens to be for the ordering under test.
        leg_calls: RefCell<u32>,
    }

    fn network(octet: u8) -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, octet),
            Ipv4PrefixLength::new(32).expect("valid prefix"),
        ))
    }

    fn old_route() -> Route {
        Route::new(RouteId::new(1), network(0)).with_interface_index(1)
    }

    fn new_route_config() -> RouteConfig {
        RouteConfig::new(network(0)).with_interface_index(2)
    }

    /// A replacement candidate sharing `old_route`'s gateway/interface
    /// identity but requesting a different metric — the shape the Darwin-
    /// metric-only capability rejection actually matches (a route move
    /// alone, to a different interface, is not itself a metric change).
    fn metric_only_change(metric: u32) -> RouteConfig {
        RouteConfig::new(network(0))
            .with_interface_index(1)
            .with_metric(metric)
    }

    impl FakeRouteBackend {
        fn new(order: RouteReplaceOrder, supports_metric: bool) -> Self {
            Self {
                routes: RefCell::new(vec![old_route()]),
                capabilities: Capability::ROUTE_MUTATION,
                supports_route_metric: supports_metric,
                route_replace_order: order,
                fail_add: false,
                fail_remove: false,
                fail_second_leg: false,
                fail_routes_read: false,
                stale_readback: false,
                leg_calls: RefCell::new(0),
            }
        }

        /// Whether the call about to be made (`add_route`/`remove_route`)
        /// is the second mutating call this backend has seen, and should
        /// fail because `fail_second_leg` is set.
        fn should_fail_this_leg(&self) -> bool {
            let mut calls = self.leg_calls.borrow_mut();
            *calls += 1;
            self.fail_second_leg && *calls == 2
        }
    }

    /// Builds an observed [`Route`] carrying forward the fields a
    /// [`RouteConfig`] intent actually populated, mirroring
    /// `net-lattice-model::apply`'s own conversion in the other direction.
    fn route_from_config(id: RouteId, config: &RouteConfig) -> Route {
        let mut route = Route::new(id, config.destination);
        if let Some(gateway) = config.gateway {
            route = route.with_gateway(gateway);
        }
        if let Some(metric) = config.metric {
            route = route.with_metric(metric);
        }
        if let Some(interface_index) = config.interface_index {
            route = route.with_interface_index(interface_index);
        }
        route
    }

    impl RouteProvider for FakeRouteBackend {
        type Route = Route;

        fn routes(&self) -> Result<Vec<Self::Route>> {
            if self.fail_routes_read {
                Err(Error::InvalidState)
            } else if self.stale_readback {
                Ok(vec![old_route()])
            } else {
                Ok(self.routes.borrow().clone())
            }
        }
    }

    impl RouteMutator for FakeRouteBackend {
        type RouteConfig = RouteConfig;

        fn add_route(&self, route: Self::RouteConfig) -> Result<()> {
            let should_fail_second = self.should_fail_this_leg();
            if self.fail_add || should_fail_second {
                return Err(Error::InvalidState);
            }
            let id = RouteId::new(u64::from(self.routes.borrow().len() as u32) + 100);
            self.routes.borrow_mut().push(route_from_config(id, &route));
            Ok(())
        }

        fn remove_route(&self, route: Self::RouteConfig) -> Result<()> {
            let should_fail_second = self.should_fail_this_leg();
            if self.fail_remove || should_fail_second {
                return Err(Error::InvalidState);
            }
            self.routes.borrow_mut().retain(|candidate| {
                !(candidate.destination == route.destination
                    && candidate.gateway == route.gateway
                    && candidate.metric == route.metric
                    && candidate.interface_index == route.interface_index)
            });
            Ok(())
        }

        fn supports_route_metric(&self) -> bool {
            self.supports_route_metric
        }

        fn route_replace_order(&self) -> RouteReplaceOrder {
            self.route_replace_order
        }
    }

    impl InterfaceProvider for FakeRouteBackend {
        type Interface = Interface;

        fn interfaces(&self) -> Result<Vec<Self::Interface>> {
            Ok(vec![Interface::new(
                net_lattice_model::interface::InterfaceId::new(1),
                1,
                "test0",
                InterfaceKind::Ethernet,
            )])
        }
    }

    impl InterfaceMutator for FakeRouteBackend {
        type InterfaceConfig = InterfaceConfig;

        fn set_interface_config(&self, _config: Self::InterfaceConfig) -> Result<Self::Interface> {
            Err(Error::Unsupported)
        }
    }

    impl DnsProvider for FakeRouteBackend {
        type DnsConfig = DnsConfig;

        fn dns_config(&self) -> Result<Self::DnsConfig> {
            Ok(DnsConfig::new())
        }
    }

    impl DnsMutator for FakeRouteBackend {
        type NewDnsConfig = NewDnsConfig;

        fn set_dns_config(&self, _config: Self::NewDnsConfig) -> Result<Self::DnsConfig> {
            Err(Error::Unsupported)
        }
    }

    impl NeighborProvider for FakeRouteBackend {
        type NeighborEntry = NeighborEntry;

        fn neighbors(&self) -> Result<Vec<Self::NeighborEntry>> {
            Ok(Vec::new())
        }
    }

    impl NeighborMutator for FakeRouteBackend {
        type StaticNeighbor = StaticNeighbor;
        type NeighborEntry = NeighborEntry;

        fn add_static_neighbor(
            &self,
            _neighbor: Self::StaticNeighbor,
        ) -> Result<Self::NeighborEntry> {
            Err(Error::Unsupported)
        }

        fn remove_static_neighbor(&self, _neighbor: Self::StaticNeighbor) -> Result<()> {
            Err(Error::Unsupported)
        }
    }

    impl AddressProvider for FakeRouteBackend {
        type InterfaceAddress = InterfaceAddress;

        fn addresses(&self) -> Result<Vec<Self::InterfaceAddress>> {
            Ok(Vec::new())
        }
    }

    impl AddressMutator for FakeRouteBackend {
        type NewInterfaceAddress = NewInterfaceAddress;
        type InterfaceAddress = InterfaceAddress;

        fn add_address(
            &self,
            _address: Self::NewInterfaceAddress,
        ) -> Result<Self::InterfaceAddress> {
            Err(Error::Unsupported)
        }

        fn remove_address(&self, _address: Self::InterfaceAddress) -> Result<()> {
            Err(Error::Unsupported)
        }
    }

    impl CapabilityProvider for FakeRouteBackend {
        fn capabilities(&self) -> Capability {
            self.capabilities
        }
    }

    impl EventProvider for FakeRouteBackend {
        type Event = Event;
        type EventFilter = EventFilter;

        fn watch(&self) -> Result<EventReceiver<Self::Event>> {
            Err(Error::Unsupported)
        }

        fn watch_filtered(&self, _filter: Self::EventFilter) -> Result<EventReceiver<Self::Event>> {
            Err(Error::Unsupported)
        }
    }

    impl AdditionProvider for FakeRouteBackend {}

    fn lattice(backend: FakeRouteBackend) -> Lattice<FakeRouteBackend> {
        Lattice { backend }
    }

    fn replace_route_plan() -> ApplyPlan {
        ApplyPlan::from_steps([ApplyStep::ReplaceRoute {
            old: old_route(),
            new: new_route_config(),
        }])
    }

    // ---- success, both orderings ----

    #[test]
    fn replace_route_succeeds_with_remove_before_add() {
        let lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::RemoveBeforeAdd,
            true,
        ));
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(report.is_success(), "{report:?}");
        assert!(matches!(report.rollback(), RollbackStatus::NotNeeded));
        let routes = lattice.routes().expect("routes");
        assert!(routes.iter().any(|route| route.interface_index == Some(2)));
        assert!(!routes.iter().any(|route| route.interface_index == Some(1)));
    }

    #[test]
    fn replace_route_succeeds_with_add_before_remove() {
        let lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::AddBeforeRemove,
            false,
        ));
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(report.is_success(), "{report:?}");
        let routes = lattice.routes().expect("routes");
        assert!(routes.iter().any(|route| route.interface_index == Some(2)));
        assert!(!routes.iter().any(|route| route.interface_index == Some(1)));
    }

    // ---- capability rejection (Darwin-metric-only shape) ----

    #[test]
    fn replace_route_metric_change_rejected_when_backend_does_not_support_metric() {
        let lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::AddBeforeRemove,
            false,
        ));
        let plan = ApplyPlan::from_steps([ApplyStep::ReplaceRoute {
            old: old_route(),
            new: metric_only_change(7),
        }]);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&plan, &mut options);

        assert_eq!(report.rejected_count(), 1);
        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::Rejected {
                error: Error::Unsupported
            })
        ));
    }

    #[test]
    fn bare_add_route_metric_rejected_when_backend_does_not_support_metric() {
        let lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::AddBeforeRemove,
            false,
        ));
        let plan = ApplyPlan::from_steps([ApplyStep::Single(Mutation::AddRoute(
            RouteConfig::new(network(5)).with_metric(7),
        ))]);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&plan, &mut options);

        assert_eq!(report.rejected_count(), 1);
    }

    #[test]
    fn replace_route_metric_change_accepted_when_backend_supports_metric() {
        let lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::RemoveBeforeAdd,
            true,
        ));
        let plan = ApplyPlan::from_steps([ApplyStep::ReplaceRoute {
            old: old_route(),
            new: metric_only_change(7),
        }]);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&plan, &mut options);

        assert!(report.is_success(), "{report:?}");
    }

    #[test]
    fn replace_route_without_route_mutation_capability_is_rejected() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.capabilities = Capability::empty();
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert_eq!(report.rejected_count(), 1);
    }

    // ---- stale precondition ----

    #[test]
    fn replace_route_reports_stale_precondition_when_old_route_already_gone() {
        let backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.routes.borrow_mut().clear();
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert_eq!(report.non_convergent_count(), 1);
        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::NonConvergent {
                reason: NonConvergentReason::StalePrecondition
            })
        ));
    }

    // ---- leg failures, both orderings ----

    #[test]
    fn replace_route_first_leg_failure_reports_no_partial_application_remove_before_add() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.fail_remove = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::Failed {
                may_have_applied: false,
                ..
            })
        ));
    }

    #[test]
    fn replace_route_second_leg_failure_reports_partial_application_remove_before_add() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.fail_second_leg = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::Failed {
                may_have_applied: true,
                ..
            })
        ));
        // Remove-before-add's first leg (remove) completed: the old route
        // is gone even though the add failed.
        let routes = lattice.routes().expect("routes");
        assert!(!routes.iter().any(|route| route.interface_index == Some(1)));
    }

    #[test]
    fn replace_route_first_leg_failure_reports_no_partial_application_add_before_remove() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::AddBeforeRemove, false);
        backend.fail_add = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::Failed {
                may_have_applied: false,
                ..
            })
        ));
    }

    #[test]
    fn replace_route_second_leg_failure_reports_partial_application_add_before_remove() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::AddBeforeRemove, false);
        backend.fail_second_leg = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::Failed {
                may_have_applied: true,
                ..
            })
        ));
        // Add-before-remove's first leg (add) completed: the new route is
        // present even though the remove failed.
        let routes = lattice.routes().expect("routes");
        assert!(routes.iter().any(|route| route.interface_index == Some(2)));
    }

    // ---- cancellation ----

    #[test]
    fn replace_route_stops_at_cancellation_boundary() {
        let lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::RemoveBeforeAdd,
            true,
        ));
        let mut cancel = |_index: usize, _operation: &Mutation| true;
        let mut options = ExecutionOptions::default().cancellation(&mut cancel);
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::NotAttempted)
        ));
        // Nothing was ever attempted natively.
        let routes = lattice.routes().expect("routes");
        assert!(routes.iter().any(|route| route.interface_index == Some(1)));
    }

    // ---- compensation: best-effort and none-supplied ----

    #[test]
    fn replace_route_compensation_not_attempted_without_a_supplied_callback() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.fail_second_leg = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
    }

    #[test]
    fn replace_route_second_leg_failure_is_compensated_when_callback_supplied() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.fail_second_leg = true;
        let lattice = lattice(backend);
        let mut compensate =
            |_index: usize, _operation: &Mutation, _prior: Option<&MutationSnapshot>| Ok(());
        let mut options = ExecutionOptions::default().compensation(&mut compensate);
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(report.rollback(), RollbackStatus::Completed));
        // Best-effort compensation restored the old route (remove-before-
        // add's completed leg was the remove; compensation re-adds `old`).
        let routes = lattice.routes().expect("routes");
        assert!(routes.iter().any(|route| route.interface_index == Some(1)));
    }

    #[test]
    fn replace_route_compensation_does_not_invoke_the_callers_callback() {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.fail_second_leg = true;
        let lattice = lattice(backend);
        let invocations = RefCell::new(0);
        let mut compensate =
            |_index: usize, _operation: &Mutation, _prior: Option<&MutationSnapshot>| {
                *invocations.borrow_mut() += 1;
                Ok(())
            };
        let mut options = ExecutionOptions::default().compensation(&mut compensate);
        lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert_eq!(*invocations.borrow(), 0);
    }

    #[test]
    fn replace_route_compensation_failure_is_reported() {
        // The second leg (add) fails, leaving the first leg (remove)
        // completed (`FirstLegOnly`); compensation for `RemoveBeforeAdd` +
        // `FirstLegOnly` re-adds `old` via `add_route`, which also fails
        // here (`fail_add`), so compensation itself fails.
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.fail_add = true;
        let lattice = lattice(backend);
        let mut compensate =
            |_index: usize, _operation: &Mutation, _prior: Option<&MutationSnapshot>| Ok(());
        let mut options = ExecutionOptions::default().compensation(&mut compensate);
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(
            report.rollback(),
            RollbackStatus::Failed {
                operation_index: 0,
                ..
            }
        ));
    }

    // ---- read-after-write: ambiguous / unverifiable ----

    #[test]
    fn replace_route_reports_non_convergent_when_readback_cannot_confirm_replacement() {
        // Both native calls succeed, but `stale_readback` makes `routes()`
        // keep reporting the plan's original state regardless — read-
        // after-write must catch that the replacement is unconfirmed even
        // though neither `add_route` nor `remove_route` returned an error.
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.stale_readback = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert_eq!(report.non_convergent_count(), 1);
        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::NonConvergent {
                reason: NonConvergentReason::AmbiguousReplacementUnverifiable
            })
        ));
    }

    #[test]
    fn replace_route_non_convergent_ambiguous_stops_the_plan_and_is_not_compensated_without_a_callback()
     {
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::AddBeforeRemove, false);
        backend.stale_readback = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
    }

    // ---- ADR NL-A-15's own required coverage: Single-step parity and a
    // mixed Single/ReplaceRoute plan (NL-73's reviewed gap #1) ----

    #[test]
    fn single_step_parity_with_execute_plan_and_mixed_plan_compensates_both_step_kinds() {
        // Part 1: a bare `ApplyStep::Single` step run through
        // `execute_apply_plan` produces the same outcome/report shape as an
        // equivalent `MutationPlan` run through `execute_plan` — the ADR's
        // own required "Single step execution parity" coverage.
        let single_operation =
            Mutation::AddRoute(RouteConfig::new(network(9)).with_interface_index(3));

        let apply_lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::RemoveBeforeAdd,
            true,
        ));
        let apply_plan = ApplyPlan::from_steps([ApplyStep::Single(single_operation.clone())]);
        let mut apply_options = ExecutionOptions::default();
        let apply_report = apply_lattice.execute_apply_plan(&apply_plan, &mut apply_options);

        let plan_lattice = lattice(FakeRouteBackend::new(
            RouteReplaceOrder::RemoveBeforeAdd,
            true,
        ));
        let mutation_plan = MutationPlan::from_operations([single_operation]);
        let mut plan_options = ExecutionOptions::default();
        let plan_report = plan_lattice.execute_plan(&mutation_plan, &mut plan_options);

        assert!(apply_report.is_success(), "{apply_report:?}");
        assert!(plan_report.is_success(), "{plan_report:?}");
        assert_eq!(apply_report.applied_count(), 1);
        assert_eq!(plan_report.applied_count(), 1);
        assert!(matches!(
            apply_report.outcome(0),
            Some(ApplyStepOutcome::Applied)
        ));
        assert!(matches!(
            plan_report.outcome(0),
            Some(MutationOutcome::Applied)
        ));
        assert!(matches!(apply_report.rollback(), RollbackStatus::NotNeeded));
        assert!(matches!(plan_report.rollback(), RollbackStatus::NotNeeded));
        assert_eq!(
            apply_lattice.routes().expect("routes").len(),
            plan_lattice.routes().expect("routes").len(),
        );

        // Part 2: a mixed plan (`Single`, `ReplaceRoute`, then a failing
        // `Single`) exercises both `AppliedApplyStep` variants together and
        // the reverse-order compensation loop across mixed step kinds.
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.capabilities = Capability::ROUTE_MUTATION | Capability::INTERFACE_ADMIN_STATE;
        let lattice = lattice(backend);

        let single_add_config = RouteConfig::new(network(9)).with_interface_index(3);
        let single_add = Mutation::AddRoute(single_add_config);
        let failing_interface_patch = Mutation::SetInterfaceConfig(
            net_lattice_model::interface::InterfaceConfig::new(
                net_lattice_model::interface::InterfaceId::new(1),
                Some(net_lattice_model::interface::DesiredAdminState::Up),
                None,
            )
            .expect("valid admin-state-only patch"),
        );
        let plan = ApplyPlan::from_steps([
            ApplyStep::Single(single_add),
            ApplyStep::ReplaceRoute {
                old: old_route(),
                new: new_route_config(),
            },
            ApplyStep::Single(failing_interface_patch),
        ]);

        let compensated_indices: RefCell<Vec<usize>> = RefCell::new(Vec::new());
        let mut compensate =
            |index: usize, operation: &Mutation, _prior: Option<&MutationSnapshot>| {
                compensated_indices.borrow_mut().push(index);
                // Perform the reversal for real, the way a real caller
                // would, so the resulting route state below actually
                // proves the callback ran and did its job.
                if let Mutation::AddRoute(config) = operation {
                    lattice.remove_route(*config)?;
                }
                Ok(())
            };
        let mut options = ExecutionOptions::default().compensation(&mut compensate);
        let report = lattice.execute_apply_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(ApplyStepOutcome::Applied)));
        assert!(matches!(report.outcome(1), Some(ApplyStepOutcome::Applied)));
        assert!(matches!(
            report.outcome(2),
            Some(ApplyStepOutcome::Failed { .. })
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));

        // The `Single` step (index 0) is compensated via the caller's own
        // callback; the `ReplaceRoute` step (index 1) is reversed
        // internally (see `execute_apply_plan`'s rustdoc) and never reaches
        // the callback — so only index 0 shows up here, even though both
        // were rolled back, and it is only invoked after the `ReplaceRoute`
        // step's own internal reversal completes (reverse plan order).
        assert_eq!(*compensated_indices.borrow(), vec![0]);

        // Both reversals actually happened: `ReplaceRoute`'s `new` route
        // (interface_index 2) is gone and `old` (interface_index 1) is
        // restored (internal compensation); the `Single` step's added
        // route (interface_index 3) is gone too (caller callback).
        let routes = lattice.routes().expect("routes");
        assert!(routes.iter().any(|route| route.interface_index == Some(1)));
        assert!(!routes.iter().any(|route| route.interface_index == Some(2)));
        assert!(!routes.iter().any(|route| route.interface_index == Some(3)));
    }

    // ---- read-after-write: precondition/snapshot re-read failure (NL-73's
    // reviewed gap #2) ----

    #[test]
    fn replace_route_reports_snapshot_failed_when_precondition_read_fails() {
        // `FakeRouteBackend::fail_routes_read` fails every `routes()` call,
        // so `execute_replace_route_step`'s step-3 precondition re-read
        // fails before either native leg is attempted — the `ReplaceRoute`
        // counterpart of a snapshot-read failure, distinct from the
        // read-after-write ambiguity covered by the `stale_readback` tests
        // above (that branch is only reached once the precondition re-read
        // itself has already succeeded).
        let mut backend = FakeRouteBackend::new(RouteReplaceOrder::RemoveBeforeAdd, true);
        backend.fail_routes_read = true;
        let lattice = lattice(backend);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_apply_plan(&replace_route_plan(), &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(ApplyStepOutcome::Failed {
                error: Error::InvalidState,
                may_have_applied: false,
            })
        ));
        let operation_report = report.operation_report(0).expect("operation report");
        assert_eq!(operation_report.phase, MutationExecutionPhase::Snapshot);
        assert_eq!(
            operation_report.stop_reason,
            Some(MutationStopReason::SnapshotFailed)
        );
        // No leg was attempted, so nothing needs compensating even though
        // execution stopped.
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
    }
}
