# Code style and architecture

This document describes patterns present in the repository; the public API
and platform contracts in `ARCHITECTURE.md` remain authoritative.

## Boundaries

- `core` owns shared errors and identifiers; `ip` owns address and prefix
  types; `model` describes observed state and mutation intent.
- `platform` defines generic provider traits and capabilities without a
  dependency on `model`. OS backends implement those contracts; the facade
  binds associated types and selects a backend.
- Keep planning separate from execution: desired state is compared with
  observed state to produce inspectable plans; the facade executes them and
  reports outcomes, including compensation failures.
- Async adaptation is separated from the synchronous platform contracts.

## Rust conventions

- Prefer typed values, errors and explicit capabilities to strings or
  assumptions about OS support. Observed state and mutation intent are
  distinct types; successful mutations return fresh observations.
- Document public items, invariants, platform differences, permissions and
  failure behavior in rustdoc. Keep unsafe platform interactions localized.
- Use small provider traits and injectable implementations for tests; test
  pure planning separately from OS integration and privileged operations.
- Format with `cargo fmt`; follow the CI clippy, test and rustdoc gates.
  Test actual platform behavior on each supported OS where relevant.

Capabilities describe implementation support, not a guarantee of operating
system permissions. See the platform matrix and caveats in `README.md`.
