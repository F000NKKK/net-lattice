# Release and versioning rules

- One roadmap Sprint maps to one release version. Sprint `0.18` ships as
  crate version `0.18.x`, Sprint `0.19` ships as `0.19.x`, and so on. The
  YouTrack `Sprint` custom field and the crate's SemVer minor version march
  together pre-1.0 — do not invent a different mapping when filing or
  scoping issues.
- Net Lattice's Stage 0.21 compatibility audit (`ARCHITECTURE.md`'s roadmap
  gate for 1.0) is complete — the public-API freeze, `Addition` tier
  (ADR-0014), `Error` `#[non_exhaustive]` (ADR-0015), and full rustdoc
  coverage are all done. The path to `1.0.0` is closed; publication is a
  user-invoked release-script action, not further roadmap work. Before this
  point, a Sprint's release was allowed to change the public API
  meaningfully as normal roadmap evolution, provided the change was recorded
  in an ADR (see `rules/youtrack.md`'s ADR section) and in `CHANGELOG.md`; a
  pre-1.0 minor bump was never a compatibility guarantee.
- Once a crate reaches `1.0.0`, this changes: within one major version
  (`1.x`, `2.x`, ...), the public API must not change in a breaking way —
  ordinary SemVer discipline applies (new public items are additive minor
  bumps, fixes are patch bumps; nothing already public may be removed or
  have its behavior/meaning changed without a major version bump). A
  breaking change after 1.0 requires bumping the major version and is a
  deliberate, explicitly user-authorized decision — not something an agent
  introduces quietly inside what looks like a routine Sprint release the way
  pre-1.0 minor bumps can be. Treat any post-1.0 architect/implementer work
  that would break a public contract as requiring the same explicit
  user sign-off a pre-1.0 breaking change gets today, escalated rather than
  assumed.
- `Cargo.toml` version numbers are set by the user, not by an agent. Agents
  never edit a crate's `version` field themselves. If a crate gained public
  API that plausibly warrants a version bump (e.g. a new public type/trait
  was added but the crate's version wasn't bumped), flag that
  version-consistency question explicitly in the relevant issue's evidence
  comment instead of guessing at or editing the number.
- When a crate's version does change (by the user), `CHANGELOG.md`,
  `SECURITY.md`'s supported-version table, and `SUPPORT.md`'s project-status
  summary must be reviewed together per `rules/files.md` — a stale "current
  supported line" statement in `SECURITY.md` or `SUPPORT.md` is exactly the
  kind of drift this rule exists to prevent.
