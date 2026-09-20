# Security Policy

## Supported Versions

Net Lattice follows a rolling support policy. Security fixes are provided only
for the latest stable release series. The current supported line is 1.0.x,
and support for every pre-1.0 series (0.1.x-0.22.x) has ended (see
[CHANGELOG.md](CHANGELOG.md) for the dated history).

| Version | Supported |
| ------- | --------- |
| 1.0.x | ✅ |
| < 1.0.0 | ❌ |

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

Net Lattice provides route, interface, interface-address, DNS resolver,
static ARP/NDP neighbor, and native-firewall inspection and mutation, plus
whole-system `CurrentState` snapshots, on Linux (Netlink, `/etc/resolv.conf`),
Windows (IP Helper API, WFP), and macOS (BSD routing sockets, `pf`). It also
publishes a declarative layer on top: `DesiredState`, a pure `Diff`, and a
pure `ApplyPlan` compiled from that `Diff`. Computing/compiling either is
side-effect-free; only executing a compiled `ApplyPlan` is privileged, and
exactly as privileged as the underlying mutation it lowers to — the
declarative layer adds no new privilege surface or capability gate.

In scope: unintended network mutation, partial DNS/firewall application,
privilege confusion, memory-safety issues in route/interface/DNS/neighbor/
address/firewall/monitoring data handling, a static-neighbor removal
silently evicting a dynamically-learned (non-`Permanent`) entry, native-
firewall scoping being bypassed (each backend owns one managed object — an
nftables table, a WFP provider's filters, a `pf` anchor — and must never
touch firewall state owned by other tools), a `FirewallRule` compiling to a
different match than it describes, a struct-layout mismatch in
`net-lattice-backend-darwin`'s hand-built `ioctl` structs, and a declarative
apply converging to an unintended state (including a route replacement
leaving both or neither route present).

Out of scope: VLAN, VRF, namespaces, and isolated destructive topology
orchestration (none exist yet); tunnel interface management (see the
separate tunnel-lattice project).
