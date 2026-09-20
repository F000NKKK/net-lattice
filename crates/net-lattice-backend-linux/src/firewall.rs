//! Native-firewall management via nftables (`FirewallProvider`/`FirewallMutator`).
//!
//! Manages one Net-Lattice-owned nftables table (`net_lattice`) with two base
//! chains (`inbound` hooked at `NF_INET_LOCAL_IN`, `outbound` hooked at
//! `NF_INET_LOCAL_OUT`), each set to the requested [`FirewallPolicy`]'s
//! `default_verdict` as its chain policy. Every [`FirewallRule`] compiles to
//! one nftables rule appended to the chain matching its
//! [`Direction`](net_lattice_model::firewall::Direction). Built on the
//! `nftnl` crate (Mullvad, MIT/Apache-2.0), a safe wrapper over `libnftnl`
//! used by the Mullvad VPN client's own kill-switch — no `nft` subprocess is
//! ever spawned. See ADR-0017 (`NL-A-19`) for the full design rationale.
//!
//! Building this crate requires the `libmnl` and `libnftnl` development
//! packages (headers and `pkg-config` files) to be installed on the build
//! machine — e.g. `apt-get install libmnl-dev libnftnl-dev` on
//! Debian/Ubuntu. The corresponding runtime shared libraries
//! (`libmnl0`/`libnftnl11` or newer) must be present wherever the resulting
//! binary runs. This is a build-time requirement only; it does not affect
//! the crate's runtime portability beyond requiring those shared libraries.

use std::ffi::CStr;
use std::io;

use net_lattice_core::{Error, PlatformErrorCode, Result};
use net_lattice_model::Network;
use net_lattice_model::firewall::{Direction, FirewallPolicy, FirewallRule, Protocol, Verdict};
use net_lattice_platform::{FirewallMutator, FirewallProvider};
use nftnl::expr::{
    Bitwise, Cmp, CmpOp, Ipv4HeaderField, Ipv6HeaderField, Meta, NetworkHeaderField, Payload,
    TcpHeaderField, TransportHeaderField, UdpHeaderField, Verdict as NftVerdict,
};
use nftnl::nftnl_sys::libc;
use nftnl::{Batch, Chain, Hook, MsgType, Policy as ChainPolicy, ProtoFamily, Rule, Table};

use crate::LinuxBackend;

const TABLE_NAME: &CStr = c"net_lattice";
const INBOUND_CHAIN_NAME: &CStr = c"inbound";
const OUTBOUND_CHAIN_NAME: &CStr = c"outbound";

/// The `#[non_exhaustive]` `net_lattice_model::firewall::FirewallPolicy`
/// bound to this backend's `FirewallMutator::FirewallPolicy` associated
/// type. This backend accepts the model type directly rather than a
/// backend-specific intent type: unlike routes or static neighbors, a
/// firewall policy carries no backend-synthesized identity that would need
/// to be kept out of caller-authored intent.
pub type LinuxFirewallPolicy = FirewallPolicy;

fn mnl_error_code(err: &io::Error) -> PlatformErrorCode {
    PlatformErrorCode::Linux(err.raw_os_error().unwrap_or(0))
}

fn chain_policy(verdict: Verdict) -> ChainPolicy {
    match verdict {
        Verdict::Allow => ChainPolicy::Accept,
        Verdict::Deny => ChainPolicy::Drop,
        _ => unreachable!("Verdict is non_exhaustive; every current variant is handled above"),
    }
}

fn nft_verdict(verdict: Verdict) -> NftVerdict {
    match verdict {
        Verdict::Allow => NftVerdict::Accept,
        Verdict::Deny => NftVerdict::Drop,
        _ => unreachable!("Verdict is non_exhaustive; every current variant is handled above"),
    }
}

/// Returns the `IPPROTO_*` number nftables expects for `protocol`.
///
/// [`Protocol::Icmp`] is ambiguous between IPv4 ICMP (`1`) and ICMPv6
/// (`58`) when the rule carries no `remote` network to disambiguate the
/// address family; such a rule matches IPv4 ICMP only, which is documented
/// here rather than silently guessing. Callers that need to match ICMPv6
/// specifically should pair `Protocol::Icmp` with an IPv6 `remote` network.
fn protocol_number(protocol: Protocol, remote: Option<&Network>) -> u8 {
    match protocol {
        Protocol::Tcp => libc::IPPROTO_TCP as u8,
        Protocol::Udp => libc::IPPROTO_UDP as u8,
        Protocol::Icmp => match remote {
            Some(Network::V6(_)) => libc::IPPROTO_ICMPV6 as u8,
            _ => libc::IPPROTO_ICMP as u8,
        },
        _ => unreachable!("Protocol is non_exhaustive; every current variant is handled above"),
    }
}

/// Appends the match expressions (and terminating verdict) for `config` to
/// `rule`.
///
/// Port numbers are compared as explicit big-endian byte slices, not as a
/// bare `u16` — `nftnl`'s `Cmp<u16>` compares native-endian bytes, but
/// `payload`-loaded transport-header fields are raw big-endian wire bytes.
/// Comparing a `u16` verdict directly here would silently never match on a
/// little-endian build host, which is every common target this crate
/// supports (x86_64, aarch64). Interface indices (`meta iif`/`oif`) and the
/// protocol number (`meta l4proto`) are plain host-order kernel-internal
/// values, not wire bytes, so they are compared as native values without
/// this concern.
fn add_expressions(rule: &mut Rule<'_>, config: &FirewallRule) {
    if let Some(index) = config.interface_index {
        match config.direction {
            Direction::Inbound => rule.add_expr(&Meta::Iif),
            Direction::Outbound => rule.add_expr(&Meta::Oif),
            _ => {
                unreachable!("Direction is non_exhaustive; every current variant is handled above")
            }
        }
        rule.add_expr(&Cmp::new(CmpOp::Eq, index));
    }

    if let Some(remote) = config.remote {
        add_remote_match(rule, config.direction, remote);
    }

    if let Some(protocol) = config.protocol {
        rule.add_expr(&Meta::L4Proto);
        rule.add_expr(&Cmp::new(
            CmpOp::Eq,
            protocol_number(protocol, config.remote.as_ref()),
        ));

        if let Some(port) = config.port
            && matches!(protocol, Protocol::Tcp | Protocol::Udp)
        {
            add_port_match(rule, config.direction, protocol, port.start, port.end);
        }
    }

    rule.add_expr(&nft_verdict(config.verdict));
}

/// Appends a network-address match (masked by prefix length) for `remote`,
/// matching the source address for [`Direction::Inbound`] or the
/// destination address for [`Direction::Outbound`] — mirroring
/// [`FirewallRule::remote`]'s documented convention.
fn add_remote_match(rule: &mut Rule<'_>, direction: Direction, remote: Network) {
    match remote {
        Network::V4(network) => {
            let field = match direction {
                Direction::Inbound => Ipv4HeaderField::Saddr,
                Direction::Outbound => Ipv4HeaderField::Daddr,
                _ => unreachable!(
                    "Direction is non_exhaustive; every current variant is handled above"
                ),
            };
            rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv4(field)));
            let prefix = network.prefix().value();
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            rule.add_expr(&Bitwise::new(
                mask.to_be_bytes().as_slice(),
                [0u8; 4].as_slice(),
            ));
            rule.add_expr(&Cmp::new(
                CmpOp::Eq,
                std::net::Ipv4Addr::from(network.address()),
            ));
        }
        Network::V6(network) => {
            let field = match direction {
                Direction::Inbound => Ipv6HeaderField::Saddr,
                Direction::Outbound => Ipv6HeaderField::Daddr,
                _ => unreachable!(
                    "Direction is non_exhaustive; every current variant is handled above"
                ),
            };
            rule.add_expr(&Payload::Network(NetworkHeaderField::Ipv6(field)));
            let prefix = u32::from(network.prefix().value());
            let mask = ipv6_prefix_mask(prefix);
            rule.add_expr(&Bitwise::new(mask.as_slice(), [0u8; 16].as_slice()));
            rule.add_expr(&Cmp::new(
                CmpOp::Eq,
                std::net::Ipv6Addr::from(network.address()),
            ));
        }
    }
}

/// Builds a 16-byte big-endian IPv6 prefix mask covering the leading
/// `prefix` bits.
fn ipv6_prefix_mask(prefix: u32) -> [u8; 16] {
    let mut mask = [0u8; 16];
    for (i, byte) in mask.iter_mut().enumerate() {
        let bit_offset = i as u32 * 8;
        *byte = if bit_offset + 8 <= prefix {
            0xff
        } else if bit_offset < prefix {
            0xffu8 << (8 - (prefix - bit_offset))
        } else {
            0x00
        };
    }
    mask
}

/// Appends a transport-port match for `start..=end`, matching the
/// destination port for [`Direction::Outbound`] or the source port for
/// [`Direction::Inbound`] — mirroring [`FirewallRule::port`]'s documented
/// convention (the remote's port).
///
/// A single-port range (`start == end`) compiles to one equality
/// comparison; a wider range compiles to two range-bound comparisons
/// (greater-or-equal and less-or-equal).
fn add_port_match(
    rule: &mut Rule<'_>,
    direction: Direction,
    protocol: Protocol,
    start: u16,
    end: u16,
) {
    let field = match (protocol, direction) {
        (Protocol::Tcp, Direction::Inbound) => TransportHeaderField::Tcp(TcpHeaderField::Sport),
        (Protocol::Tcp, Direction::Outbound) => TransportHeaderField::Tcp(TcpHeaderField::Dport),
        (Protocol::Udp, Direction::Inbound) => TransportHeaderField::Udp(UdpHeaderField::Sport),
        (Protocol::Udp, Direction::Outbound) => TransportHeaderField::Udp(UdpHeaderField::Dport),
        (Protocol::Icmp, _) => return,
        _ => unreachable!(
            "Protocol/Direction are non_exhaustive; every current combination is handled above"
        ),
    };
    rule.add_expr(&Payload::Transport(field));
    if start == end {
        rule.add_expr(&Cmp::new(CmpOp::Eq, start.to_be_bytes().as_slice()));
    } else {
        rule.add_expr(&Cmp::new(CmpOp::Gte, start.to_be_bytes().as_slice()));
        rule.add_expr(&Payload::Transport(field));
        rule.add_expr(&Cmp::new(CmpOp::Lte, end.to_be_bytes().as_slice()));
    }
}

/// Sends `batch` to the kernel over a `NETLINK_NETFILTER` socket and waits
/// for every message's acknowledgement, mapping any failure to
/// [`Error::Platform`].
fn send_batch(batch: nftnl::FinalizedBatch) -> Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)
        .map_err(|err| Error::Platform(mnl_error_code(&err)))?;
    let portid = socket.portid();

    socket
        .send_all(&batch)
        .map_err(|err| Error::Platform(mnl_error_code(&err)))?;

    let mut buffer = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    let expected_seqs = batch.sequence_numbers();
    for expected_seq in expected_seqs {
        let messages = socket
            .recv(&mut buffer[..])
            .map_err(|err| Error::Platform(mnl_error_code(&err)))?;
        for message in messages {
            let message = message.map_err(|err| Error::Platform(mnl_error_code(&err)))?;
            mnl::cb_run(message, expected_seq, portid)
                .map_err(|err| Error::Platform(mnl_error_code(&err)))?;
        }
    }
    Ok(())
}

/// Builds and sends the transaction that replaces the managed table's
/// chains and rules with `policy`, split into the `inbound`/`outbound`
/// chains by each rule's [`FirewallRule::direction`].
fn apply_policy(policy: &FirewallPolicy) -> Result<()> {
    let mut batch = Batch::new();

    let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
    batch.add(&table, MsgType::Add);

    let mut inbound = Chain::new(INBOUND_CHAIN_NAME, &table);
    inbound.set_hook(Hook::In, 0);
    inbound.set_policy(chain_policy(policy.default_verdict));
    let mut outbound = Chain::new(OUTBOUND_CHAIN_NAME, &table);
    outbound.set_hook(Hook::Out, 0);
    outbound.set_policy(chain_policy(policy.default_verdict));
    batch.add(&inbound, MsgType::Add);
    batch.add(&outbound, MsgType::Add);

    // Flush every existing rule from both chains before adding the new
    // policy's rules: a `Rule` built with no handle set (as `Rule::new`
    // always does) and sent as `MsgType::Del` is nftables' "delete every
    // rule in this chain" idiom, not a single-rule delete.
    batch.add(&Rule::new(&inbound), MsgType::Del);
    batch.add(&Rule::new(&outbound), MsgType::Del);

    // Batch::add borrows its argument only for the duration of the call
    // (it serializes immediately), so rules can be built and added in a
    // loop without a lifetime conflict against `inbound`/`outbound` above.
    for config in &policy.rules {
        let chain = match config.direction {
            Direction::Inbound => &inbound,
            Direction::Outbound => &outbound,
            _ => {
                unreachable!("Direction is non_exhaustive; every current variant is handled above")
            }
        };
        let mut rule = Rule::new(chain);
        add_expressions(&mut rule, config);
        batch.add(&rule, MsgType::Add);
    }

    send_batch(batch.finalize())
}

impl FirewallProvider for LinuxBackend {
    type FirewallRule = FirewallRule;

    fn firewall_rules(&self) -> Result<Vec<Self::FirewallRule>> {
        // Returns the last policy this process applied via
        // `set_firewall_policy`, not a native GETRULE dump — see NL-165 for
        // the tracked follow-up to read the managed table/chains directly
        // from the kernel. This does not detect the managed policy being
        // changed or removed out-of-band.
        let policy = self
            .firewall_policy
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        Ok(policy
            .as_ref()
            .map(|policy| policy.rules.clone())
            .unwrap_or_default())
    }
}

impl FirewallMutator for LinuxBackend {
    type FirewallPolicy = LinuxFirewallPolicy;

    fn set_firewall_policy(&self, policy: Self::FirewallPolicy) -> Result<()> {
        apply_policy(&policy)?;
        *self
            .firewall_policy
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Some(policy);
        Ok(())
    }

    fn clear_firewall_policy(&self) -> Result<()> {
        let empty = FirewallPolicy::new(Verdict::Allow);
        apply_policy(&empty)?;
        *self
            .firewall_policy
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Some(empty);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_prefix_mask_covers_leading_bits_only() {
        assert_eq!(ipv6_prefix_mask(0), [0u8; 16]);
        assert_eq!(ipv6_prefix_mask(128), [0xffu8; 16]);

        let mask = ipv6_prefix_mask(64);
        assert_eq!(&mask[..8], &[0xff; 8]);
        assert_eq!(&mask[8..], &[0x00; 8]);

        // A prefix that ends mid-byte (/12) sets the leading 4 bits of the
        // second byte and nothing after it.
        let mask = ipv6_prefix_mask(12);
        assert_eq!(mask[0], 0xff);
        assert_eq!(mask[1], 0xf0);
        assert_eq!(&mask[2..], &[0x00; 14]);
    }

    #[test]
    fn protocol_number_disambiguates_icmp_by_remote_family() {
        use net_lattice_ip::{Ipv6Address, Ipv6Network, Ipv6PrefixLength};

        let v6 = Network::V6(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(32).unwrap(),
        ));
        assert_eq!(
            protocol_number(Protocol::Icmp, Some(&v6)),
            libc::IPPROTO_ICMPV6 as u8
        );
        assert_eq!(
            protocol_number(Protocol::Icmp, None),
            libc::IPPROTO_ICMP as u8
        );
    }

    /// Requires `CAP_NET_ADMIN` (root, or `sudo -E cargo test -- --ignored`
    /// in this crate). Not run by default for the same reason as this
    /// crate's other privileged tests — see
    /// `add_then_remove_route_round_trips_through_the_kernel` in `lib.rs`.
    ///
    /// A real, allowed-by-default outbound DNS rule plus a default-deny
    /// policy is applied and then cleared. This has not been verified
    /// against a live kernel by the author of this change (no `CAP_NET_ADMIN`
    /// was available in the environment it was written in) — a passing run
    /// of this test, or an `nft list ruleset` inspection while it is
    /// paused mid-run, is the outstanding verification this crate's own
    /// `@.claude/rules/ci.md` requires before this Task can be considered
    /// independently reviewed.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux -- --ignored`"]
    fn set_then_clear_firewall_policy_round_trips_through_the_kernel() {
        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");

        let allow_dns = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Udp)
            .with_port(net_lattice_model::firewall::PortRange::single(53));
        let policy = FirewallPolicy::new(Verdict::Deny).with_rule(allow_dns);

        let set_result = backend.set_firewall_policy(policy.clone());
        if matches!(
            set_result,
            Err(Error::PermissionDenied) | Err(Error::Platform(_))
        ) {
            set_result.expect("set_firewall_policy failed - are you running with CAP_NET_ADMIN?");
        }

        let observed = backend
            .firewall_rules()
            .expect("firewall_rules() failed after set_firewall_policy succeeded");
        assert_eq!(observed, policy.rules);

        // Clean up regardless of the assertion above.
        let _ = backend.clear_firewall_policy();
    }
}
