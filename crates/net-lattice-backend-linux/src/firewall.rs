//! Native-firewall management via nftables (`FirewallProvider`/`FirewallMutator`).
//!
//! Manages one Net-Lattice-owned nftables table (`net_lattice`) with two base
//! chains (`inbound` hooked at `NF_INET_LOCAL_IN`, `outbound` hooked at
//! `NF_INET_LOCAL_OUT`), each set to the requested [`FirewallPolicy`]'s
//! `default_verdict` as its chain policy. Every [`FirewallRule`] compiles to
//! one nftables rule appended to the chain matching its
//! [`Direction`](net_lattice_model::firewall::Direction). Built on the
//! `nftnl` crate (Mullvad, MIT/Apache-2.0), a safe wrapper over `libnftnl` —
//! no `nft` subprocess is ever spawned. See ADR-0017 (`NL-A-19`) for the
//! full design rationale. See `examples/kill_switch.rs` for one concrete
//! usage pattern (a fail-closed default-deny policy) built on this generic
//! API; this module itself makes no kill-switch-specific assumptions.
//!
//! Building this crate requires the `libmnl` and `libnftnl` development
//! packages (headers and `pkg-config` files) to be installed on the build
//! machine — e.g. `apt-get install libmnl-dev libnftnl-dev` on
//! Debian/Ubuntu. The corresponding runtime shared libraries
//! (`libmnl0`/`libnftnl11` or newer) must be present wherever the resulting
//! binary runs. This is a build-time requirement only; it does not affect
//! the crate's runtime portability beyond requiring those shared libraries.
//!
//! [`FirewallProvider::firewall_rules`] reads the managed table's rules
//! directly from the kernel (`NFT_MSG_GETRULE`, dumped per chain) rather
//! than serving a cached copy of the last-applied policy, so it reflects
//! out-of-band changes (e.g. `nft` run by hand against the same table).
//! The `nftnl` crate itself only supports building/sending rules, not
//! parsing a kernel reply back into typed expressions, so this module talks
//! to the lower-level `nftnl_sys` bindings directly for the read path —
//! walking each rule's expression list (`nftnl_expr_iter_*`) and decoding
//! only the fixed expression shapes this module itself ever writes (see
//! `add_expressions`/`add_remote_match`/`add_port_match`); an unrecognized
//! expression is skipped rather than treated as a decode failure, since a
//! future-modified rule shape here should degrade gracefully, not panic.
//! One real, unavoidable limitation: `inbound`/`outbound` are separate
//! nftables chains, so the original [`FirewallPolicy::rules`] list order is
//! only preserved *within* each direction, not across directions that were
//! interleaved in the caller's original list — [`FirewallProvider::firewall_rules`]
//! returns every inbound rule (in original order) followed by every
//! outbound rule (in original order), not necessarily the caller's exact
//! interleaving.

use std::ffi::{CStr, CString};
use std::io;

use net_lattice_core::{Error, PlatformErrorCode, Result};
use net_lattice_ip::{Ipv4Network, Ipv4PrefixLength, Ipv6Network, Ipv6PrefixLength};
use net_lattice_model::Network;
use net_lattice_model::firewall::{
    Direction, FirewallPolicy, FirewallRule, PortRange, Protocol, Verdict,
};
use net_lattice_platform::{FirewallMutator, FirewallProvider};
use nftnl::expr::{
    Bitwise, Cmp, CmpOp, Ipv4HeaderField, Ipv6HeaderField, Meta, NetworkHeaderField, Payload,
    TcpHeaderField, TransportHeaderField, UdpHeaderField, Verdict as NftVerdict,
};
use nftnl::nftnl_sys::{self as sys, libc};
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

/// Standard Linux UAPI `linux/netlink.h` constants. Not re-exported by the
/// plain `libc` crate on non-Android Linux (confirmed by inspecting its
/// source: only `unix/linux_like/android/mod.rs` defines them), so defined
/// locally rather than pulled from a dependency — these values have been
/// stable since netlink's inception and are not expected to change.
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

fn chain_name(direction: Direction) -> &'static CStr {
    match direction {
        Direction::Inbound => INBOUND_CHAIN_NAME,
        Direction::Outbound => OUTBOUND_CHAIN_NAME,
        _ => unreachable!("Direction is non_exhaustive; every current variant is handled above"),
    }
}

/// Reads the `nlmsghdr` fields needed to route each dump reply: `nlmsg_len`
/// and `nlmsg_type`, both native-endian per netlink wire format.
fn nlmsg_header(message: &[u8]) -> Option<(u32, u16)> {
    if message.len() < 6 {
        return None;
    }
    let len = u32::from_ne_bytes(message[0..4].try_into().ok()?);
    let msg_type = u16::from_ne_bytes(message[4..6].try_into().ok()?);
    Some((len, msg_type))
}

/// Returns the raw `errno` an `NLMSG_ERROR` reply carries (its payload's
/// first 4 bytes, per `struct nlmsgerr`), or `None` if the message is too
/// short to contain one.
fn nlmsg_error_code(message: &[u8]) -> Option<i32> {
    const NLMSGHDR_LEN: usize = 16;
    if message.len() < NLMSGHDR_LEN + 4 {
        return None;
    }
    Some(i32::from_ne_bytes(
        message[NLMSGHDR_LEN..NLMSGHDR_LEN + 4].try_into().ok()?,
    ))
}

/// Returns this expression's type name (e.g. `"meta"`, `"cmp"`,
/// `"payload"`, `"bitwise"`, `"immediate"`), or `None` if libnftnl has no
/// name attribute set (shouldn't happen for a rule the kernel returned).
fn expr_name(expr: *const sys::nftnl_expr) -> Option<String> {
    let ptr = unsafe { sys::nftnl_expr_get_str(expr, sys::NFTNL_EXPR_NAME as u16) };
    if ptr.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Returns a copy of a variable-length expression attribute's raw bytes
/// (e.g. `NFTNL_EXPR_CMP_DATA`, `NFTNL_EXPR_BITWISE_MASK`).
fn expr_bytes(expr: *const sys::nftnl_expr, attr: u32) -> Vec<u8> {
    let mut len: u32 = 0;
    let ptr = unsafe { sys::nftnl_expr_get(expr, attr as u16, &mut len) };
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len as usize) }.to_vec()
}

/// Reconstructs a [`Network`] from the raw big-endian address and
/// prefix-mask bytes an `add_remote_match`-written `payload`+`bitwise`+`cmp`
/// sequence carries. Returns `None` for any shape this module didn't itself
/// write (wrong length, or a mask with non-leading set bits).
fn decode_remote(addr: &[u8], mask: &[u8]) -> Option<Network> {
    if addr.len() != mask.len() {
        return None;
    }
    match addr.len() {
        4 => {
            let addr4: [u8; 4] = addr.try_into().ok()?;
            let mask4: [u8; 4] = mask.try_into().ok()?;
            let prefix = u32::from_be_bytes(mask4).leading_ones();
            let network = Ipv4Network::new(
                std::net::Ipv4Addr::from(addr4).into(),
                Ipv4PrefixLength::new(prefix as u8)?,
            );
            Some(Network::V4(network))
        }
        16 => {
            let addr16: [u8; 16] = addr.try_into().ok()?;
            let mask16: [u8; 16] = mask.try_into().ok()?;
            let prefix = u128::from_be_bytes(mask16).leading_ones();
            let network = Ipv6Network::new(
                std::net::Ipv6Addr::from(addr16).into(),
                Ipv6PrefixLength::new(prefix as u8)?,
            );
            Some(Network::V6(network))
        }
        _ => None,
    }
}

fn protocol_from_number(number: u8) -> Option<Protocol> {
    match number as i32 {
        n if n == libc::IPPROTO_TCP => Some(Protocol::Tcp),
        n if n == libc::IPPROTO_UDP => Some(Protocol::Udp),
        n if n == libc::IPPROTO_ICMP || n == libc::IPPROTO_ICMPV6 => Some(Protocol::Icmp),
        _ => None,
    }
}

/// Decodes one kernel-returned `nftnl_rule`'s expression list back into a
/// [`FirewallRule`], by walking the exact fixed expression sequences
/// `add_expressions` (and its helpers) write. Returns `None` only if the
/// rule carries no terminating verdict expression at all — every other
/// unrecognized shape degrades gracefully (that piece of the rule is
/// simply left unset) rather than failing the whole decode.
fn decode_rule(rule: *const sys::nftnl_rule, direction: Direction) -> Option<FirewallRule> {
    let iter = unsafe { sys::nftnl_expr_iter_create(rule) };
    if iter.is_null() {
        return None;
    }

    let mut interface_index = None;
    let mut remote = None;
    let mut protocol_number = None;
    let mut port = None;
    let mut verdict = None;

    loop {
        let expr = unsafe { sys::nftnl_expr_iter_next(iter) };
        if expr.is_null() {
            break;
        }
        match expr_name(expr).as_deref() {
            Some("meta") => {
                let key = unsafe { sys::nftnl_expr_get_u32(expr, sys::NFTNL_EXPR_META_KEY as u16) };
                let cmp = unsafe { sys::nftnl_expr_iter_next(iter) };
                if cmp.is_null() {
                    break;
                }
                let data = expr_bytes(cmp, sys::NFTNL_EXPR_CMP_DATA);
                if key == libc::NFT_META_IIF as u32 || key == libc::NFT_META_OIF as u32 {
                    if let Ok(bytes) = <[u8; 4]>::try_from(data.as_slice()) {
                        interface_index = Some(u32::from_ne_bytes(bytes));
                    }
                } else if key == libc::NFT_META_L4PROTO as u32
                    && let Some(&byte) = data.first()
                {
                    protocol_number = Some(byte);
                }
            }
            Some("payload") => {
                let next = unsafe { sys::nftnl_expr_iter_next(iter) };
                if next.is_null() {
                    break;
                }
                match expr_name(next).as_deref() {
                    Some("bitwise") => {
                        let mask = expr_bytes(next, sys::NFTNL_EXPR_BITWISE_MASK);
                        let cmp = unsafe { sys::nftnl_expr_iter_next(iter) };
                        if cmp.is_null() {
                            break;
                        }
                        let addr = expr_bytes(cmp, sys::NFTNL_EXPR_CMP_DATA);
                        remote = decode_remote(&addr, &mask);
                    }
                    Some("cmp") => {
                        let op =
                            unsafe { sys::nftnl_expr_get_u32(next, sys::NFTNL_EXPR_CMP_OP as u16) };
                        let data = expr_bytes(next, sys::NFTNL_EXPR_CMP_DATA);
                        if let Ok(bytes) = <[u8; 2]>::try_from(data.as_slice()) {
                            let start = u16::from_be_bytes(bytes);
                            if op == libc::NFT_CMP_GTE as u32 {
                                // A range compiles to payload+cmp(Gte) then a
                                // reloaded payload+cmp(Lte) — consume both.
                                let _reload = unsafe { sys::nftnl_expr_iter_next(iter) };
                                let cmp2 = unsafe { sys::nftnl_expr_iter_next(iter) };
                                if let Some(end_bytes) = (!cmp2.is_null())
                                    .then(|| expr_bytes(cmp2, sys::NFTNL_EXPR_CMP_DATA))
                                    .and_then(|data| <[u8; 2]>::try_from(data.as_slice()).ok())
                                {
                                    port =
                                        Some(PortRange::new(start, u16::from_be_bytes(end_bytes)));
                                }
                            } else {
                                port = Some(PortRange::single(start));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Some("immediate") => {
                let verdict_num =
                    unsafe { sys::nftnl_expr_get_u32(expr, sys::NFTNL_EXPR_IMM_VERDICT as u16) };
                verdict = Some(if verdict_num == libc::NF_ACCEPT as u32 {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                });
            }
            _ => {}
        }
    }
    unsafe { sys::nftnl_expr_iter_destroy(iter) };

    let mut built = FirewallRule::new(direction, verdict?);
    if let Some(index) = interface_index {
        built = built.with_interface_index(index);
    }
    if let Some(remote) = remote {
        built = built.with_remote(remote);
    }
    if let Some(number) = protocol_number
        && let Some(protocol) = protocol_from_number(number)
    {
        built = built.with_protocol(protocol);
        if let Some(port) = port {
            built = built.with_port(port);
        }
    }
    Some(built)
}

/// Dumps every rule in `direction`'s managed chain directly from the
/// kernel (`NFT_MSG_GETRULE`, `NLM_F_DUMP`, scoped to `net_lattice`'s
/// `inbound`/`outbound` chain) and decodes each one back into a
/// [`FirewallRule`], preserving the chain's own rule order.
fn read_chain_rules(direction: Direction) -> Result<Vec<FirewallRule>> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)
        .map_err(|err| Error::Platform(mnl_error_code(&err)))?;

    let mut send_buf = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    let msg_len = unsafe {
        let filter_rule = sys::nftnl_rule_alloc();
        if filter_rule.is_null() {
            return Err(Error::Platform(PlatformErrorCode::Linux(libc::ENOMEM)));
        }
        sys::nftnl_rule_set_u32(
            filter_rule,
            sys::NFTNL_RULE_FAMILY as u16,
            ProtoFamily::Inet as u32,
        );
        let table_name = CString::new(TABLE_NAME.to_bytes())
            .expect("TABLE_NAME has no interior NUL, it's a static &CStr literal");
        sys::nftnl_rule_set_str(
            filter_rule,
            sys::NFTNL_RULE_TABLE as u16,
            table_name.as_ptr(),
        );
        let chain_name_owned = CString::new(chain_name(direction).to_bytes())
            .expect("chain names have no interior NUL, they're static &CStr literals");
        sys::nftnl_rule_set_str(
            filter_rule,
            sys::NFTNL_RULE_CHAIN as u16,
            chain_name_owned.as_ptr(),
        );

        let header = sys::nftnl_nlmsg_build_hdr(
            send_buf.as_mut_ptr().cast(),
            libc::NFT_MSG_GETRULE as u16,
            ProtoFamily::Inet as u16,
            NLM_F_DUMP,
            1,
        );
        sys::nftnl_rule_nlmsg_build_payload(header, filter_rule);
        sys::nftnl_rule_free(filter_rule);

        u32::from_ne_bytes(
            send_buf[0..4]
                .try_into()
                .expect("nlmsghdr is at least 4 bytes"),
        ) as usize
    };

    socket
        .send(&send_buf[..msg_len])
        .map_err(|err| Error::Platform(mnl_error_code(&err)))?;

    let mut rules = Vec::new();
    let mut recv_buf = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    'dump: loop {
        let messages = socket
            .recv(&mut recv_buf)
            .map_err(|err| Error::Platform(mnl_error_code(&err)))?;
        for message in messages {
            let message = message.map_err(|err| Error::Platform(mnl_error_code(&err)))?;
            let Some((_len, msg_type)) = nlmsg_header(message) else {
                continue;
            };
            if msg_type == NLMSG_DONE {
                break 'dump;
            }
            if msg_type == NLMSG_ERROR {
                let errno = nlmsg_error_code(message).unwrap_or(0);
                if errno != 0 {
                    return Err(Error::Platform(PlatformErrorCode::Linux(-errno)));
                }
                break 'dump;
            }

            let rule = unsafe { sys::nftnl_rule_alloc() };
            if rule.is_null() {
                return Err(Error::Platform(PlatformErrorCode::Linux(libc::ENOMEM)));
            }
            let nlh = message.as_ptr().cast::<libc::nlmsghdr>();
            let parsed = unsafe { sys::nftnl_rule_nlmsg_parse(nlh, rule) };
            if parsed == 0
                && let Some(decoded) = decode_rule(rule, direction)
            {
                rules.push(decoded);
            }
            unsafe { sys::nftnl_rule_free(rule) };
        }
    }

    Ok(rules)
}

impl FirewallProvider for LinuxBackend {
    type FirewallRule = FirewallRule;

    fn firewall_rules(&self) -> Result<Vec<Self::FirewallRule>> {
        let mut rules = read_chain_rules(Direction::Inbound)?;
        rules.extend(read_chain_rules(Direction::Outbound)?);
        Ok(rules)
    }
}

impl FirewallMutator for LinuxBackend {
    type FirewallPolicy = LinuxFirewallPolicy;

    fn set_firewall_policy(&self, policy: Self::FirewallPolicy) -> Result<()> {
        apply_policy(&policy)
    }

    fn clear_firewall_policy(&self) -> Result<()> {
        apply_policy(&FirewallPolicy::new(Verdict::Allow))
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
    /// Exercises every match shape `decode_rule` handles (interface, IPv4
    /// remote, IPv6 remote, a single port, a port range, and a bare
    /// protocol match with no port) in one policy, all on
    /// [`Direction::Outbound`] so `firewall_rules()`'s documented
    /// direction-grouping caveat doesn't affect the equality check. An
    /// earlier, narrower version of this test (one rule: outbound UDP/53)
    /// has passed on real Linux CI with `CAP_NET_ADMIN`; this expanded
    /// version, covering the full `decode_rule` decoder added for `NL-165`,
    /// has not yet had its own CI run — the author of this change has no
    /// `CAP_NET_ADMIN` locally to verify it directly.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run with `sudo -E cargo test -p net-lattice-backend-linux -- --ignored`"]
    fn set_then_clear_firewall_policy_round_trips_through_the_kernel() {
        use net_lattice_ip::{
            Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
        };

        let backend = LinuxBackend::new().expect("failed to open a Netlink connection");

        let loopback_index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(loopback_index, 0, "this host has no `lo` interface");

        let via_loopback = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_interface_index(loopback_index);
        let v4_remote = FirewallRule::new(Direction::Outbound, Verdict::Deny).with_remote(
            Network::V4(Ipv4Network::new(
                Ipv4Address::new(198, 51, 100, 0),
                Ipv4PrefixLength::new(24).unwrap(),
            )),
        );
        let v6_remote = FirewallRule::new(Direction::Outbound, Verdict::Deny).with_remote(
            Network::V6(Ipv6Network::new(
                Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                Ipv6PrefixLength::new(32).unwrap(),
            )),
        );
        let single_port = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Udp)
            .with_port(net_lattice_model::firewall::PortRange::single(53));
        let port_range = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Tcp)
            .with_port(net_lattice_model::firewall::PortRange::new(1000, 2000));
        let protocol_only =
            FirewallRule::new(Direction::Outbound, Verdict::Deny).with_protocol(Protocol::Icmp);

        let policy = FirewallPolicy::new(Verdict::Allow)
            .with_rule(via_loopback)
            .with_rule(v4_remote)
            .with_rule(v6_remote)
            .with_rule(single_port)
            .with_rule(port_range)
            .with_rule(protocol_only);

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
        assert!(
            backend
                .firewall_rules()
                .expect("firewall_rules() failed after clear_firewall_policy succeeded")
                .is_empty()
        );
    }
}
