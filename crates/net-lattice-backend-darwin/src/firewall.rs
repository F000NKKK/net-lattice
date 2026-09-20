//! Native-firewall management via macOS `pf` (`FirewallProvider`/
//! `FirewallMutator`), using raw ioctl calls on `/dev/pf`.
//!
//! There is no safe Rust wrapper crate for `pf` equivalent to Linux's
//! `nftnl`, and Apple does not ship the kernel-private `net/pfvar.h` header
//! in the public SDK (confirmed empirically: absent under
//! `$(xcrun --show-sdk-path)/usr/include/net`). The [`pfvar`] submodule's
//! struct definitions are transcribed field-for-field from Apple's own
//! published kernel source, **not** reconstructed from memory or borrowed
//! from a modern upstream OpenBSD header (macOS's `pf` forked from OpenBSD
//! around 2007 and has not tracked its ABI evolution since, so a current
//! OpenBSD `pfvar.h` would actively mislead rather than help):
//!
//! <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/pfvar.h>
//! (fetched 2026-09-20).
//!
//! Getting a raw ioctl struct's field layout wrong is not a logic bug a
//! test can shrug off — `ioctl()` copies exactly `sizeof(struct)` bytes
//! to/from the pointer given it, so a mismatched Rust `#[repr(C)]` type is
//! a real memory-safety hazard, not merely "the rule won't apply
//! correctly." Every [`pfvar`] type is transcribed field-by-field, in
//! order, with Rust types matched for size and alignment to their C
//! counterparts (`#[repr(C, align(N))]` wrappers where a union's widest
//! member forces an alignment plain field types wouldn't reproduce on
//! their own) — `#[repr(C)]`'s layout algorithm then reproduces the same
//! padding a C compiler would, without this module hand-computing offsets.
//! Fields this module never reads or writes (kernel-owned pointers,
//! counters, OS-fingerprint state, ALTQ/dummynet scheduling) are left at
//! their zeroed default, mirroring how `pfctl` itself builds a rule.
//!
//! The author of this change has never compiled this against a real macOS
//! SDK or run it against a live kernel — only cross-compiled via `cargo
//! check`/`clippy --target {x86_64,aarch64}-apple-darwin`, which cannot
//! catch an ABI mismatch in a hand-transcribed struct (see above). The
//! mutator path (`set_firewall_policy`/`clear_firewall_policy`, i.e.
//! `DIOCXBEGIN`/`DIOCADDRULE`/`DIOCXCOMMIT`) has since passed a privileged
//! round-trip test on real `macos-latest` CI as root, which is real
//! evidence the transcribed ABI is correct — but each subsequent change to
//! this module (e.g. the `DIOCGETRULES`/`DIOCGETRULE` read path) still
//! needs its own CI run before being trusted; see the specific privileged
//! test docs below for what has and hasn't been confirmed yet.
//!
//! One `pf` anchor (`net_lattice`) holds every rule this module manages,
//! added via a single `DIOCXBEGIN`/`DIOCADDRULE*`/`DIOCXCOMMIT` transaction
//! per [`FirewallMutator::set_firewall_policy`] call — `pf`'s transaction
//! ticket mechanism stages a fresh ruleset and swaps it in atomically on
//! commit, which is also exactly the semantics `FirewallMutator` documents
//! (whole-policy replace), so unlike the Linux/Windows backends this one
//! needs no separate explicit flush step. Every rule carries `quick = 1`
//! (first-match-wins, matching [`FirewallPolicy`]'s documented evaluation
//! order) and [`FirewallPolicy::default_verdict`] is realized as one final
//! unconditional `quick` rule appended after the caller's ordered rules —
//! `pf` has no equivalent to nftables' base-chain policy or a WFP
//! condition-free lowest-weight filter, but the same effect follows from
//! `quick` evaluation order.
//!
//! [`FirewallProvider::firewall_rules`] reads the anchor's rules directly
//! from the kernel (`DIOCGETRULES` for the count and a snapshot ticket,
//! then `DIOCGETRULE` per index) rather than serving a cached copy of the
//! last-applied policy, so it reflects out-of-band changes (e.g. `pfctl`
//! run by hand against the same anchor). Because `pf` stores one linear
//! ruleset per anchor (`direction` is just a per-rule match field, not a
//! separate chain), `pf_rule.nr`'s kernel-assigned order already matches
//! the caller's original list order exactly, including interleaved
//! directions — unlike the Linux backend's separate `inbound`/`outbound`
//! chains, which can only preserve order within one direction.

use std::ffi::CString;
use std::io;

use net_lattice_core::{Error, PlatformErrorCode, Result};
use net_lattice_ip::{Ipv4Network, Ipv4PrefixLength, Ipv6Network, Ipv6PrefixLength};
use net_lattice_model::Network;
use net_lattice_model::firewall::{
    Direction, FirewallPolicy, FirewallRule, PortRange, Protocol, Verdict,
};
use net_lattice_platform::{FirewallMutator, FirewallProvider};

use crate::DarwinBackend;

/// Raw `pf` ioctl structs transcribed from Apple's `bsd/net/pfvar.h` — see
/// this module's doc comment for provenance and the verification gap.
#[allow(
    non_camel_case_types,
    non_snake_case,
    dead_code,
    reason = "transcribed 1:1 from the real header for completeness/documentation; \
    not every constant this module defines is consumed (e.g. PF_OP_NONE is the \
    implicit default an unset xport already has)"
)]
mod pfvar {
    use std::ffi::c_void;

    pub const IFNAMSIZ: usize = 16;
    pub const MAXPATHLEN: usize = 1024;
    pub const PF_TABLE_NAME_SIZE: usize = 32;
    pub const RTLABEL_LEN: usize = 32;
    pub const PF_RULE_LABEL_SIZE: usize = 64;
    pub const PF_QNAME_SIZE: usize = 64;
    pub const PF_TAG_NAME_SIZE: usize = 64;
    pub const PF_OWNER_NAME_SIZE: usize = 64;
    pub const PF_SKIP_COUNT: usize = 8;
    /// Real indices into `pf_rule.timeout[]` run `0..PFTM_MAX` (26); this
    /// module never sets a per-rule timeout override, so only the array's
    /// size (for correct `pf_rule` layout) matters here.
    pub const PFTM_MAX: usize = 26;

    pub const PF_INOUT: u8 = 0;
    pub const PF_IN: u8 = 1;
    pub const PF_OUT: u8 = 2;

    pub const PF_PASS: u8 = 0;
    pub const PF_DROP: u8 = 1;

    pub const PF_ADDR_ADDRMASK: u8 = 0;

    pub const PF_OP_NONE: u8 = 0;
    pub const PF_OP_EQ: u8 = 2;
    pub const PF_OP_RRG: u8 = 9;

    pub const PF_RULESET_FILTER: i32 = 1;

    pub const DIOCADDRULE: libc::c_ulong = ioc::iowr(b'D', 4, size_of::<PfiocRule>());
    pub const DIOCGETRULES: libc::c_ulong = ioc::iowr(b'D', 6, size_of::<PfiocRule>());
    pub const DIOCGETRULE: libc::c_ulong = ioc::iowr(b'D', 7, size_of::<PfiocRule>());
    pub const DIOCBEGINADDRS: libc::c_ulong = ioc::iowr(b'D', 51, size_of::<PfiocPooladdr>());
    pub const DIOCXBEGIN: libc::c_ulong = ioc::iowr(b'D', 81, size_of::<PfiocTrans>());
    pub const DIOCXCOMMIT: libc::c_ulong = ioc::iowr(b'D', 82, size_of::<PfiocTrans>());
    pub const DIOCXROLLBACK: libc::c_ulong = ioc::iowr(b'D', 83, size_of::<PfiocTrans>());

    /// BSD `_IOWR` ioctl request-code encoding (`sys/ioccom.h`), unchanged
    /// across Darwin/FreeBSD/NetBSD for decades: `IOC_INOUT | (len <<
    /// 16) | (group << 8) | num`.
    mod ioc {
        const IOCPARM_MASK: libc::c_ulong = 0x1fff;
        const IOC_OUT: libc::c_ulong = 0x4000_0000;
        const IOC_IN: libc::c_ulong = 0x8000_0000;
        const IOC_INOUT: libc::c_ulong = IOC_IN | IOC_OUT;

        pub const fn iowr(group: u8, num: u8, len: usize) -> libc::c_ulong {
            IOC_INOUT
                | ((len as libc::c_ulong & IOCPARM_MASK) << 16)
                | ((group as libc::c_ulong) << 8)
                | (num as libc::c_ulong)
        }
    }

    /// `struct pf_addr`: a 128-bit address union. Represented as raw bytes;
    /// this module only ever writes the leading 4 (IPv4) or all 16 (IPv6)
    /// bytes and leaves the rest zero, which is exactly how the real union
    /// behaves for a shorter address. `align(4)` reproduces the alignment
    /// the real union gets from its `struct in_addr`/`u_int32_t[4]`
    /// members, which a bare `[u8; 16]` would not carry on its own.
    #[repr(C, align(4))]
    #[derive(Clone, Copy, Default)]
    pub struct PfAddr(pub [u8; 16]);

    /// The `v` union inside `struct pf_addr_wrap` (address+mask, or an
    /// interface/table/route-label name). This module only ever uses the
    /// address+mask form; the others are represented only for correct
    /// size/alignment (32 bytes, 4-aligned — the widest member is the
    /// `{ addr, mask }` pair of two 16-byte, 4-aligned `pf_addr`s).
    #[repr(C, align(4))]
    #[derive(Clone, Copy, Default)]
    pub struct PfAddrWrapV {
        pub addr: PfAddr,
        pub mask: PfAddr,
    }

    /// `struct pf_addr_wrap`. The `p` union (`dyn`/`tbl`/`dyncnt`/`tblcnt`)
    /// is kernel/table-management state this module never populates —
    /// represented as a plain `u64` (matching the union's
    /// `__attribute__((aligned(8)))`-forced size and alignment) and always
    /// left zero.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PfAddrWrap {
        pub v: PfAddrWrapV,
        pub p: u64,
        pub r#type: u8,
        pub iflags: u8,
    }

    /// `struct pf_port_range` packed into `union pf_rule_xport` (the union
    /// also has a `u_int16_t call_id` and `u_int32_t spi` variant, neither
    /// used by this module; the range form is its widest member).
    #[repr(C, align(4))]
    #[derive(Clone, Copy, Default)]
    pub struct PfRuleXport {
        pub port: [u16; 2],
        pub op: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PfRuleAddr {
        pub addr: PfAddrWrap,
        pub xport: PfRuleXport,
        pub neg: u8,
    }

    /// `struct pf_palist` (`TAILQ_HEAD`): two pointers, always empty here.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PfPalist {
        pub tqh_first: u64,
        pub tqh_last: u64,
    }

    /// `union pf_poolhashkey`: represented as raw bytes; this module never
    /// sets a source-hash pool, so it is always zero.
    #[repr(C, align(4))]
    #[derive(Clone, Copy, Default)]
    pub struct PfPoolhashkey(pub [u8; 16]);

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PfPool {
        pub list: PfPalist,
        pub cur: u64,
        pub key: PfPoolhashkey,
        pub counter: PfAddr,
        pub tblidx: i32,
        pub proxy_port: [u16; 2],
        pub port_op: u8,
        pub opts: u8,
        pub af: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PfRuleUid {
        pub uid: [u32; 2],
        pub op: u8,
        pub _pad: [u8; 3],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PfRuleGid {
        pub gid: [u32; 2],
        pub op: u8,
        pub _pad: [u8; 3],
    }

    /// `union pf_rule_ptr` (`skip[]` kernel-computed jump targets): a
    /// tagged pointer/index the kernel recomputes on load, forced 8-byte
    /// aligned in the real union. Always zero from userspace.
    pub type PfRulePtr = u64;

    /// `struct pf_rule`, transcribed field-for-field from `bsd/net/pfvar.h`
    /// (see this module's parent doc comment for the exact source). Only
    /// `src`, `dst`, `ifname`, `rule_flag`, `action`, `direction`, `quick`,
    /// `af`, and `proto` are ever set by this module; every other field
    /// stays at its `Default` (zeroed) value, the same way `pfctl` builds
    /// a rule it doesn't need every feature of.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct PfRule {
        pub src: PfRuleAddr,
        pub dst: PfRuleAddr,
        pub skip: [PfRulePtr; PF_SKIP_COUNT],
        pub label: [u8; PF_RULE_LABEL_SIZE],
        pub ifname: [u8; IFNAMSIZ],
        pub qname: [u8; PF_QNAME_SIZE],
        pub pqname: [u8; PF_QNAME_SIZE],
        pub tagname: [u8; PF_TAG_NAME_SIZE],
        pub match_tagname: [u8; PF_TAG_NAME_SIZE],
        pub overload_tblname: [u8; PF_TABLE_NAME_SIZE],
        pub entries: PfPalist,
        pub rpool: PfPool,
        pub evaluations: u64,
        pub packets: [u64; 2],
        pub bytes: [u64; 2],
        pub ticket: u64,
        pub owner: [u8; PF_OWNER_NAME_SIZE],
        pub priority: u32,
        pub kif: u64,
        pub anchor: u64,
        pub overload_tbl: u64,
        pub os_fingerprint: u32,
        pub rtableid: u32,
        pub timeout: [u32; PFTM_MAX],
        pub states: u32,
        pub max_states: u32,
        pub src_nodes: u32,
        pub max_src_nodes: u32,
        pub max_src_states: u32,
        pub max_src_conn: u32,
        pub max_src_conn_rate_limit: u32,
        pub max_src_conn_rate_seconds: u32,
        pub qid: u32,
        pub pqid: u32,
        pub rt_listid: u32,
        pub nr: u32,
        pub prob: u32,
        pub cuid: u32,
        pub cpid: i32,
        pub return_icmp: u16,
        pub return_icmp6: u16,
        pub max_mss: u16,
        pub tag: u16,
        pub match_tag: u16,
        pub uid: PfRuleUid,
        pub gid: PfRuleGid,
        pub rule_flag: u32,
        pub action: u8,
        pub direction: u8,
        pub log: u8,
        pub logif: u8,
        pub quick: u8,
        pub ifnot: u8,
        pub match_tag_not: u8,
        pub natpass: u8,
        pub keep_state: u8,
        pub af: u8,
        pub proto: u8,
        pub r#type: u8,
        pub code: u8,
        pub flags: u8,
        pub flagset: u8,
        pub min_ttl: u8,
        pub allow_opts: u8,
        pub rt: u8,
        pub return_ttl: u8,
        pub tos: u8,
        pub anchor_relative: u8,
        pub anchor_wildcard: u8,
        pub flush: u8,
        pub proto_variant: u8,
        pub extfilter: u8,
        pub extmap: u8,
        pub dnpipe: u32,
        pub dntype: u32,
    }

    impl Default for PfRule {
        fn default() -> Self {
            // SAFETY: every field is a plain integer, byte array, or one of
            // this module's own zeroable wrapper types — an all-zero bit
            // pattern is a valid value for all of them, mirroring pfctl's
            // own `bzero(&rule, sizeof(rule))` convention.
            unsafe { std::mem::zeroed() }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct PfiocRule {
        pub action: u32,
        pub ticket: u32,
        pub pool_ticket: u32,
        pub nr: u32,
        pub anchor: [u8; MAXPATHLEN],
        pub anchor_call: [u8; MAXPATHLEN],
        pub rule: PfRule,
    }

    impl Default for PfiocRule {
        fn default() -> Self {
            // SAFETY: same reasoning as `PfRule::default` — every field is
            // zeroable, and `pfctl` itself builds this struct the same way.
            unsafe { std::mem::zeroed() }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PfPooladdrAddr {
        pub addr: PfAddrWrap,
        pub entries: PfPalist,
        pub ifname: [u8; IFNAMSIZ],
        pub kif: u64,
    }

    #[repr(C)]
    pub struct PfiocPooladdr {
        pub action: u32,
        pub ticket: u32,
        pub nr: u32,
        pub r_num: u32,
        pub r_action: u8,
        pub r_last: u8,
        pub af: u8,
        pub anchor: [u8; MAXPATHLEN],
        pub addr: PfPooladdrAddr,
    }

    impl Default for PfiocPooladdr {
        fn default() -> Self {
            // SAFETY: every field is zeroable; matches `pfctl`'s own usage
            // (a fresh, empty pool request needs no fields but `anchor`).
            unsafe { std::mem::zeroed() }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct PfiocTransE {
        pub rs_num: i32,
        pub anchor: [u8; MAXPATHLEN],
        pub ticket: u32,
    }

    impl Default for PfiocTransE {
        fn default() -> Self {
            // SAFETY: every field is zeroable.
            unsafe { std::mem::zeroed() }
        }
    }

    #[repr(C)]
    pub struct PfiocTrans {
        pub size: i32,
        pub esize: i32,
        pub array: *mut PfiocTransE,
    }

    /// Casts `t` to the `*mut c_void` `ioctl`'s variadic third argument
    /// expects, purely to keep call sites free of a repeated inline cast.
    pub fn as_ioctl_arg<T>(t: &mut T) -> *mut c_void {
        (t as *mut T).cast()
    }
}

const ANCHOR: &[u8] = b"net_lattice";

fn darwin_error_code(err: &io::Error) -> PlatformErrorCode {
    PlatformErrorCode::Darwin(err.raw_os_error().unwrap_or(0))
}

fn anchor_bytes() -> [u8; pfvar::MAXPATHLEN] {
    let mut anchor = [0u8; pfvar::MAXPATHLEN];
    anchor[..ANCHOR.len()].copy_from_slice(ANCHOR);
    anchor
}

fn ioctl_checked(fd: i32, request: libc::c_ulong, arg: *mut std::ffi::c_void) -> Result<()> {
    let status = unsafe { libc::ioctl(fd, request, arg) };
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Platform(darwin_error_code(
            &io::Error::last_os_error(),
        )))
    }
}

fn open_pf() -> Result<i32> {
    let path = CString::new("/dev/pf").expect("static path has no interior NUL");
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(Error::Platform(darwin_error_code(
            &io::Error::last_os_error(),
        )));
    }
    Ok(fd)
}

fn pf_action(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Allow => pfvar::PF_PASS,
        Verdict::Deny => pfvar::PF_DROP,
        _ => unreachable!("Verdict is non_exhaustive; every current variant is handled above"),
    }
}

fn pf_direction(direction: Direction) -> u8 {
    match direction {
        Direction::Inbound => pfvar::PF_IN,
        Direction::Outbound => pfvar::PF_OUT,
        _ => unreachable!("Direction is non_exhaustive; every current variant is handled above"),
    }
}

/// Returns the `IPPROTO_*` number for `protocol`, disambiguating
/// [`Protocol::Icmp`] by `remote`'s family exactly like the Linux backend
/// (a single `pf_rule.af` covers both directions here, same ambiguity when
/// `remote` is `None`): defaults to IPv4 ICMP unless `remote` is IPv6.
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

fn address_family(remote: Option<&Network>) -> u8 {
    match remote {
        Some(Network::V4(_)) => libc::AF_INET as u8,
        Some(Network::V6(_)) => libc::AF_INET6 as u8,
        None => libc::AF_UNSPEC as u8,
    }
}

fn pf_rule_addr_for(remote: Network) -> pfvar::PfRuleAddr {
    let mut addr = pfvar::PfRuleAddr {
        addr: pfvar::PfAddrWrap {
            r#type: pfvar::PF_ADDR_ADDRMASK,
            ..Default::default()
        },
        ..Default::default()
    };
    match remote {
        Network::V4(network) => {
            let ip = std::net::Ipv4Addr::from(network.address()).octets();
            addr.addr.v.addr.0[..4].copy_from_slice(&ip);
            let prefix = network.prefix().value();
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            addr.addr.v.mask.0[..4].copy_from_slice(&mask.to_be_bytes());
        }
        Network::V6(network) => {
            let ip = std::net::Ipv6Addr::from(network.address()).octets();
            addr.addr.v.addr.0 = ip;
            addr.addr.v.mask.0 = ipv6_prefix_mask(u32::from(network.prefix().value()));
        }
    }
    addr
}

/// Builds a 16-byte big-endian IPv6 prefix mask covering the leading
/// `prefix` bits — identical construction to the Linux backend's helper of
/// the same shape.
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

fn set_port_xport(xport: &mut pfvar::PfRuleXport, start: u16, end: u16) {
    if start == end {
        xport.op = pfvar::PF_OP_EQ;
        xport.port = [start.to_be(), 0];
    } else {
        xport.op = pfvar::PF_OP_RRG;
        xport.port = [start.to_be(), end.to_be()];
    }
}

/// Compiles `config` into a `pf_rule`. `quick` is always set — see this
/// module's doc comment for why every managed rule needs first-match-wins
/// evaluation.
fn build_pf_rule(config: &FirewallRule) -> pfvar::PfRule {
    let mut rule = pfvar::PfRule {
        action: pf_action(config.verdict),
        direction: pf_direction(config.direction),
        quick: 1,
        af: address_family(config.remote.as_ref()),
        ..Default::default()
    };

    if let Some(index) = config.interface_index {
        let mut name_buf = [0u8; libc::IF_NAMESIZE];
        let name_ptr = unsafe { libc::if_indextoname(index, name_buf.as_mut_ptr().cast()) };
        if !name_ptr.is_null() {
            let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(0);
            let copy_len = name_len.min(pfvar::IFNAMSIZ - 1);
            rule.ifname[..copy_len].copy_from_slice(&name_buf[..copy_len]);
        }
    }

    if let Some(remote) = config.remote {
        let remote_addr = pf_rule_addr_for(remote);
        match config.direction {
            Direction::Inbound => rule.src = remote_addr,
            Direction::Outbound => rule.dst = remote_addr,
            _ => {
                unreachable!("Direction is non_exhaustive; every current variant is handled above")
            }
        }
    }

    if let Some(protocol) = config.protocol {
        rule.proto = protocol_number(protocol, config.remote.as_ref());

        if let Some(port) = config.port
            && matches!(protocol, Protocol::Tcp | Protocol::Udp)
        {
            let xport = match config.direction {
                Direction::Inbound => &mut rule.src.xport,
                Direction::Outbound => &mut rule.dst.xport,
                _ => unreachable!(
                    "Direction is non_exhaustive; every current variant is handled above"
                ),
            };
            set_port_xport(xport, port.start, port.end);
        }
    }

    rule
}

fn default_rule(verdict: Verdict) -> pfvar::PfRule {
    pfvar::PfRule {
        action: pf_action(verdict),
        direction: pfvar::PF_INOUT,
        quick: 1,
        ..Default::default()
    }
}

/// Reserves a pool ticket for a rule with no route/NAT pool. `pf`'s
/// `DIOCADDRULE` handler validates `rule.pool_ticket` against the current
/// pool generation even for a rule that never references a pool address,
/// so every rule still needs one, matching `pfctl`'s own behavior.
fn begin_pool_ticket(fd: i32) -> Result<u32> {
    let mut request = pfvar::PfiocPooladdr {
        anchor: anchor_bytes(),
        ..Default::default()
    };
    ioctl_checked(fd, pfvar::DIOCBEGINADDRS, pfvar::as_ioctl_arg(&mut request))?;
    Ok(request.ticket)
}

/// Replaces every rule in the `net_lattice` anchor with `policy`'s rules
/// (each compiled with `quick = 1`) plus one trailing unconditional
/// `quick` rule for `policy.default_verdict`, inside one
/// `DIOCXBEGIN`/`DIOCADDRULE`/`DIOCXCOMMIT` transaction.
fn apply_policy(policy: &FirewallPolicy) -> Result<()> {
    let fd = open_pf()?;
    let result = (|| -> Result<()> {
        let mut trans_entry = pfvar::PfiocTransE {
            rs_num: pfvar::PF_RULESET_FILTER,
            anchor: anchor_bytes(),
            ticket: 0,
        };
        let mut trans = pfvar::PfiocTrans {
            size: 1,
            esize: size_of::<pfvar::PfiocTransE>() as i32,
            array: &mut trans_entry,
        };
        ioctl_checked(fd, pfvar::DIOCXBEGIN, pfvar::as_ioctl_arg(&mut trans))?;

        let add = |rule: pfvar::PfRule| -> Result<()> {
            let pool_ticket = begin_pool_ticket(fd)?;
            let mut request = pfvar::PfiocRule {
                ticket: trans_entry.ticket,
                pool_ticket,
                anchor: anchor_bytes(),
                rule,
                ..Default::default()
            };
            ioctl_checked(fd, pfvar::DIOCADDRULE, pfvar::as_ioctl_arg(&mut request))
        };

        for config in &policy.rules {
            add(build_pf_rule(config))?;
        }
        add(default_rule(policy.default_verdict))?;

        ioctl_checked(fd, pfvar::DIOCXCOMMIT, pfvar::as_ioctl_arg(&mut trans))
    })();

    if result.is_err() {
        let mut trans_entry = pfvar::PfiocTransE {
            rs_num: pfvar::PF_RULESET_FILTER,
            anchor: anchor_bytes(),
            ticket: 0,
        };
        let mut trans = pfvar::PfiocTrans {
            size: 1,
            esize: size_of::<pfvar::PfiocTransE>() as i32,
            array: &mut trans_entry,
        };
        let _ = ioctl_checked(fd, pfvar::DIOCXROLLBACK, pfvar::as_ioctl_arg(&mut trans));
    }
    unsafe {
        libc::close(fd);
    }
    result
}

/// Decodes one `xport` back into a [`PortRange`], the inverse of
/// [`set_port_xport`]. Returns `None` for [`pfvar::PF_OP_NONE`] (no port
/// match set) or any other operator this module never itself writes.
fn decode_port_range(xport: &pfvar::PfRuleXport) -> Option<PortRange> {
    match xport.op {
        pfvar::PF_OP_EQ => Some(PortRange::single(u16::from_be(xport.port[0]))),
        pfvar::PF_OP_RRG => Some(PortRange::new(
            u16::from_be(xport.port[0]),
            u16::from_be(xport.port[1]),
        )),
        _ => None,
    }
}

/// Decodes one `pf_rule_addr`'s address+mask into a [`Network`], given the
/// address family `af` already tells us how many bytes are meaningful —
/// see [`decode_pf_rule`] for why `af` (not the address bytes themselves)
/// is the authoritative family signal.
fn decode_remote(addr: &pfvar::PfRuleAddr, af: u8) -> Option<Network> {
    if af == libc::AF_INET as u8 {
        let bytes: [u8; 4] = addr.addr.v.addr.0[..4].try_into().ok()?;
        let mask: [u8; 4] = addr.addr.v.mask.0[..4].try_into().ok()?;
        let prefix = Ipv4PrefixLength::new(u32::from_be_bytes(mask).leading_ones() as u8)?;
        let network = Ipv4Network::new(std::net::Ipv4Addr::from(bytes).into(), prefix);
        Some(Network::V4(network))
    } else if af == libc::AF_INET6 as u8 {
        let bytes = addr.addr.v.addr.0;
        let mask = addr.addr.v.mask.0;
        let prefix = Ipv6PrefixLength::new(u128::from_be_bytes(mask).leading_ones() as u8)?;
        let network = Ipv6Network::new(std::net::Ipv6Addr::from(bytes).into(), prefix);
        Some(Network::V6(network))
    } else {
        None
    }
}

/// Decodes one kernel-returned `pf_rule` back into a [`FirewallRule`],
/// mirroring [`build_pf_rule`]'s exact field usage. Returns `None` for the
/// trailing default-verdict catch-all rule ([`default_rule`] always writes
/// `direction: PF_INOUT`, which no caller-authored [`FirewallRule`] ever
/// produces — [`Direction`] only has `Inbound`/`Outbound`) or an
/// unrecognized action.
///
/// `af` is the authoritative signal for whether `remote` is present at
/// all, not merely which family it is: [`build_pf_rule`] always sets it
/// from `config.remote`, `AF_UNSPEC` when `remote` is `None`. Without this,
/// an explicit `0.0.0.0/0`/`::/0` remote (an all-zero address *and* mask,
/// the same bit pattern a genuinely absent remote leaves behind) would be
/// indistinguishable from no remote at all — matching every remote address
/// either way, so this narrow case doesn't change a rule's actual behavior
/// even if `af` were somehow wrong, but `af` makes the decode unambiguous
/// regardless.
fn decode_pf_rule(rule: &pfvar::PfRule) -> Option<FirewallRule> {
    let direction = match rule.direction {
        pfvar::PF_IN => Direction::Inbound,
        pfvar::PF_OUT => Direction::Outbound,
        _ => return None,
    };
    let verdict = match rule.action {
        pfvar::PF_PASS => Verdict::Allow,
        pfvar::PF_DROP => Verdict::Deny,
        _ => return None,
    };

    let mut built = FirewallRule::new(direction, verdict);

    if rule.ifname[0] != 0 {
        let name_len = rule.ifname.iter().position(|&b| b == 0).unwrap_or(0);
        if let Ok(name) = CString::new(&rule.ifname[..name_len]) {
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index != 0 {
                built = built.with_interface_index(index);
            }
        }
    }

    let remote_side = match direction {
        Direction::Inbound => &rule.src,
        Direction::Outbound => &rule.dst,
        _ => unreachable!("Direction is non_exhaustive; every current variant is handled above"),
    };
    if let Some(remote) = decode_remote(remote_side, rule.af) {
        built = built.with_remote(remote);
    }

    if rule.proto != 0
        && let Some(protocol) = protocol_from_number(rule.proto)
    {
        built = built.with_protocol(protocol);
        if let Some(port) = decode_port_range(&remote_side.xport) {
            built = built.with_port(port);
        }
    }

    Some(built)
}

fn protocol_from_number(number: u8) -> Option<Protocol> {
    match number as i32 {
        n if n == libc::IPPROTO_TCP => Some(Protocol::Tcp),
        n if n == libc::IPPROTO_UDP => Some(Protocol::Udp),
        n if n == libc::IPPROTO_ICMP || n == libc::IPPROTO_ICMPV6 => Some(Protocol::Icmp),
        _ => None,
    }
}

/// Reads every rule in the `net_lattice` anchor's filter ruleset directly
/// from the kernel: `DIOCGETRULES` first (fills the rule count and a
/// ticket identifying this snapshot), then one `DIOCGETRULE` per index
/// using that same ticket, exactly mirroring `pfctl`'s own read pattern.
/// `pf_rule.nr` (position in the anchor's single linear ruleset) is the
/// kernel's own ordering, so — unlike the Linux backend's separate
/// inbound/outbound chains — this preserves the caller's exact original
/// order, including interleaved directions.
fn read_anchor_rules() -> Result<Vec<FirewallRule>> {
    let fd = open_pf()?;
    let result = (|| -> Result<Vec<FirewallRule>> {
        let mut count_request = pfvar::PfiocRule {
            anchor: anchor_bytes(),
            ..Default::default()
        };
        ioctl_checked(
            fd,
            pfvar::DIOCGETRULES,
            pfvar::as_ioctl_arg(&mut count_request),
        )?;

        let mut rules = Vec::new();
        for index in 0..count_request.nr {
            let mut get_request = pfvar::PfiocRule {
                anchor: anchor_bytes(),
                ticket: count_request.ticket,
                nr: index,
                ..Default::default()
            };
            ioctl_checked(
                fd,
                pfvar::DIOCGETRULE,
                pfvar::as_ioctl_arg(&mut get_request),
            )?;
            if let Some(decoded) = decode_pf_rule(&get_request.rule) {
                rules.push(decoded);
            }
        }
        Ok(rules)
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

impl FirewallProvider for DarwinBackend {
    type FirewallRule = FirewallRule;

    fn firewall_rules(&self) -> Result<Vec<Self::FirewallRule>> {
        read_anchor_rules()
    }
}

impl FirewallMutator for DarwinBackend {
    type FirewallPolicy = FirewallPolicy;

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
    fn pf_action_and_pf_direction_map_verdict_and_direction() {
        assert_eq!(pf_action(Verdict::Allow), pfvar::PF_PASS);
        assert_eq!(pf_action(Verdict::Deny), pfvar::PF_DROP);
        assert_eq!(pf_direction(Direction::Inbound), pfvar::PF_IN);
        assert_eq!(pf_direction(Direction::Outbound), pfvar::PF_OUT);
    }

    #[test]
    fn address_family_reflects_remote_presence_and_kind() {
        use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

        assert_eq!(address_family(None), libc::AF_UNSPEC as u8);
        let v4 = Network::V4(Ipv4Network::new(
            Ipv4Address::new(10, 0, 0, 0),
            Ipv4PrefixLength::new(8).unwrap(),
        ));
        assert_eq!(address_family(Some(&v4)), libc::AF_INET as u8);
    }

    #[test]
    fn anchor_bytes_is_null_terminated_and_matches_the_anchor_name() {
        let bytes = anchor_bytes();
        assert_eq!(&bytes[..ANCHOR.len()], ANCHOR);
        assert_eq!(bytes[ANCHOR.len()], 0);
    }

    #[test]
    fn darwin_error_code_preserves_the_raw_errno() {
        let err = io::Error::from_raw_os_error(13);
        assert_eq!(darwin_error_code(&err), PlatformErrorCode::Darwin(13));
    }

    #[test]
    fn ioctl_request_codes_match_the_documented_bsd_encoding() {
        // DIOCADDRULE = _IOWR('D', 4, struct pfioc_rule) — spot-check
        // against the header's literal macro expansion rather than only
        // re-deriving the same formula this module already uses.
        let expected = 0x8000_0000u64
            | 0x4000_0000u64
            | ((size_of::<pfvar::PfiocRule>() as u64 & 0x1fff) << 16)
            | (u64::from(b'D') << 8)
            | 4;
        assert_eq!(pfvar::DIOCADDRULE, expected);
    }

    #[test]
    fn ipv6_prefix_mask_covers_leading_bits_only() {
        assert_eq!(ipv6_prefix_mask(0), [0u8; 16]);
        assert_eq!(ipv6_prefix_mask(128), [0xffu8; 16]);
        let mask = ipv6_prefix_mask(64);
        assert_eq!(&mask[..8], &[0xff; 8]);
        assert_eq!(&mask[8..], &[0x00; 8]);
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

    #[test]
    fn set_port_xport_uses_network_byte_order() {
        let mut xport = pfvar::PfRuleXport::default();
        set_port_xport(&mut xport, 53, 53);
        assert_eq!(xport.op, pfvar::PF_OP_EQ);
        assert_eq!(xport.port[0], 53u16.to_be());

        let mut xport = pfvar::PfRuleXport::default();
        set_port_xport(&mut xport, 1000, 2000);
        assert_eq!(xport.op, pfvar::PF_OP_RRG);
        assert_eq!(xport.port[0], 1000u16.to_be());
        assert_eq!(xport.port[1], 2000u16.to_be());
    }

    /// Exercises the `build_pf_rule`/`decode_pf_rule` pair entirely in
    /// process memory — no `/dev/pf`, no ioctl, no privilege — by building
    /// a `pf_rule` for a [`FirewallRule`] and decoding it straight back,
    /// asserting the two are equal. This is the same transformation the
    /// live kernel round trip exercises, just without the kernel: it
    /// catches a `build`/`decode` mismatch (e.g. a field one side reads
    /// that the other never writes) that a compile-only check cannot, at
    /// the cost of not proving the real ioctl ABI itself is correct — see
    /// the privileged test below for that half of the risk.
    #[test]
    fn build_then_decode_pf_rule_round_trips_every_match_shape() {
        use net_lattice_ip::{
            Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
        };

        let loopback_index = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        assert_ne!(loopback_index, 0, "this host has no `lo0` interface");

        let cases = [
            FirewallRule::new(Direction::Outbound, Verdict::Allow)
                .with_interface_index(loopback_index),
            FirewallRule::new(Direction::Outbound, Verdict::Deny).with_remote(Network::V4(
                Ipv4Network::new(
                    Ipv4Address::new(198, 51, 100, 0),
                    Ipv4PrefixLength::new(24).unwrap(),
                ),
            )),
            FirewallRule::new(Direction::Inbound, Verdict::Deny).with_remote(Network::V6(
                Ipv6Network::new(
                    Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                    Ipv6PrefixLength::new(32).unwrap(),
                ),
            )),
            FirewallRule::new(Direction::Outbound, Verdict::Allow)
                .with_protocol(Protocol::Udp)
                .with_port(PortRange::single(53)),
            FirewallRule::new(Direction::Inbound, Verdict::Allow)
                .with_protocol(Protocol::Tcp)
                .with_port(PortRange::new(1000, 2000)),
            FirewallRule::new(Direction::Outbound, Verdict::Deny).with_protocol(Protocol::Icmp),
        ];

        for rule in cases {
            let built = build_pf_rule(&rule);
            assert_eq!(
                decode_pf_rule(&built),
                Some(rule),
                "round trip for {rule:?}"
            );
        }
    }

    #[test]
    fn decode_pf_rule_skips_the_default_verdict_catch_all_rule() {
        let catch_all = default_rule(Verdict::Deny);
        assert_eq!(decode_pf_rule(&catch_all), None);
    }

    #[test]
    fn decode_pf_rule_rejects_an_unrecognized_action() {
        let mut rule = pfvar::PfRule {
            direction: pfvar::PF_OUT,
            action: 0xff,
            ..Default::default()
        };
        assert_eq!(decode_pf_rule(&rule), None);

        rule.action = pfvar::PF_PASS;
        assert!(decode_pf_rule(&rule).is_some());
    }

    /// Requires running as root on a real macOS host with `pf` present
    /// (present on every supported macOS version, but not necessarily
    /// enabled by default). Not run by default for the same reason as
    /// this crate's other privileged tests.
    ///
    /// An earlier, narrower version of this test (one rule: outbound
    /// UDP/53 to a /24) has passed on real macOS CI as root — the
    /// hand-transcribed `pfvar` ABI (see this module's doc comment for its
    /// provenance) held up under a real `DIOCXBEGIN`/`DIOCADDRULE`/
    /// `DIOCXCOMMIT` round trip on the first attempt. This expanded
    /// version, covering the `decode_pf_rule`/`DIOCGETRULES`/`DIOCGETRULE`
    /// read path added for `NL-165`, has not yet had its own CI run — the
    /// author of this change has no macOS host locally to verify it
    /// directly (only cross-compilation, which cannot validate ABI
    /// correctness at all, only that the Rust itself type-checks).
    ///
    /// Exercises every match shape `decode_pf_rule` handles (interface,
    /// IPv4 remote, IPv6 remote, a single port, a port range, and a bare
    /// protocol match) with directions deliberately interleaved, to verify
    /// the module doc comment's claim that `pf`'s single linear ruleset
    /// preserves the caller's exact original order.
    #[test]
    #[ignore]
    fn set_then_clear_firewall_policy_round_trips_through_the_kernel() {
        use net_lattice_ip::{
            Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
        };

        let backend = DarwinBackend::new().expect("create backend");

        let loopback_index = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        assert_ne!(loopback_index, 0, "this host has no `lo0` interface");

        let via_loopback = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_interface_index(loopback_index);
        let v6_remote = FirewallRule::new(Direction::Inbound, Verdict::Deny).with_remote(
            Network::V6(Ipv6Network::new(
                Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                Ipv6PrefixLength::new(32).unwrap(),
            )),
        );
        let v4_remote = FirewallRule::new(Direction::Outbound, Verdict::Deny).with_remote(
            Network::V4(Ipv4Network::new(
                Ipv4Address::new(198, 51, 100, 0),
                Ipv4PrefixLength::new(24).unwrap(),
            )),
        );
        let port_range = FirewallRule::new(Direction::Inbound, Verdict::Allow)
            .with_protocol(Protocol::Tcp)
            .with_port(net_lattice_model::firewall::PortRange::new(1000, 2000));
        let single_port = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Udp)
            .with_port(net_lattice_model::firewall::PortRange::single(53));
        let protocol_only =
            FirewallRule::new(Direction::Outbound, Verdict::Deny).with_protocol(Protocol::Icmp);

        let policy = FirewallPolicy::new(Verdict::Allow)
            .with_rule(via_loopback)
            .with_rule(v6_remote)
            .with_rule(v4_remote)
            .with_rule(port_range)
            .with_rule(single_port)
            .with_rule(protocol_only);

        backend
            .set_firewall_policy(policy.clone())
            .expect("apply policy");
        assert_eq!(backend.firewall_rules().unwrap(), policy.rules);

        backend.clear_firewall_policy().expect("clear policy");
        assert!(backend.firewall_rules().unwrap().is_empty());
    }

    /// Requires root; not run by default, same as this module's other
    /// privileged tests.
    ///
    /// A policy with no rules at all (just the trailing default-verdict
    /// catch-all rule) exercises `apply_policy`'s rule loop with zero
    /// iterations and `read_anchor_rules`'s zero-`nr` path — neither is
    /// exercised by the six-rule policy the other privileged test in this
    /// module applies.
    #[test]
    #[ignore]
    fn empty_firewall_policy_round_trips_through_the_kernel() {
        let backend = DarwinBackend::new().expect("create backend");

        backend
            .set_firewall_policy(FirewallPolicy::new(Verdict::Deny))
            .expect("apply empty policy");
        assert!(backend.firewall_rules().unwrap().is_empty());

        backend.clear_firewall_policy().expect("clear policy");
    }

    /// Requires root; not run by default, same as this module's other
    /// privileged tests.
    ///
    /// Applies one policy, then a second, entirely different policy, and
    /// confirms `firewall_rules()` reflects only the second — exercising
    /// `pf`'s transaction-replace semantics against an anchor that already
    /// holds real (non-default) rules from a previous call, not only the
    /// already-empty anchor every other test in this module starts from.
    #[test]
    #[ignore]
    fn replacing_a_firewall_policy_discards_the_previous_rules() {
        let backend = DarwinBackend::new().expect("create backend");

        let first = FirewallPolicy::new(Verdict::Allow).with_rule(
            FirewallRule::new(Direction::Outbound, Verdict::Deny).with_protocol(Protocol::Tcp),
        );
        backend
            .set_firewall_policy(first)
            .expect("first apply policy");

        let second = FirewallPolicy::new(Verdict::Deny).with_rule(
            FirewallRule::new(Direction::Inbound, Verdict::Allow).with_protocol(Protocol::Udp),
        );
        backend
            .set_firewall_policy(second.clone())
            .expect("second apply policy");

        assert_eq!(backend.firewall_rules().unwrap(), second.rules);

        backend.clear_firewall_policy().expect("clear policy");
    }
}
