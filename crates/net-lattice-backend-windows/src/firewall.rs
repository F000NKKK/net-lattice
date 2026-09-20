//! Native-firewall management via the Windows Filtering Platform (WFP)
//! (`FirewallProvider`/`FirewallMutator`).
//!
//! Manages one Net-Lattice-owned WFP provider and sublayer, with filters
//! added to the four IPv4/IPv6 ALE (Application Layer Enforcement) layers:
//! `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`_V6` for [`Direction::Outbound`]
//! (evaluated when a socket attempts to connect out) and
//! `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`/`_V6` for [`Direction::Inbound`]
//! (evaluated when an inbound connection is accepted). Every
//! [`FirewallRule`] compiles to one filter in the layer(s) matching its
//! direction and, if `remote` narrows the address family, that family only;
//! a rule with no `remote` is added to both the V4 and V6 layer for its
//! direction. See ADR-0017 (`NL-A-19`) for the full design rationale.
//!
//! Unlike nftables' base-chain policy, WFP has no per-sublayer default
//! action: an unmatched packet at these layers is implicitly permitted.
//! [`FirewallPolicy::default_verdict`] is therefore realized as an explicit,
//! lowest-weight, condition-free filter added to all four layers, so a
//! `Verdict::Deny` default genuinely blocks everything the ordered rules
//! don't allow.
//!
//! Filters are evaluated within a sublayer in descending weight order
//! (highest weight first), which this module uses to realize
//! [`FirewallPolicy`]'s documented first-match-wins rule order: rule `i`
//! (0-indexed) gets weight `min(255, rules.len() - i)`, clamped to a
//! minimum of 1, and the default-verdict filter gets weight 0. **Only the
//! first 255 rules in a policy are distinctly ordered** — WFP filter weight
//! is a single byte; a 256th-or-later rule collapses to the same weight as
//! the 255th and their *relative* order against each other (though not
//! against the first 254) is no longer guaranteed. This is a real platform
//! ceiling, not an oversight; policies this large are far outside this
//! domain's kill-switch/allowlist intended use.
//!
//! All managed objects (provider, sublayer, filters) are added with the
//! `PERSISTENT` flag so they survive process exit, matching the durability
//! nftables gives the Linux backend's managed table. Replacing a policy
//! flushes every existing filter owned by this crate's provider GUID (by
//! enumerating and deleting them, per layer) inside one WFP transaction, so
//! a caller never observes a partially-applied policy.
//!
//! [`FirewallProvider::firewall_rules`] reads every managed filter directly
//! from the engine (`FwpmFilterEnum0`, scoped to this crate's provider GUID,
//! per layer) rather than serving a cached copy of the last-applied policy,
//! so it reflects out-of-band changes. Because a rule's weight is assigned
//! once from its position in the caller's original flat rule list
//! (regardless of direction — see `rule_weight`), merging decoded filters
//! by descending weight across all four layers reconstructs the caller's
//! exact original order, including interleaved directions — unlike the
//! Linux backend, which stores `inbound`/`outbound` as separate nftables
//! chains and can only preserve order within each direction.

use net_lattice_core::{Error, PlatformErrorCode, Result};
use net_lattice_ip::{Ipv4Network, Ipv4PrefixLength, Ipv6Network, Ipv6PrefixLength};
use net_lattice_model::Network;
use net_lattice_model::firewall::{
    Direction, FirewallPolicy, FirewallRule, PortRange, Protocol, Verdict,
};
use net_lattice_platform::{FirewallMutator, FirewallProvider};
use windows::Win32::Foundation::{FWP_E_ALREADY_EXISTS, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_EMPTY,
    FWP_FILTER_ENUM_OVERLAPPING, FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE_TYPE, FWP_RANGE0,
    FWP_UINT8, FWP_UINT16, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmProviderAdd0,
    FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR};

use crate::WindowsBackend;

/// The `#[non_exhaustive]` `net_lattice_model::firewall::FirewallPolicy`
/// bound to this backend's `FirewallMutator::FirewallPolicy` associated
/// type, mirroring the Linux backend's `LinuxFirewallPolicy` alias.
pub type WindowsFirewallPolicy = FirewallPolicy;

/// This crate's fixed WFP provider GUID. Every object this module adds
/// carries this as its `providerKey`, which is how a policy replacement
/// finds and flushes only its own previously-added filters rather than
/// touching Windows Firewall's or another application's WFP state.
const PROVIDER_KEY: GUID = GUID::from_u128(0x6f8f6b34_9d0c_4a2b_8e2d_6a2f7a9f0c11);

/// This crate's fixed WFP sublayer GUID. All managed filters live in this
/// one sublayer, evaluated by weight (see the module doc comment).
const SUBLAYER_KEY: GUID = GUID::from_u128(0x1b6b6e9a_9b0a_4c39_9f7e_4f3d3e6d9a22);

/// The four ALE layers a policy's filters and default-verdict filter are
/// distributed across: outbound (connect) and inbound (recv-accept), each
/// split by IP version.
const ALL_LAYERS: [(Direction, bool); 4] = [
    (Direction::Outbound, false),
    (Direction::Outbound, true),
    (Direction::Inbound, false),
    (Direction::Inbound, true),
];

fn wfp_error_code(status: u32) -> PlatformErrorCode {
    PlatformErrorCode::Windows(status)
}

/// Maps a raw WFP `u32` status to a `Result`, tolerating "already exists"
/// for idempotent provider/sublayer creation (this module always attempts
/// to (re)create both on every policy replacement rather than tracking
/// whether a previous call already succeeded).
fn ok_or_already_exists(status: u32) -> Result<()> {
    if status == 0 || status == FWP_E_ALREADY_EXISTS.0 as u32 {
        Ok(())
    } else {
        Err(Error::Platform(wfp_error_code(status)))
    }
}

fn ok_or_platform_error(status: u32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Platform(wfp_error_code(status)))
    }
}

/// Opens a WFP session against the local machine's filter engine.
fn open_engine() -> Result<HANDLE> {
    let mut engine = HANDLE::default();
    let status =
        unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine) };
    ok_or_platform_error(status)?;
    Ok(engine)
}

fn wfp_action(verdict: Verdict) -> FWPM_ACTION0 {
    let action_type = match verdict {
        Verdict::Allow => FWP_ACTION_PERMIT,
        Verdict::Deny => FWP_ACTION_BLOCK,
        _ => unreachable!("Verdict is non_exhaustive; every current variant is handled above"),
    };
    FWPM_ACTION0 {
        r#type: action_type,
        ..Default::default()
    }
}

/// Returns the `IPPROTO_*` number WFP expects for `protocol`, disambiguating
/// [`Protocol::Icmp`] by which IP-version layer this filter is being built
/// for — unlike the Linux backend (one `inet`-family chain per direction),
/// each Windows ALE layer is already family-specific, so there is no
/// ambiguity here to document as a limitation.
fn protocol_number(protocol: Protocol, is_v6_layer: bool) -> u8 {
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_ICMPV6: u8 = 58;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    match protocol {
        Protocol::Tcp => IPPROTO_TCP,
        Protocol::Udp => IPPROTO_UDP,
        Protocol::Icmp => {
            if is_v6_layer {
                IPPROTO_ICMPV6
            } else {
                IPPROTO_ICMP
            }
        }
        _ => unreachable!("Protocol is non_exhaustive; every current variant is handled above"),
    }
}

/// The inverse of [`protocol_number`]: both ICMP numbers (v4 and v6) decode
/// to [`Protocol::Icmp`], since the model doesn't distinguish them.
fn protocol_from_number(number: u8) -> Option<Protocol> {
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_ICMPV6: u8 = 58;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    match number {
        IPPROTO_TCP => Some(Protocol::Tcp),
        IPPROTO_UDP => Some(Protocol::Udp),
        IPPROTO_ICMP | IPPROTO_ICMPV6 => Some(Protocol::Icmp),
        _ => None,
    }
}

fn layer_key(direction: Direction, is_v6: bool) -> GUID {
    match (direction, is_v6) {
        (Direction::Outbound, false) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        (Direction::Outbound, true) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        (Direction::Inbound, false) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        (Direction::Inbound, true) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        _ => unreachable!("Direction is non_exhaustive; every current variant is handled above"),
    }
}

/// Returns the `(direction, is_v6)` layer identifiers `rule` must be added
/// to: both address families for its direction when `remote` doesn't
/// narrow one, or only the matching family otherwise.
fn layers_for_rule(rule: &FirewallRule) -> Vec<(Direction, bool)> {
    match rule.remote {
        None => vec![(rule.direction, false), (rule.direction, true)],
        Some(Network::V4(_)) => vec![(rule.direction, false)],
        Some(Network::V6(_)) => vec![(rule.direction, true)],
    }
}

fn uint8_value(value: u8) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_CONDITION_VALUE0_0 { uint8: value },
    }
}

/// Builds the ordered condition list plus terminating action for `rule` on
/// the given `is_v6` layer.
///
/// Backing storage for pointer-shaped [`FWP_CONDITION_VALUE0`] union
/// members (the local interface LUID, the remote address/mask, and a port
/// range) is returned alongside the conditions and must outlive the
/// `FwpmFilterAdd0` call that consumes them — see this function's caller.
#[allow(
    dead_code,
    reason = "kept alive only for its address, referenced by \
    raw pointer from `conditions` above, which the compiler can't see as a read"
)]
struct RuleConditions {
    conditions: Vec<FWPM_FILTER_CONDITION0>,
    interface_luid: Box<u64>,
    remote_v4: Box<FWP_V4_ADDR_AND_MASK>,
    remote_v6: Box<FWP_V6_ADDR_AND_MASK>,
    port_range: Box<FWP_RANGE0>,
}

fn build_rule_conditions(rule: &FirewallRule, is_v6: bool) -> Result<RuleConditions> {
    let mut conditions = Vec::new();
    let mut interface_luid = Box::new(0u64);
    let mut remote_v4 = Box::new(FWP_V4_ADDR_AND_MASK::default());
    let mut remote_v6 = Box::new(FWP_V6_ADDR_AND_MASK::default());
    let mut port_range = Box::new(FWP_RANGE0::default());

    if let Some(index) = rule.interface_index {
        let mut luid = NET_LUID_LH::default();
        let status = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
        if status.0 != 0 {
            return Err(Error::Platform(wfp_error_code(status.0)));
        }
        *interface_luid = unsafe { luid.Value };
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint64: interface_luid.as_mut(),
                },
            },
        });
    }

    match rule.remote {
        Some(Network::V4(network)) if !is_v6 => {
            remote_v4.addr = u32::from_be_bytes(network.address().octets());
            let prefix = network.prefix().value();
            remote_v4.mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: remote_v4.as_mut(),
                    },
                },
            });
        }
        Some(Network::V6(network)) if is_v6 => {
            remote_v6.addr = std::net::Ipv6Addr::from(network.address()).octets();
            remote_v6.prefixLength = network.prefix().value();
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: remote_v6.as_mut(),
                    },
                },
            });
        }
        // The other family: this filter isn't built for that layer at all
        // (see `layers_for_rule`), so there is nothing to add here.
        _ => {}
    }

    if let Some(protocol) = rule.protocol {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: uint8_value(protocol_number(protocol, is_v6)),
        });

        if let Some(port) = rule.port
            && matches!(protocol, Protocol::Tcp | Protocol::Udp)
        {
            if port.start == port.end {
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port.start },
                    },
                });
            } else {
                port_range.valueLow = FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: port.start },
                };
                port_range.valueHigh = FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: port.end },
                };
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: FWP_MATCH_RANGE,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_RANGE_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            rangeValue: port_range.as_mut(),
                        },
                    },
                });
            }
        }
    }

    Ok(RuleConditions {
        conditions,
        interface_luid,
        remote_v4,
        remote_v6,
        port_range,
    })
}

/// Computes this rule's WFP filter weight from its position in the policy's
/// ordered rule list — see the module doc comment for the scheme and its
/// 255-rule ceiling.
fn rule_weight(index: usize, rule_count: usize) -> u8 {
    let remaining = rule_count.saturating_sub(index);
    remaining.clamp(1, u8::MAX as usize) as u8
}

fn weight_value(weight: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: weight },
    }
}

/// Encodes `s` as a null-terminated UTF-16 buffer suitable for a `PWSTR`
/// pointer. WFP rejects `FwpmProviderAdd0`/`FwpmSubLayerAdd0`/
/// `FwpmFilterAdd0` with `FWP_E_NULL_DISPLAY_NAME` when `displayData.name`
/// is null (observed on a real Windows CI runner: `FWPM_DISPLAY_DATA0
/// ::default()`'s zeroed `PWSTR` is exactly that), so every managed object
/// needs one of these kept alive for the duration of its `Add` call.
fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn display_data(name: &mut Vec<u16>) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(name.as_mut_ptr()),
        description: windows::core::PWSTR::null(),
    }
}

fn add_filter(
    engine: HANDLE,
    layer: GUID,
    weight: u8,
    action: FWPM_ACTION0,
    built: &RuleConditions,
) -> Result<()> {
    let mut provider_key = PROVIDER_KEY;
    let mut name = wide_z("Net Lattice managed filter");
    let filter = FWPM_FILTER0 {
        filterKey: GUID::new().unwrap_or(GUID::zeroed()),
        displayData: display_data(&mut name),
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        providerData: Default::default(),
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
        weight: weight_value(weight),
        numFilterConditions: built.conditions.len() as u32,
        filterCondition: built.conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0,
        action,
        Anonymous: Default::default(),
        reserved: std::ptr::null_mut(),
        filterId: 0,
        effectiveWeight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: Default::default(),
        },
    };
    let status = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
    ok_or_platform_error(status)
}

/// Deletes every filter this crate's provider previously added to `layer`.
fn flush_layer(engine: HANDLE, layer: GUID) -> Result<()> {
    let mut provider_key = PROVIDER_KEY;
    let template = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: &mut provider_key,
        layerKey: layer,
        enumType: FWP_FILTER_ENUM_OVERLAPPING,
        flags: 0,
        providerContextTemplate: std::ptr::null_mut(),
        numFilterConditions: 0,
        filterCondition: std::ptr::null_mut(),
        actionMask: 0xFFFF_FFFF,
        calloutKey: std::ptr::null_mut(),
    };

    let mut enum_handle = HANDLE::default();
    let status = unsafe { FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle) };
    ok_or_platform_error(status)?;

    let mut keys_to_delete = Vec::new();
    loop {
        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;
        let status =
            unsafe { FwpmFilterEnum0(engine, enum_handle, 128, &mut entries, &mut returned) };
        if status != 0 {
            unsafe {
                let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
            }
            return Err(Error::Platform(wfp_error_code(status)));
        }
        if returned == 0 {
            break;
        }
        for i in 0..returned as isize {
            let entry = unsafe { *entries.offset(i) };
            keys_to_delete.push(unsafe { (*entry).filterKey });
        }
        if returned < 128 {
            break;
        }
    }
    unsafe {
        let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
    }

    for key in keys_to_delete {
        let status = unsafe { FwpmFilterDeleteByKey0(engine, &key) };
        ok_or_platform_error(status)?;
    }
    Ok(())
}

/// Decodes one enumerated filter's conditions back into a [`FirewallRule`],
/// paired with its weight (used by [`WindowsBackend::firewall_rules`] to
/// reconstruct the original policy's rule order — see the module doc
/// comment). Returns `None` for the weight-0 default-verdict catch-all
/// filter (not a caller-authored rule) or an unrecognized action type;
/// every other unrecognized condition is skipped rather than failing the
/// whole decode, so a future filter shape degrades gracefully.
fn decode_filter(filter: &FWPM_FILTER0, direction: Direction) -> Option<(u8, FirewallRule)> {
    if filter.weight.r#type != FWP_UINT8 {
        return None;
    }
    let weight = unsafe { filter.weight.Anonymous.uint8 };
    if weight == 0 {
        return None;
    }

    let verdict = if filter.action.r#type == FWP_ACTION_PERMIT {
        Verdict::Allow
    } else if filter.action.r#type == FWP_ACTION_BLOCK {
        Verdict::Deny
    } else {
        return None;
    };

    let mut rule = FirewallRule::new(direction, verdict);
    let conditions = unsafe {
        std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
    };
    for condition in conditions {
        if condition.fieldKey == FWPM_CONDITION_IP_LOCAL_INTERFACE {
            if condition.conditionValue.r#type == FWP_UINT64 {
                let luid_ptr = unsafe { condition.conditionValue.Anonymous.uint64 };
                if let Some(&luid_value) = unsafe { luid_ptr.as_ref() } {
                    let luid = NET_LUID_LH { Value: luid_value };
                    let mut index = 0u32;
                    let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
                    if status.0 == 0 {
                        rule = rule.with_interface_index(index);
                    }
                }
            }
        } else if condition.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS {
            if condition.conditionValue.r#type == FWP_V4_ADDR_MASK {
                let ptr = unsafe { condition.conditionValue.Anonymous.v4AddrMask };
                if let Some(v4) = unsafe { ptr.as_ref() }
                    && let Some(prefix) = Ipv4PrefixLength::new(v4.mask.leading_ones() as u8)
                {
                    let addr = std::net::Ipv4Addr::from(v4.addr.to_be_bytes());
                    rule = rule.with_remote(Network::V4(Ipv4Network::new(addr.into(), prefix)));
                }
            } else if condition.conditionValue.r#type == FWP_V6_ADDR_MASK {
                let ptr = unsafe { condition.conditionValue.Anonymous.v6AddrMask };
                if let Some(v6) = unsafe { ptr.as_ref() }
                    && let Some(prefix) = Ipv6PrefixLength::new(v6.prefixLength)
                {
                    let addr = std::net::Ipv6Addr::from(v6.addr);
                    rule = rule.with_remote(Network::V6(Ipv6Network::new(addr.into(), prefix)));
                }
            }
        } else if condition.fieldKey == FWPM_CONDITION_IP_PROTOCOL {
            if condition.conditionValue.r#type == FWP_UINT8 {
                let number = unsafe { condition.conditionValue.Anonymous.uint8 };
                if let Some(protocol) = protocol_from_number(number) {
                    rule = rule.with_protocol(protocol);
                }
            }
        } else if condition.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT {
            if condition.conditionValue.r#type == FWP_UINT16 {
                let port = unsafe { condition.conditionValue.Anonymous.uint16 };
                rule = rule.with_port(PortRange::single(port));
            } else if condition.conditionValue.r#type == FWP_RANGE_TYPE {
                let ptr = unsafe { condition.conditionValue.Anonymous.rangeValue };
                if let Some(range) = unsafe { ptr.as_ref() } {
                    let low = unsafe { range.valueLow.Anonymous.uint16 };
                    let high = unsafe { range.valueHigh.Anonymous.uint16 };
                    rule = rule.with_port(PortRange::new(low, high));
                }
            }
        }
    }

    Some((weight, rule))
}

/// Enumerates every filter this crate's provider owns on `layer` and
/// decodes it via [`decode_filter`].
fn read_layer_rules(
    engine: HANDLE,
    direction: Direction,
    is_v6: bool,
) -> Result<Vec<(u8, FirewallRule)>> {
    let mut provider_key = PROVIDER_KEY;
    let layer = layer_key(direction, is_v6);
    let template = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: &mut provider_key,
        layerKey: layer,
        enumType: FWP_FILTER_ENUM_OVERLAPPING,
        flags: 0,
        providerContextTemplate: std::ptr::null_mut(),
        numFilterConditions: 0,
        filterCondition: std::ptr::null_mut(),
        actionMask: 0xFFFF_FFFF,
        calloutKey: std::ptr::null_mut(),
    };

    let mut enum_handle = HANDLE::default();
    let status = unsafe { FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle) };
    ok_or_platform_error(status)?;

    let mut decoded = Vec::new();
    loop {
        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;
        let status =
            unsafe { FwpmFilterEnum0(engine, enum_handle, 128, &mut entries, &mut returned) };
        if status != 0 {
            unsafe {
                let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
            }
            return Err(Error::Platform(wfp_error_code(status)));
        }
        if returned == 0 {
            break;
        }
        for i in 0..returned as isize {
            let entry = unsafe { *entries.offset(i) };
            if let Some(filter) = unsafe { entry.as_ref() }
                && let Some(pair) = decode_filter(filter, direction)
            {
                decoded.push(pair);
            }
        }
        if returned < 128 {
            break;
        }
    }
    unsafe {
        let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
    }
    Ok(decoded)
}

/// Replaces the managed provider's filters across all four ALE layers with
/// `policy`, inside one WFP transaction.
fn apply_policy(policy: &FirewallPolicy) -> Result<()> {
    let engine = open_engine()?;

    let apply = || -> Result<()> {
        let status = unsafe { FwpmTransactionBegin0(engine, 0) };
        ok_or_platform_error(status)?;

        let mut provider_key = PROVIDER_KEY;
        let mut provider_name = wide_z("Net Lattice");
        let provider = FWPM_PROVIDER0 {
            providerKey: provider_key,
            displayData: display_data(&mut provider_name),
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: Default::default(),
            serviceName: Default::default(),
        };
        ok_or_already_exists(unsafe { FwpmProviderAdd0(engine, &provider, None) })?;

        let mut sublayer_name = wide_z("Net Lattice managed firewall policy");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&mut sublayer_name),
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            providerData: Default::default(),
            weight: 0,
        };
        ok_or_already_exists(unsafe { FwpmSubLayerAdd0(engine, &sublayer, None) })?;

        for (direction, is_v6) in ALL_LAYERS {
            flush_layer(engine, layer_key(direction, is_v6))?;
        }

        for (direction, is_v6) in ALL_LAYERS {
            let empty = RuleConditions {
                conditions: Vec::new(),
                interface_luid: Box::new(0),
                remote_v4: Box::new(FWP_V4_ADDR_AND_MASK::default()),
                remote_v6: Box::new(FWP_V6_ADDR_AND_MASK::default()),
                port_range: Box::new(FWP_RANGE0::default()),
            };
            add_filter(
                engine,
                layer_key(direction, is_v6),
                0,
                wfp_action(policy.default_verdict),
                &empty,
            )?;
        }

        for (index, rule) in policy.rules.iter().enumerate() {
            let weight = rule_weight(index, policy.rules.len());
            for (direction, is_v6) in layers_for_rule(rule) {
                debug_assert_eq!(direction, rule.direction);
                let built = build_rule_conditions(rule, is_v6)?;
                add_filter(
                    engine,
                    layer_key(direction, is_v6),
                    weight,
                    wfp_action(rule.verdict),
                    &built,
                )?;
            }
        }

        let status = unsafe { FwpmTransactionCommit0(engine) };
        ok_or_platform_error(status)
    };

    let result = apply();
    if result.is_err() {
        unsafe {
            let _ = FwpmTransactionAbort0(engine);
        }
    }
    unsafe {
        let _ = FwpmEngineClose0(engine);
    }
    result
}

impl FirewallProvider for WindowsBackend {
    type FirewallRule = FirewallRule;

    fn firewall_rules(&self) -> Result<Vec<Self::FirewallRule>> {
        let engine = open_engine()?;
        let result = (|| -> Result<Vec<FirewallRule>> {
            let mut by_weight: std::collections::BTreeMap<
                u8,
                std::collections::HashSet<FirewallRule>,
            > = std::collections::BTreeMap::new();
            for (direction, is_v6) in ALL_LAYERS {
                for (weight, rule) in read_layer_rules(engine, direction, is_v6)? {
                    by_weight.entry(weight).or_default().insert(rule);
                }
            }
            // Weight is assigned once per rule from its position in the
            // caller's original flat `policy.rules` list (see
            // `rule_weight`), regardless of direction, so — unlike the
            // Linux backend's separate inbound/outbound chains — merging
            // by descending weight across all four layers reconstructs the
            // caller's exact original order, including interleaved
            // directions. A `remote: None` rule decodes identically from
            // both its v4 and v6 layer, which the `HashSet` collapses back
            // to the single original rule.
            Ok(by_weight
                .into_iter()
                .rev()
                .filter_map(|(_, rules)| rules.into_iter().next())
                .collect())
        })();
        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
        result
    }
}

impl FirewallMutator for WindowsBackend {
    type FirewallPolicy = WindowsFirewallPolicy;

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
    fn rule_weight_decreases_with_index_and_never_reaches_zero() {
        assert_eq!(rule_weight(0, 3), 3);
        assert_eq!(rule_weight(1, 3), 2);
        assert_eq!(rule_weight(2, 3), 1);
        // Every rule outranks the default-verdict filter's weight of 0.
        assert!(rule_weight(2, 3) > 0);
    }

    #[test]
    fn rule_weight_clamps_at_u8_max_for_large_policies() {
        assert_eq!(rule_weight(0, 1000), u8::MAX);
        assert_eq!(rule_weight(998, 1000), 2);
        assert_eq!(rule_weight(999, 1000), 1);
    }

    #[test]
    fn protocol_number_disambiguates_icmp_by_layer_family() {
        assert_eq!(protocol_number(Protocol::Icmp, false), 1);
        assert_eq!(protocol_number(Protocol::Icmp, true), 58);
        assert_eq!(protocol_number(Protocol::Tcp, false), 6);
        assert_eq!(protocol_number(Protocol::Udp, true), 17);
    }

    #[test]
    fn layers_for_rule_with_no_remote_covers_both_families() {
        let rule = FirewallRule::new(Direction::Outbound, Verdict::Deny);
        let layers = layers_for_rule(&rule);
        assert_eq!(
            layers,
            vec![(Direction::Outbound, false), (Direction::Outbound, true)]
        );
    }

    #[test]
    fn layers_for_rule_with_v4_remote_is_v4_only() {
        use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

        let rule = FirewallRule::new(Direction::Inbound, Verdict::Allow).with_remote(Network::V4(
            Ipv4Network::new(
                Ipv4Address::new(10, 0, 0, 0),
                Ipv4PrefixLength::new(8).unwrap(),
            ),
        ));
        assert_eq!(layers_for_rule(&rule), vec![(Direction::Inbound, false)]);
    }

    #[test]
    fn layers_for_rule_with_v6_remote_is_v6_only() {
        use net_lattice_ip::{Ipv6Address, Ipv6Network, Ipv6PrefixLength};

        let rule = FirewallRule::new(Direction::Outbound, Verdict::Deny).with_remote(Network::V6(
            Ipv6Network::new(
                Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                Ipv6PrefixLength::new(32).unwrap(),
            ),
        ));
        assert_eq!(layers_for_rule(&rule), vec![(Direction::Outbound, true)]);
    }

    /// Exercises `build_rule_conditions`/`decode_filter` entirely in
    /// process memory — no WFP engine, no privilege — by building a
    /// filter's condition list for a [`FirewallRule`], wrapping it in a
    /// bare `FWPM_FILTER0`, and decoding it straight back. Catches a
    /// `build`/`decode` mismatch a compile-only check cannot, at the cost
    /// of not proving the real WFP condition-value encoding itself is
    /// correct — see the privileged test below for that half of the risk.
    #[test]
    fn build_then_decode_filter_round_trips_every_match_shape() {
        use net_lattice_ip::{
            Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
        };

        let cases = [
            (
                FirewallRule::new(Direction::Outbound, Verdict::Allow).with_interface_index(1),
                false,
            ),
            (
                FirewallRule::new(Direction::Outbound, Verdict::Deny).with_remote(Network::V4(
                    Ipv4Network::new(
                        Ipv4Address::new(198, 51, 100, 0),
                        Ipv4PrefixLength::new(24).unwrap(),
                    ),
                )),
                false,
            ),
            (
                FirewallRule::new(Direction::Inbound, Verdict::Deny).with_remote(Network::V6(
                    Ipv6Network::new(
                        Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                        Ipv6PrefixLength::new(32).unwrap(),
                    ),
                )),
                true,
            ),
            (
                FirewallRule::new(Direction::Outbound, Verdict::Allow)
                    .with_protocol(Protocol::Udp)
                    .with_port(PortRange::single(53)),
                false,
            ),
            (
                FirewallRule::new(Direction::Inbound, Verdict::Allow)
                    .with_protocol(Protocol::Tcp)
                    .with_port(PortRange::new(1000, 2000)),
                false,
            ),
            (
                FirewallRule::new(Direction::Outbound, Verdict::Deny).with_protocol(Protocol::Icmp),
                false,
            ),
        ];

        for (rule, is_v6) in cases {
            let built = build_rule_conditions(&rule, is_v6).expect("build conditions");
            let filter = FWPM_FILTER0 {
                weight: weight_value(7),
                numFilterConditions: built.conditions.len() as u32,
                filterCondition: built.conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0,
                action: wfp_action(rule.verdict),
                ..Default::default()
            };
            let decoded = decode_filter(&filter, rule.direction);
            assert_eq!(decoded, Some((7, rule)), "round trip for {rule:?}");
        }
    }

    #[test]
    fn decode_filter_skips_the_weight_zero_default_verdict_filter() {
        let filter = FWPM_FILTER0 {
            weight: weight_value(0),
            action: wfp_action(Verdict::Deny),
            ..Default::default()
        };
        assert_eq!(decode_filter(&filter, Direction::Outbound), None);
    }

    /// Requires running as Administrator on a real Windows host with the
    /// Base Filtering Engine service running (the default). Not run by
    /// default for the same reason as this crate's other privileged tests.
    ///
    /// Exercises every match shape `decode_filter` handles (interface, IPv4
    /// remote, IPv6 remote, a single port, a port range, and a bare
    /// protocol match) across *both* directions in one policy, to verify
    /// the module doc comment's claim that weight-based merging
    /// reconstructs the exact original interleaved order. An earlier,
    /// narrower version of this test (one rule: outbound UDP/53 to a /24)
    /// has passed on real Windows CI as Administrator, including catching
    /// a real `FWP_E_NULL_DISPLAY_NAME` defect cross-compilation alone
    /// could not have found; this expanded version, covering the
    /// `decode_filter` read path added for `NL-165`, has not yet had its
    /// own CI run — the author of this change has no Windows host locally
    /// to verify it directly (only cross-compilation via `cargo
    /// check`/`clippy --target x86_64-pc-windows-gnu`, which catches
    /// type/signature mismatches but proves nothing about runtime
    /// behavior).
    #[test]
    #[ignore]
    fn set_then_clear_firewall_policy_round_trips_through_the_engine() {
        use net_lattice_ip::{
            Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
        };

        let backend = WindowsBackend::new().expect("create backend");

        let via_loopback =
            FirewallRule::new(Direction::Outbound, Verdict::Allow).with_interface_index(1);
        let v4_remote = FirewallRule::new(Direction::Outbound, Verdict::Deny).with_remote(
            Network::V4(Ipv4Network::new(
                Ipv4Address::new(198, 51, 100, 0),
                Ipv4PrefixLength::new(24).unwrap(),
            )),
        );
        let v6_remote = FirewallRule::new(Direction::Inbound, Verdict::Deny).with_remote(
            Network::V6(Ipv6Network::new(
                Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                Ipv6PrefixLength::new(32).unwrap(),
            )),
        );
        let single_port = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Udp)
            .with_port(net_lattice_model::firewall::PortRange::single(53));
        let port_range = FirewallRule::new(Direction::Inbound, Verdict::Allow)
            .with_protocol(Protocol::Tcp)
            .with_port(net_lattice_model::firewall::PortRange::new(1000, 2000));
        let protocol_only =
            FirewallRule::new(Direction::Outbound, Verdict::Deny).with_protocol(Protocol::Icmp);

        // Directions are deliberately interleaved, not grouped, to exercise
        // the cross-direction order-fidelity this backend's weight scheme
        // claims over the Linux backend's per-chain-only ordering.
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
}
