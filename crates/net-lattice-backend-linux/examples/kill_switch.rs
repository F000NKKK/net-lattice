//! Builds a VPN-style kill switch on top of the generic native-firewall
//! policy API.
//!
//! `FirewallMutator`/`FirewallPolicy` are deliberately generic: they replace
//! one Net-Lattice-owned nftables table/chain pair with whatever ordered
//! rule list and default verdict the caller supplies. This example shows one
//! way to *use* that primitive for a kill switch — traffic is allowed to
//! leave only through loopback or a named tunnel interface, and everything
//! else is denied by the policy's default verdict — rather than treating
//! "kill switch" as a built-in mode of the API itself.
//!
//! Set `NET_LATTICE_APPLY_KILL_SWITCH_EXAMPLE=1` and run with `CAP_NET_ADMIN`
//! (e.g. via `sudo -E`) to actually install the policy; otherwise this only
//! prints the policy it would install. The example clears the policy before
//! exiting, restoring the default-allow state it started from.
//!
//! `net-lattice-backend-linux` compiles to an empty crate outside
//! `target_os = "linux"` (see its `#![cfg(target_os = "linux")]`), but an
//! example is its own crate root and is not covered by that attribute — a
//! workspace-wide `cargo check`/`build` on Windows or macOS would otherwise
//! try to compile this file against a backend crate that exports nothing
//! there. Gate the real body the same way the library does.

#[cfg(target_os = "linux")]
fn main() -> net_lattice_core::Result<()> {
    use net_lattice_model::firewall::{Direction, FirewallPolicy, FirewallRule, Verdict};
    use net_lattice_platform::{FirewallMutator, InterfaceProvider};

    let tunnel_interface_name =
        std::env::var("NET_LATTICE_KILL_SWITCH_INTERFACE").unwrap_or_else(|_| "tun0".to_string());

    let backend = net_lattice_backend_linux::LinuxBackend::new()?;

    let tunnel_index = backend
        .interfaces()?
        .into_iter()
        .find(|interface| interface.name == tunnel_interface_name)
        .map(|interface| interface.index);

    let Some(tunnel_index) = tunnel_index else {
        eprintln!(
            "interface {tunnel_interface_name:?} not found; bring up the tunnel first \
             or set NET_LATTICE_KILL_SWITCH_INTERFACE to an existing interface name"
        );
        return Ok(());
    };

    let loopback_index = backend
        .interfaces()?
        .into_iter()
        .find(|interface| interface.name == "lo")
        .map(|interface| interface.index);

    // Default-deny both directions; explicitly allow only loopback and the
    // tunnel interface. Everything else -- including any traffic that would
    // otherwise leave via the underlying physical interface if the tunnel
    // drops -- falls through to the default verdict and is dropped.
    let mut policy = FirewallPolicy::new(Verdict::Deny);
    if let Some(loopback_index) = loopback_index {
        policy = policy
            .with_rule(
                FirewallRule::new(Direction::Outbound, Verdict::Allow)
                    .with_interface_index(loopback_index),
            )
            .with_rule(
                FirewallRule::new(Direction::Inbound, Verdict::Allow)
                    .with_interface_index(loopback_index),
            );
    }
    policy = policy
        .with_rule(
            FirewallRule::new(Direction::Outbound, Verdict::Allow)
                .with_interface_index(tunnel_index),
        )
        .with_rule(
            FirewallRule::new(Direction::Inbound, Verdict::Allow)
                .with_interface_index(tunnel_index),
        );

    println!("kill-switch policy for interface {tunnel_interface_name:?} (index {tunnel_index}):");
    println!("{policy:#?}");

    if std::env::var("NET_LATTICE_APPLY_KILL_SWITCH_EXAMPLE").as_deref() != Ok("1") {
        eprintln!(
            "set NET_LATTICE_APPLY_KILL_SWITCH_EXAMPLE=1 (and run with CAP_NET_ADMIN) \
             to actually install this policy"
        );
        return Ok(());
    }

    let result = backend.set_firewall_policy(policy);
    println!("set_firewall_policy result: {result:?}");

    let cleared = backend.clear_firewall_policy();
    println!("clear_firewall_policy result: {cleared:?}");

    result
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this example only runs on target_os = \"linux\" (uses nftables via net-lattice-backend-linux)");
}
