//! Read, replace, and clear the managed native-firewall policy through the
//! public facade when explicitly enabled by the caller.
//!
//! Set `NET_LATTICE_APPLY_FIREWALL_EXAMPLE=1` and run with elevated
//! privilege (`CAP_NET_ADMIN` on Linux, Administrator on Windows, root on
//! macOS). This replaces the connected backend's managed firewall policy
//! with a minimal outbound-DNS-only allowlist, then restores an
//! unrestricted (default-allow, no rules) policy before exiting. See
//! `net-lattice-backend-linux/examples/kill_switch.rs` for a more elaborate
//! usage pattern (a fail-closed VPN kill switch) built on this same API.

use net_lattice::model::{Direction, FirewallRule, PortRange, Protocol, Verdict};
use net_lattice::mutation::FirewallPolicy;
use net_lattice::{Capability, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    if !lattice.supports(Capability::FIREWALL_MUTATION) {
        eprintln!("connected backend does not advertise Capability::FIREWALL_MUTATION");
        return Ok(());
    }

    println!("currently observed rules: {:?}", lattice.firewall_rules()?);

    if std::env::var("NET_LATTICE_APPLY_FIREWALL_EXAMPLE").as_deref() != Ok("1") {
        eprintln!(
            "set NET_LATTICE_APPLY_FIREWALL_EXAMPLE=1 (and run with the platform's elevated \
             privilege) to actually replace the managed policy"
        );
        return Ok(());
    }

    let allow_dns = FirewallRule::new(Direction::Outbound, Verdict::Allow)
        .with_protocol(Protocol::Udp)
        .with_port(PortRange::single(53));
    let policy = FirewallPolicy::new(Verdict::Deny).with_rule(allow_dns);

    lattice.set_firewall_policy(policy)?;
    println!("rules after set: {:?}", lattice.firewall_rules()?);

    lattice.clear_firewall_policy()?;
    println!("rules after clear: {:?}", lattice.firewall_rules()?);

    Ok(())
}
