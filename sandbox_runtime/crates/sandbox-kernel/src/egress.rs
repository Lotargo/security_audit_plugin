use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::str::FromStr;
use thiserror::Error;
#[allow(unused_imports)]
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    Local,
    Remote,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    pub mode: AuditMode,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    #[serde(default = "default_denied_cidrs")]
    pub denied_cidrs: Vec<String>,
    #[serde(default)]
    pub proxy_enabled: bool,
    #[serde(default)]
    pub proxy_target: Option<String>,
    #[serde(default)]
    pub tor_enabled: bool,
    #[serde(default = "default_management_port")]
    pub management_port: u16,
    #[serde(default)]
    pub extra_management_cidrs: Vec<String>,
    #[serde(default)]
    pub extra_dns_resolvers: Vec<String>,
}

fn default_management_port() -> u16 {
    9999
}

pub fn default_denied_cidrs() -> Vec<String> {
    vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "127.0.0.0/8".to_string(),
        "169.254.0.0/16".to_string(),
        "0.0.0.0/8".to_string(),
        "224.0.0.0/4".to_string(),
        "240.0.0.0/4".to_string(),
    ]
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            mode: AuditMode::Local,
            targets: Vec::new(),
            allowed_cidrs: Vec::new(),
            denied_cidrs: default_denied_cidrs(),
            proxy_enabled: false,
            proxy_target: None,
            tor_enabled: false,
            management_port: 9999,
            extra_management_cidrs: Vec::new(),
            extra_dns_resolvers: Vec::new(),
        }
    }
}

#[derive(Error, Debug)]
pub enum EgressError {
    #[error("Failed to execute nft command: {0}")]
    ExecutionFailed(String),
    #[error("Invalid IP or CIDR specification: {0}")]
    InvalidAddress(String),
    #[error("I/O error during ruleset configuration: {0}")]
    IoError(#[from] std::io::Error),
}

/// Converts an 8-character little-endian hex string from /proc/net/route to an Ipv4Addr
pub fn parse_le_hex_ipv4(hex_str: &str) -> Option<Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    let bytes = val.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// Parses /proc/net/route content to discover directly attached on-link subnets
/// (e.g. Docker bridge / management networks) without requiring the 'ip' or 'route' CLI binary.
pub fn discover_onlink_cidrs_from_route(route_content: &str) -> Vec<String> {
    let mut cidrs = BTreeSet::new();
    cidrs.insert("127.0.0.0/8".to_string());

    for line in route_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        let dest_hex = parts[1];
        let gw_hex = parts[2];
        let mask_hex = parts[7];

        // Gateway == "00000000" indicates an on-link (directly attached) subnet
        if gw_hex != "00000000" {
            continue;
        }

        if let (Some(dest_ip), Some(mask_ip)) =
            (parse_le_hex_ipv4(dest_hex), parse_le_hex_ipv4(mask_hex))
        {
            let mask_u32 = u32::from(mask_ip);
            let prefix = mask_u32.count_ones();
            if prefix > 0 && prefix <= 32 {
                cidrs.insert(format!("{}/{}", dest_ip, prefix));
            }
        }
    }

    cidrs.into_iter().collect()
}

/// Reads Linux /proc/net/route if available, or returns loopback fallback
pub fn discover_management_cidrs() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            return discover_onlink_cidrs_from_route(&content);
        }
    }
    vec!["127.0.0.0/8".to_string()]
}

/// Parses /etc/resolv.conf content to extract configured nameserver IP addresses
pub fn discover_resolvers_from_resolv_conf(resolv_content: &str) -> Vec<String> {
    let mut resolvers = BTreeSet::new();
    for line in resolv_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(ip) = IpAddr::from_str(parts[1]) {
                    resolvers.insert(ip.to_string());
                }
            }
        }
    }
    resolvers.into_iter().collect()
}

/// Reads Linux /etc/resolv.conf if available
pub fn discover_resolvers() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            return discover_resolvers_from_resolv_conf(&content);
        }
    }
    vec!["127.0.0.11".to_string(), "1.1.1.1".to_string()]
}

/// Splits a list of IP addresses / CIDRs into IPv4 and IPv6 groups
pub fn split_ip_families(addrs: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for addr in addrs {
        let clean = addr.trim();
        if clean.is_empty() {
            continue;
        }

        // Check if CIDR or standalone IP
        let ip_part = clean.split('/').next().unwrap_or(clean);
        if let Ok(ip) = IpAddr::from_str(ip_part) {
            match ip {
                IpAddr::V4(_) => v4.push(clean.to_string()),
                IpAddr::V6(_) => v6.push(clean.to_string()),
            }
        } else if clean.contains(':') {
            v6.push(clean.to_string());
        } else {
            v4.push(clean.to_string());
        }
    }

    (v4, v6)
}

#[derive(Debug, Default)]
pub struct EgressManager {
    mock_mode: bool,
}

impl EgressManager {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        let mock_mode = false;
        #[cfg(not(target_os = "linux"))]
        let mock_mode = true;

        Self { mock_mode }
    }

    pub fn with_mock_mode(mut self, mock: bool) -> Self {
        self.mock_mode = mock;
        self
    }

    /// Compiles the strict nftables ruleset according to the supplied EgressConfig
    /// with dynamic management-plane discovery and IPv4/IPv6 address family isolation.
    pub fn compile_nftables_rules(&self, config: &EgressConfig) -> String {
        let mut rules = String::new();
        rules.push_str("#!/usr/sbin/nft -f\n");
        rules.push_str("# security-audit-plugin RoE Egress Guardrail (Decepticon Hardened)\n\n");
        rules.push_str("flush ruleset\n\n");

        rules.push_str("table inet filter {\n");

        // 1. Discover management CIDRs (on-link docker bridge + loopback)
        let mut mgmt_cidrs = discover_management_cidrs();
        for extra in &config.extra_management_cidrs {
            if !mgmt_cidrs.contains(extra) {
                mgmt_cidrs.push(extra.clone());
            }
        }
        let (mgmt_v4, _mgmt_v6) = split_ip_families(&mgmt_cidrs);

        // 2. Discover DNS resolvers
        let mut dns_resolvers = discover_resolvers();
        for extra in &config.extra_dns_resolvers {
            if !dns_resolvers.contains(extra) {
                dns_resolvers.push(extra.clone());
            }
        }
        let (dns_v4, dns_v6) = split_ip_families(&dns_resolvers);

        // 3. Allowed targets
        let (allowed_v4, allowed_v6) = split_ip_families(&config.allowed_cidrs);

        // 4. Denied CIDRs (SSRF & Private protection)
        let (denied_v4, denied_v6) = split_ip_families(&config.denied_cidrs);

        // Define nftables sets with strict family matching
        if !mgmt_v4.is_empty() {
            rules.push_str("    set management_subnets_v4 {\n");
            rules.push_str("        type ipv4_addr\n");
            rules.push_str("        flags interval\n");
            rules.push_str(&format!(
                "        elements = {{ {} }}\n",
                mgmt_v4.join(", ")
            ));
            rules.push_str("    }\n\n");
        }

        if !dns_v4.is_empty() {
            rules.push_str("    set dns_resolvers_v4 {\n");
            rules.push_str("        type ipv4_addr\n");
            rules.push_str("        flags interval\n");
            rules.push_str(&format!("        elements = {{ {} }}\n", dns_v4.join(", ")));
            rules.push_str("    }\n\n");
        }

        if !allowed_v4.is_empty() {
            rules.push_str("    set allowed_targets_v4 {\n");
            rules.push_str("        type ipv4_addr\n");
            rules.push_str("        flags interval\n");
            rules.push_str(&format!(
                "        elements = {{ {} }}\n",
                allowed_v4.join(", ")
            ));
            rules.push_str("    }\n\n");
        }

        if !allowed_v6.is_empty() {
            rules.push_str("    set allowed_targets_v6 {\n");
            rules.push_str("        type ipv6_addr\n");
            rules.push_str("        flags interval\n");
            rules.push_str(&format!(
                "        elements = {{ {} }}\n",
                allowed_v6.join(", ")
            ));
            rules.push_str("    }\n\n");
        }

        if !denied_v4.is_empty() {
            rules.push_str("    set denied_private_cidrs_v4 {\n");
            rules.push_str("        type ipv4_addr\n");
            rules.push_str("        flags interval\n");
            rules.push_str(&format!(
                "        elements = {{ {} }}\n",
                denied_v4.join(", ")
            ));
            rules.push_str("    }\n\n");
        }

        if !denied_v6.is_empty() {
            rules.push_str("    set denied_private_cidrs_v6 {\n");
            rules.push_str("        type ipv6_addr\n");
            rules.push_str("        flags interval\n");
            rules.push_str(&format!(
                "        elements = {{ {} }}\n",
                denied_v6.join(", ")
            ));
            rules.push_str("    }\n\n");
        }

        // Input chain (Strict management port + established)
        rules.push_str("    chain input {\n");
        rules.push_str("        type filter hook input priority 0; policy drop;\n");
        rules.push_str("        iifname \"lo\" accept\n");
        rules.push_str("        ct state established,related accept\n");
        rules.push_str("        ct state invalid drop\n");
        rules.push_str(&format!(
            "        tcp dport {} accept comment \"management-net\"\n",
            config.management_port
        ));
        rules.push_str("    }\n\n");

        // Forward chain
        rules.push_str("    chain forward {\n");
        rules.push_str("        type filter hook forward priority 0; policy drop;\n");
        rules.push_str("    }\n\n");

        // Output chain
        rules.push_str("    chain output {\n");
        rules.push_str("        type filter hook output priority 0; policy drop;\n");
        rules.push_str("        oifname \"lo\" accept\n");
        rules.push_str("        ct state established,related accept\n");
        rules.push_str("        ct state invalid drop\n");

        // CRITICAL DECEPTICON RULE: Management plane + local DNS always stay reachable, ahead of any deny!
        if !mgmt_v4.is_empty() {
            rules.push_str("        ip daddr @management_subnets_v4 accept comment \"Management subnets on-link\"\n");
        }
        if !dns_v4.is_empty() {
            rules.push_str("        ip daddr @dns_resolvers_v4 udp dport 53 accept comment \"DNS resolver v4\"\n");
            rules.push_str("        ip daddr @dns_resolvers_v4 tcp dport 53 accept comment \"DNS resolver v4\"\n");
        }
        if !dns_v6.is_empty() {
            rules.push_str("        ip6 daddr { ");
            rules.push_str(&dns_v6.join(", "));
            rules.push_str(" } udp dport 53 accept comment \"DNS resolver v6\"\n");
        }

        // Mode specific policy
        match config.mode {
            AuditMode::Local => {
                rules.push_str("        # Local mode: Complete outbound network isolation\n");
                rules.push_str("        # All non-management outbound traffic is dropped\n");
            }
            AuditMode::Remote | AuditMode::Hybrid => {
                rules.push_str("        # Remote / Hybrid mode: Controlled outbound access\n");

                // If Tor is enabled, allow access to local SOCKS5 and Tor daemon
                if config.tor_enabled {
                    rules.push_str("        # Allow Tor SOCKS5 and ControlPort\n");
                    rules.push_str("        tcp dport { 9050, 9051 } accept\n");
                }

                // If Proxy is enabled, allow access to proxy destination
                if config.proxy_enabled {
                    if let Some(proxy) = &config.proxy_target {
                        rules.push_str(&format!(
                            "        # Upstream proxy destination: {}\n",
                            proxy
                        ));
                    }
                }

                // Priority drop for private/cloud metadata ranges to prevent SSRF against host
                if !denied_v4.is_empty() {
                    rules.push_str("        ip daddr @denied_private_cidrs_v4 drop comment \"Block SSRF/Private subnets v4\"\n");
                }
                if !denied_v6.is_empty() {
                    rules.push_str("        ip6 daddr @denied_private_cidrs_v6 drop comment \"Block SSRF/Private subnets v6\"\n");
                }

                // General DNS if needed
                rules.push_str("        udp dport 53 accept\n");
                rules.push_str("        tcp dport 53 accept\n");

                // Allow traffic to explicitly allowed scope
                if !allowed_v4.is_empty() {
                    rules.push_str("        ip daddr @allowed_targets_v4 accept comment \"In-scope target CIDRs v4\"\n");
                }
                if !allowed_v6.is_empty() {
                    rules.push_str("        ip6 daddr @allowed_targets_v6 accept comment \"In-scope target CIDRs v6\"\n");
                }

                // Allow standard HTTP/HTTPS egress for remote DAST if targets are defined
                rules.push_str("        tcp dport { 80, 443, 8080, 8443 } accept comment \"HTTP/HTTPS web targets\"\n");
            }
        }

        rules.push_str("        # Default logging & drop\n");
        rules.push_str("        log prefix \"[NFT_ROE_DROP] \" group 0\n");
        rules.push_str("        drop\n");
        rules.push_str("    }\n");
        rules.push_str("}\n");

        rules
    }

    /// Applies the generated nftables configuration to the Linux kernel
    pub fn apply_rules(&self, config: &EgressConfig) -> Result<(), EgressError> {
        let rules = self.compile_nftables_rules(config);
        info!("Applying nftables ruleset for mode: {:?}", config.mode);

        if self.mock_mode {
            info!(
                "Running in mock/non-Linux mode. nftables rules generated successfully:\n{}",
                rules
            );
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            let mut child = Command::new("nft")
                .arg("-f")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(rules.as_bytes())?;
            }

            let output = child.wait_with_output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("Failed to apply nftables ruleset: {}", stderr);
                return Err(EgressError::ExecutionFailed(stderr.into_owned()));
            }
            info!("nftables rules applied successfully.");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_route_discovery() {
        let mock_route =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t011414AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
eth0\t000014AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n";

        let discovered = discover_onlink_cidrs_from_route(mock_route);
        // 000014AC with mask 0000FFFF -> 172.20.0.0/16
        assert!(discovered.iter().any(|c| c == "172.20.0.0/16"));
        // 0000007F with mask 000000FF -> 127.0.0.0/8
        assert!(discovered.iter().any(|c| c == "127.0.0.0/8"));
    }

    #[test]
    fn test_resolv_conf_discovery() {
        let mock_resolv =
            "# Generated by Docker\nnameserver 127.0.0.11\nnameserver 2001:4860:4860::8888\n";
        let discovered = discover_resolvers_from_resolv_conf(mock_resolv);
        assert_eq!(discovered.len(), 2);
        assert!(discovered.contains(&"127.0.0.11".to_string()));
        assert!(discovered.contains(&"2001:4860:4860::8888".to_string()));
    }

    #[test]
    fn test_split_ip_families() {
        let addrs = vec![
            "192.168.1.0/24".to_string(),
            "2001:db8::/32".to_string(),
            "10.0.0.1".to_string(),
            "::1".to_string(),
        ];
        let (v4, v6) = split_ip_families(&addrs);
        assert_eq!(v4, vec!["192.168.1.0/24", "10.0.0.1"]);
        assert_eq!(v6, vec!["2001:db8::/32", "::1"]);
    }

    #[test]
    fn test_local_mode_compilation() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Local,
            ..Default::default()
        };

        let rules = manager.compile_nftables_rules(&config);
        assert!(rules.contains("Local mode: Complete outbound network isolation"));
        assert!(rules.contains("tcp dport 9999 accept comment \"management-net\""));
        assert!(
            rules.contains("management_subnets_v4 accept comment \"Management subnets on-link\"")
        );
        assert!(rules.contains("policy drop"));
    }

    #[test]
    fn test_remote_mode_with_tor_and_targets() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Remote,
            allowed_cidrs: vec![
                "93.184.216.34/32".to_string(),
                "2606:4700:4700::1111/128".to_string(),
            ],
            tor_enabled: true,
            ..Default::default()
        };

        let rules = manager.compile_nftables_rules(&config);
        assert!(rules.contains("Remote / Hybrid mode: Controlled outbound access"));
        assert!(rules.contains("tcp dport { 9050, 9051 } accept"));
        assert!(rules.contains("ip daddr @denied_private_cidrs_v4 drop"));
        assert!(rules.contains("elements = { 93.184.216.34/32 }"));
        assert!(rules.contains("elements = { 2606:4700:4700::1111/128 }"));
    }

    #[test]
    fn test_apply_rules_mock() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig::default();
        assert!(manager.apply_rules(&config).is_ok());
    }
}
