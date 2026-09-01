use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::str::FromStr;
use thiserror::Error;
#[allow(unused_imports)]
use tracing::{error, info};

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
        "::1/128".to_string(),
        "fc00::/7".to_string(),
        "fe80::/10".to_string(),
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
            management_port: default_management_port(),
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
    #[error("Invalid egress policy: {0}")]
    InvalidPolicy(String),
    #[error("I/O error during ruleset configuration: {0}")]
    IoError(#[from] std::io::Error),
}

pub fn parse_le_hex_ipv4(hex_str: &str) -> Option<Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    let bytes = val.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

pub fn discover_onlink_cidrs_from_route(route_content: &str) -> Vec<String> {
    let mut cidrs = BTreeSet::new();
    cidrs.insert("127.0.0.0/8".to_string());

    for line in route_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }

        let dest_hex = parts[1];
        let gateway_hex = parts[2];
        let mask_hex = parts[7];
        if gateway_hex != "00000000" {
            continue;
        }

        if let (Some(dest_ip), Some(mask_ip)) =
            (parse_le_hex_ipv4(dest_hex), parse_le_hex_ipv4(mask_hex))
        {
            let prefix = u32::from(mask_ip).count_ones();
            if prefix > 0 && prefix <= 32 {
                cidrs.insert(format!("{dest_ip}/{prefix}"));
            }
        }
    }

    cidrs.into_iter().collect()
}

pub fn discover_management_cidrs() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            return discover_onlink_cidrs_from_route(&content);
        }
    }
    vec!["127.0.0.0/8".to_string()]
}

pub fn discover_resolvers_from_resolv_conf(resolv_content: &str) -> Vec<String> {
    let mut resolvers = BTreeSet::new();
    for line in resolv_content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("nameserver") {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 && IpAddr::from_str(parts[1]).is_ok() {
            resolvers.insert(parts[1].to_string());
        }
    }
    resolvers.into_iter().collect()
}

pub fn discover_resolvers() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            return discover_resolvers_from_resolv_conf(&content);
        }
    }
    vec!["127.0.0.11".to_string()]
}

pub fn split_ip_families(addrs: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for addr in addrs {
        let clean = addr.trim();
        if clean.is_empty() {
            continue;
        }
        let ip_part = clean.split('/').next().unwrap_or(clean);
        match IpAddr::from_str(ip_part) {
            Ok(IpAddr::V4(_)) => v4.push(clean.to_string()),
            Ok(IpAddr::V6(_)) => v6.push(clean.to_string()),
            Err(_) if clean.contains(':') => v6.push(clean.to_string()),
            Err(_) => v4.push(clean.to_string()),
        }
    }

    (v4, v6)
}

pub fn is_valid_ip_or_cidr(spec: &str) -> bool {
    let clean = spec.trim();
    if clean.is_empty() {
        return false;
    }

    if let Some((address, prefix)) = clean.rsplit_once('/') {
        let Ok(ip) = IpAddr::from_str(address) else {
            return false;
        };
        let Ok(prefix) = prefix.parse::<u8>() else {
            return false;
        };
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        return prefix <= max_prefix;
    }

    IpAddr::from_str(clean).is_ok()
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

    fn validate_address_list(label: &str, values: &[String]) -> Result<(), EgressError> {
        for value in values {
            if !is_valid_ip_or_cidr(value) {
                return Err(EgressError::InvalidAddress(format!("{label}: {value}")));
            }
        }
        Ok(())
    }

    pub fn validate_config(&self, config: &EgressConfig) -> Result<(), EgressError> {
        Self::validate_address_list("allowed_cidrs", &config.allowed_cidrs)?;
        if config
            .allowed_cidrs
            .iter()
            .any(|cidr| cidr.trim() == "0.0.0.0/0" || cidr.trim() == "::/0")
        {
            return Err(EgressError::InvalidPolicy(
                "unbounded /0 CIDRs are not permitted in the egress allowlist".to_string(),
            ));
        }
        Self::validate_address_list("denied_cidrs", &config.denied_cidrs)?;
        Self::validate_address_list("extra_management_cidrs", &config.extra_management_cidrs)?;
        Self::validate_address_list("extra_dns_resolvers", &config.extra_dns_resolvers)?;

        if config.proxy_enabled
            && config
                .proxy_target
                .as_deref()
                .is_none_or(|target| target.trim().is_empty())
        {
            return Err(EgressError::InvalidPolicy(
                "proxy_enabled requires a non-empty proxy_target".to_string(),
            ));
        }

        if matches!(config.mode, AuditMode::Remote | AuditMode::Hybrid)
            && config.allowed_cidrs.is_empty()
            && !config.tor_enabled
            && !config.proxy_enabled
        {
            return Err(EgressError::InvalidPolicy(
                "remote/hybrid mode requires resolved allowed CIDRs, Tor, or an upstream proxy"
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn push_ipv4_set(rules: &mut String, name: &str, values: &[String]) {
        if values.is_empty() {
            return;
        }
        rules.push_str(&format!("    set {name} {{\n"));
        rules.push_str("        type ipv4_addr\n");
        rules.push_str("        flags interval\n");
        rules.push_str(&format!("        elements = {{ {} }}\n", values.join(", ")));
        rules.push_str("    }\n\n");
    }

    fn push_ipv6_set(rules: &mut String, name: &str, values: &[String]) {
        if values.is_empty() {
            return;
        }
        rules.push_str(&format!("    set {name} {{\n"));
        rules.push_str("        type ipv6_addr\n");
        rules.push_str("        flags interval\n");
        rules.push_str(&format!("        elements = {{ {} }}\n", values.join(", ")));
        rules.push_str("    }\n\n");
    }

    /// Compile the kernel firewall policy. The management listener is reachable only from
    /// directly attached Docker/loopback subnets. Local mode permits only loopback and replies
    /// to already-established management connections; it opens no new DNS or Internet egress.
    pub fn compile_nftables_rules(&self, config: &EgressConfig) -> String {
        let mut rules = String::new();
        rules.push_str("#!/usr/sbin/nft -f\n");
        rules.push_str("# security-audit-plugin RoE egress guardrail\n\n");
        rules.push_str("flush ruleset\n\n");
        rules.push_str("table inet filter {\n");

        let mut management = discover_management_cidrs();
        for extra in &config.extra_management_cidrs {
            if !management.contains(extra) {
                management.push(extra.clone());
            }
        }
        let (mgmt_v4, _mgmt_v6) = split_ip_families(&management);

        let mut resolvers = discover_resolvers();
        for extra in &config.extra_dns_resolvers {
            if !resolvers.contains(extra) {
                resolvers.push(extra.clone());
            }
        }
        let (dns_v4, dns_v6) = split_ip_families(&resolvers);
        let (allowed_v4, allowed_v6) = split_ip_families(&config.allowed_cidrs);
        let (denied_v4, denied_v6) = split_ip_families(&config.denied_cidrs);

        Self::push_ipv4_set(&mut rules, "management_subnets_v4", &mgmt_v4);
        Self::push_ipv4_set(&mut rules, "dns_resolvers_v4", &dns_v4);
        Self::push_ipv6_set(&mut rules, "dns_resolvers_v6", &dns_v6);
        Self::push_ipv4_set(&mut rules, "allowed_targets_v4", &allowed_v4);
        Self::push_ipv6_set(&mut rules, "allowed_targets_v6", &allowed_v6);
        Self::push_ipv4_set(&mut rules, "denied_private_cidrs_v4", &denied_v4);
        Self::push_ipv6_set(&mut rules, "denied_private_cidrs_v6", &denied_v6);

        rules.push_str("    chain input {\n");
        rules.push_str("        type filter hook input priority 0; policy drop;\n");
        rules.push_str("        iifname \"lo\" accept\n");
        rules.push_str("        ct state established,related accept\n");
        rules.push_str("        ct state invalid drop\n");
        if !mgmt_v4.is_empty() {
            rules.push_str(&format!(
                "        ip saddr @management_subnets_v4 tcp dport {} accept comment \"host management\"\n",
                config.management_port
            ));
        }
        rules.push_str("    }\n\n");

        rules.push_str("    chain forward {\n");
        rules.push_str("        type filter hook forward priority 0; policy drop;\n");
        rules.push_str("    }\n\n");

        rules.push_str("    chain output {\n");
        rules.push_str("        type filter hook output priority 0; policy drop;\n");
        rules.push_str("        oifname \"lo\" accept\n");
        rules.push_str("        ct state established,related accept\n");
        rules.push_str("        ct state invalid drop\n");

        match config.mode {
            AuditMode::Local => {
                rules.push_str("        # Local mode: no new non-loopback network connections\n");
            }
            AuditMode::Remote | AuditMode::Hybrid => {
                rules.push_str("        # Remote / Hybrid mode: explicit pinned-target egress only\n");

                if !dns_v4.is_empty() {
                    rules.push_str("        ip daddr @dns_resolvers_v4 udp dport 53 accept comment \"DNS resolver v4\"\n");
                    rules.push_str("        ip daddr @dns_resolvers_v4 tcp dport 53 accept comment \"DNS resolver v4\"\n");
                }
                if !dns_v6.is_empty() {
                    rules.push_str("        ip6 daddr @dns_resolvers_v6 udp dport 53 accept comment \"DNS resolver v6\"\n");
                    rules.push_str("        ip6 daddr @dns_resolvers_v6 tcp dport 53 accept comment \"DNS resolver v6\"\n");
                }

                // Denied ranges win over explicit target CIDRs. Authorized private engagements
                // must narrow/replace denied_cidrs explicitly instead of disabling the guardrail
                // implicitly through a hostname that happens to resolve to a private address.
                if !denied_v4.is_empty() {
                    rules.push_str("        ip daddr @denied_private_cidrs_v4 drop comment \"block private/metadata v4\"\n");
                }
                if !denied_v6.is_empty() {
                    rules.push_str("        ip6 daddr @denied_private_cidrs_v6 drop comment \"block private/link-local v6\"\n");
                }

                if !allowed_v4.is_empty() {
                    rules.push_str("        ip daddr @allowed_targets_v4 accept comment \"explicit in-scope CIDRs v4\"\n");
                }
                if !allowed_v6.is_empty() {
                    rules.push_str("        ip6 daddr @allowed_targets_v6 accept comment \"explicit in-scope CIDRs v6\"\n");
                }

                if config.tor_enabled {
                    rules.push_str("        # Local Tor SOCKS/Control connections are covered by loopback accept\n");
                }
                if config.proxy_enabled {
                    rules.push_str("        # Upstream proxy endpoint is pinned in allowed CIDRs\n");
                }
            }
        }

        rules.push_str("        log prefix \"[NFT_ROE_DROP] \" group 0\n");
        rules.push_str("        drop\n");
        rules.push_str("    }\n");
        rules.push_str("}\n");
        rules
    }

    pub fn apply_rules(&self, config: &EgressConfig) -> Result<(), EgressError> {
        self.validate_config(config)?;
        let rules = self.compile_nftables_rules(config);
        info!("Applying nftables ruleset for mode: {:?}", config.mode);

        if self.mock_mode {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            let mut child = Command::new("nft")
                .args(["-f", "-"])
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
        assert!(discovered.iter().any(|c| c == "172.20.0.0/16"));
        assert!(discovered.iter().any(|c| c == "127.0.0.0/8"));
    }

    #[test]
    fn test_resolv_conf_discovery() {
        let discovered = discover_resolvers_from_resolv_conf(
            "# Docker\nnameserver 127.0.0.11\nnameserver 2001:4860:4860::8888\n",
        );
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
    fn validates_ip_and_cidr_specs() {
        assert!(is_valid_ip_or_cidr("93.184.216.34/32"));
        assert!(is_valid_ip_or_cidr("2001:db8::1/128"));
        assert!(is_valid_ip_or_cidr("127.0.0.11"));
        assert!(!is_valid_ip_or_cidr("10.0.0.1/33"));
        assert!(!is_valid_ip_or_cidr("1.2.3.4/32 }\nflush ruleset\n"));
    }

    #[test]
    fn local_mode_has_no_new_dns_or_management_egress() {
        let manager = EgressManager::new().with_mock_mode(true);
        let rules = manager.compile_nftables_rules(&EgressConfig::default());
        let output_chain = rules.split("chain output").nth(1).unwrap();

        assert!(rules.contains("ip saddr @management_subnets_v4 tcp dport 9999 accept"));
        assert!(output_chain.contains("Local mode: no new non-loopback network connections"));
        assert!(!output_chain.contains("udp dport 53 accept"));
        assert!(!output_chain.contains("ip daddr @management_subnets_v4 accept"));
        assert!(output_chain.contains("ct state established,related accept"));
    }

    #[test]
    fn remote_mode_has_only_explicit_pinned_target_egress() {
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

        assert!(rules.contains("elements = { 93.184.216.34/32 }"));
        assert!(rules.contains("elements = { 2606:4700:4700::1111/128 }"));
        assert!(rules.contains("ip daddr @allowed_targets_v4 accept"));
        assert!(rules.contains("ip6 daddr @allowed_targets_v6 accept"));
        assert!(!rules.contains("tcp dport { 80, 443, 8080, 8443 } accept"));
        assert!(!rules.contains("web audit egress"));
    }

    #[test]
    fn remote_mode_without_allowlist_or_proxy_fails_closed() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Remote,
            ..Default::default()
        };

        assert!(matches!(
            manager.apply_rules(&config),
            Err(EgressError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn unbounded_allowlist_is_rejected() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Remote,
            allowed_cidrs: vec!["0.0.0.0/0".to_string()],
            ..Default::default()
        };

        assert!(matches!(
            manager.apply_rules(&config),
            Err(EgressError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn invalid_cidr_is_rejected_before_nftables() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Remote,
            allowed_cidrs: vec!["93.184.216.34/32 }\nflush ruleset\n".to_string()],
            ..Default::default()
        };

        assert!(matches!(
            manager.apply_rules(&config),
            Err(EgressError::InvalidAddress(_))
        ));
    }

    #[test]
    fn proxy_target_is_not_interpolated_into_nftables_source() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Remote,
            proxy_enabled: true,
            proxy_target: Some("http://proxy.example:8080\nflush ruleset".to_string()),
            allowed_cidrs: vec!["203.0.113.7/32".to_string()],
            ..Default::default()
        };
        let rules = manager.compile_nftables_rules(&config);

        assert!(!rules.contains("proxy.example"));
        assert!(!rules.contains("flush ruleset\nflush ruleset"));
        assert!(rules.contains("Upstream proxy endpoint is pinned in allowed CIDRs"));
    }

    #[test]
    fn test_apply_rules_mock() {
        let manager = EgressManager::new().with_mock_mode(true);
        assert!(manager.apply_rules(&EgressConfig::default()).is_ok());
    }
}
