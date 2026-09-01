use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::process::Command;
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
    pub fn compile_nftables_rules(&self, config: &EgressConfig) -> String {
        let mut rules = String::new();
        rules.push_str("#!/usr/sbin/nft -f\n");
        rules.push_str("# security-audit-plugin RoE Egress Guardrail\n\n");
        rules.push_str("flush ruleset\n\n");

        rules.push_str("table inet filter {\n");

        // Sets for dynamic targets and denied CIDRs
        rules.push_str("    set allowed_hosts {\n");
        rules.push_str("        type ipv4_addr\n");
        rules.push_str("        flags interval\n");
        if !config.allowed_cidrs.is_empty() {
            let elements = config.allowed_cidrs.join(", ");
            rules.push_str(&format!("        elements = {{ {} }}\n", elements));
        }
        rules.push_str("    }\n\n");

        rules.push_str("    set denied_private_cidrs {\n");
        rules.push_str("        type ipv4_addr\n");
        rules.push_str("        flags interval\n");
        if !config.denied_cidrs.is_empty() {
            let elements = config.denied_cidrs.join(", ");
            rules.push_str(&format!("        elements = {{ {} }}\n", elements));
        }
        rules.push_str("    }\n\n");

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

        // Mode specific policy
        match config.mode {
            AuditMode::Local => {
                rules.push_str("        # Local mode: Complete outbound network isolation\n");
                rules.push_str("        # All non-loopback outbound traffic is dropped\n");
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
                rules.push_str("        ip daddr @denied_private_cidrs drop comment \"Block SSRF/Private subnets\"\n");

                // Allow DNS only if not local mode
                rules.push_str("        udp dport 53 accept\n");
                rules.push_str("        tcp dport 53 accept\n");

                // Allow traffic to allowed scope
                if !config.allowed_cidrs.is_empty() {
                    rules.push_str("        ip daddr @allowed_hosts accept comment \"In-scope target CIDRs\"\n");
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
    fn test_local_mode_compilation() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Local,
            ..Default::default()
        };

        let rules = manager.compile_nftables_rules(&config);
        assert!(rules.contains("Local mode: Complete outbound network isolation"));
        assert!(rules.contains("tcp dport 9999 accept comment \"management-net\""));
        assert!(rules.contains("policy drop"));
    }

    #[test]
    fn test_remote_mode_with_tor_and_targets() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig {
            mode: AuditMode::Remote,
            allowed_cidrs: vec!["93.184.216.34/32".to_string(), "104.21.0.0/16".to_string()],
            tor_enabled: true,
            ..Default::default()
        };

        let rules = manager.compile_nftables_rules(&config);
        assert!(rules.contains("Remote / Hybrid mode: Controlled outbound access"));
        assert!(rules.contains("tcp dport { 9050, 9051 } accept"));
        assert!(rules.contains("ip daddr @denied_private_cidrs drop"));
        assert!(rules.contains("elements = { 93.184.216.34/32, 104.21.0.0/16 }"));
    }

    #[test]
    fn test_apply_rules_mock() {
        let manager = EgressManager::new().with_mock_mode(true);
        let config = EgressConfig::default();
        assert!(manager.apply_rules(&config).is_ok());
    }
}
