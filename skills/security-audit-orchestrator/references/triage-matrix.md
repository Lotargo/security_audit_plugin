# Skill Triage & Routing Matrix

| Target Attribute / Finding Lead | Primary Skill | Secondary / Fallback Skills |
| :--- | :--- | :--- |
| External HTTP(S) Domain / URL | `tor-anonymity-onion-routing` -> `web-appsec-dast` | `osint-attack-surface-mapping`, `abuse-prevention-resilience` |
| Client JS Bundles / Source Maps | `backend-topology-cartography` | `client-supply-chain-magecart`, `injection-input-validation` |
| Authentication / JWT / Tokens / Cryptography | `cryptography-token-security` | `access-control-business-logic`, `iam-active-directory-audit` |
| Input Fields / Forms / Query Parameters | `injection-input-validation` | `web-appsec-dast`, `abuse-prevention-resilience` |
| Rate Limits / Anti-bot / WAF Block | `abuse-prevention-resilience` | `tor-anonymity-onion-routing` |
| HTTP Smuggling / Reverse Proxies / CDN | `http-smuggling-cache-attacks` | `network-segmentation-perimeter` |
| Cloud / K8s Config / Dockerfile | `cloud-kubernetes-infra-audit` | `network-segmentation-perimeter`, `cicd-supply-chain-security` |
| CI/CD Pipeline / GitHub Actions | `cicd-supply-chain-security` | `client-supply-chain-magecart` |
| Secrets / Sensitive Logs / PII | `data-exposure-privacy-resilience` | `osint-attack-surface-mapping` |
| Mobile App (APK / IPA) | `mobile-appsec-analysis` | `backend-topology-cartography`, `cryptography-token-security` |
| Active Directory / Kerberos / IAM | `iam-active-directory-audit` | `network-segmentation-perimeter` |
| Network Topology / Lateral Movement | `network-segmentation-perimeter` | `purple-team-detection-engineering` |
| Blue Team Telemetry / Detection Rules | `purple-team-detection-engineering` | `data-exposure-privacy-resilience` |
| Phishing / Human Risk / Social Engineering | `social-engineering-risk-assessment` | `osint-attack-surface-mapping` |
