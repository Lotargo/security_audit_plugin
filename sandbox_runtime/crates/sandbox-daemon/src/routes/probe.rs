use axum::{http::StatusCode, Json};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::{Error as IoError, ErrorKind};
use std::time::{Duration, Instant};
use tracing::{error, info};

#[derive(Debug, Deserialize)]
pub struct ProbeRequest {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub proxy: Option<String>,
    pub timeout_secs: Option<u64>,
    pub allowed_hosts: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct ProbeResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub waf_hints: Vec<String>,
    pub potential_deception_detected: bool,
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().to_ascii_lowercase();
    trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&trimmed)
        .to_string()
}

fn normalize_allowed_hosts(hosts: Option<Vec<String>>) -> HashSet<String> {
    hosts
        .unwrap_or_default()
        .into_iter()
        .map(|host| normalize_host(&host))
        .filter(|host| !host.is_empty())
        .collect()
}

fn url_matches_scope(url: &reqwest::Url, allowed_hosts: &HashSet<String>) -> bool {
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }
    if allowed_hosts.is_empty() {
        return true;
    }

    url.host_str()
        .map(normalize_host)
        .is_some_and(|host| allowed_hosts.contains(&host))
}

pub async fn handle_http_probe(
    Json(payload): Json<ProbeRequest>,
) -> Result<Json<ProbeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let method_str = payload
        .method
        .as_deref()
        .unwrap_or("GET")
        .to_uppercase();
    let timeout_duration = Duration::from_secs(payload.timeout_secs.unwrap_or(15));
    let allowed_hosts = normalize_allowed_hosts(payload.allowed_hosts.clone());

    let parsed_target = reqwest::Url::parse(&payload.url).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Invalid probe URL: {}", e)})),
        )
    })?;
    if !url_matches_scope(&parsed_target, &allowed_hosts) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Probe URL is outside the active RoE host scope"})),
        ));
    }
    if payload.proxy.is_some() && allowed_hosts.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Proxied HTTP probes require an explicit RoE host allowlist"
            })),
        ));
    }

    info!(
        "Sending HTTP probe: {} {} (proxy: {:?}, scope_hosts: {})",
        method_str,
        payload.url,
        payload.proxy,
        allowed_hosts.len()
    );

    let redirect_hosts = allowed_hosts.clone();
    let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error(IoError::new(
                ErrorKind::InvalidData,
                "HTTP probe exceeded the 10-redirect safety limit",
            ));
        }

        if url_matches_scope(attempt.url(), &redirect_hosts) {
            attempt.follow()
        } else {
            attempt.error(IoError::new(
                ErrorKind::PermissionDenied,
                format!(
                    "redirect target is outside active RoE scope: {}",
                    attempt.url()
                ),
            ))
        }
    });

    let mut client_builder = reqwest::Client::builder()
        .timeout(timeout_duration)
        .redirect(redirect_policy)
        .danger_accept_invalid_certs(true);

    if let Some(proxy_url) = payload.proxy.as_deref() {
        match reqwest::Proxy::all(proxy_url) {
            Ok(p) => {
                client_builder = client_builder.proxy(p);
            }
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Invalid proxy URL: {}", e)})),
                ));
            }
        }
    }

    let client = match client_builder.build() {
        Ok(c) => c,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to build HTTP client: {}", e)})),
            ));
        }
    };

    let mut req_builder = match method_str.as_str() {
        "GET" => client.get(parsed_target.clone()),
        "POST" => client.post(parsed_target.clone()),
        "PUT" => client.put(parsed_target.clone()),
        "DELETE" => client.delete(parsed_target.clone()),
        "HEAD" => client.head(parsed_target.clone()),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, parsed_target.clone()),
        "PATCH" => client.patch(parsed_target),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Unsupported HTTP method: {}", method_str)})),
            ));
        }
    };

    if let Some(headers_map) = payload.headers {
        let mut header_map = HeaderMap::new();
        for (k, v) in headers_map {
            if let (Ok(h_name), Ok(h_val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                header_map.insert(h_name, h_val);
            }
        }
        req_builder = req_builder.headers(header_map);
    }

    if let Some(body_content) = payload.body {
        req_builder = req_builder.body(body_content);
    }

    let start_time = Instant::now();
    let response = match req_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!("HTTP probe failed for {}: {}", payload.url, e);
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("HTTP probe request failed: {}", e)})),
            ));
        }
    };

    let elapsed_ms = start_time.elapsed().as_millis() as u64;
    let status = response.status().as_u16();

    let mut resp_headers = HashMap::new();
    for (k, v) in response.headers() {
        if let Ok(val_str) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), val_str.to_string());
        }
    }

    let body = response.text().await.unwrap_or_default();
    let body_lower = body.to_lowercase();

    let mut waf_hints = Vec::new();
    for k in resp_headers.keys() {
        let k_lower = k.to_lowercase();
        if k_lower.starts_with("cf-") {
            waf_hints.push("Cloudflare".to_string());
        } else if k_lower.starts_with("x-akamai") || k_lower.starts_with("akamai") {
            waf_hints.push("Akamai".to_string());
        } else if k_lower.starts_with("x-amzn-waf") {
            waf_hints.push("AWS-WAF".to_string());
        } else if k_lower.starts_with("x-datadome") {
            waf_hints.push("DataDome".to_string());
        } else if k_lower.starts_with("x-px") {
            waf_hints.push("PerimeterX".to_string());
        }
    }
    waf_hints.dedup();

    let potential_deception = match status {
        404 | 503 | 500 | 403 => {
            (body.len() > 1000
                && !body_lower.contains("not found")
                && !body_lower.contains("internal server error"))
                || (body.starts_with('{')
                    && body.contains("\"status\"")
                    && !body_lower.contains("error"))
        }
        _ => false,
    };

    Ok(Json(ProbeResponse {
        status,
        headers: resp_headers,
        body,
        elapsed_ms,
        waf_hints,
        potential_deception_detected: potential_deception,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_scope_hosts_are_enforced_for_probe_urls() {
        let allowed = normalize_allowed_hosts(Some(vec![
            "example.com".to_string(),
            "API.EXAMPLE.COM".to_string(),
        ]));

        let allowed_url = reqwest::Url::parse("https://api.example.com/v1").unwrap();
        let denied_url = reqwest::Url::parse("https://www.example.com/").unwrap();
        assert!(url_matches_scope(&allowed_url, &allowed));
        assert!(!url_matches_scope(&denied_url, &allowed));
    }

    #[test]
    fn empty_scope_hosts_preserve_direct_l3_only_mode() {
        let allowed = normalize_allowed_hosts(None);
        let url = reqwest::Url::parse("https://203.0.113.7/").unwrap();
        assert!(url_matches_scope(&url, &allowed));
    }
}
