use std::collections::HashMap;
use std::time::{Duration, Instant};
use axum::{http::StatusCode, Json};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info};

#[derive(Debug, Deserialize)]
pub struct ProbeRequest {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub proxy: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ProbeResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub elapsed_ms: u64,
}

pub async fn handle_http_probe(
    Json(payload): Json<ProbeRequest>,
) -> Result<Json<ProbeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let method_str = payload.method.unwrap_or_else(|| "GET".to_string()).to_uppercase();
    let timeout_duration = Duration::from_secs(payload.timeout_secs.unwrap_or(15));
    info!("Sending HTTP probe: {} {} (proxy: {:?})", method_str, payload.url, payload.proxy);

    let mut client_builder = reqwest::Client::builder()
        .timeout(timeout_duration)
        .danger_accept_invalid_certs(true);

    if let Some(proxy_url) = payload.proxy {
        match reqwest::Proxy::all(&proxy_url) {
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
        "GET" => client.get(&payload.url),
        "POST" => client.post(&payload.url),
        "PUT" => client.put(&payload.url),
        "DELETE" => client.delete(&payload.url),
        "HEAD" => client.head(&payload.url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &payload.url),
        "PATCH" => client.patch(&payload.url),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Unsupported HTTP method: {}", method_str)})),
            ));
        }
    };

    // Attach custom headers (including L7 IP spoofing headers)
    if let Some(headers_map) = payload.headers {
        let mut header_map = HeaderMap::new();
        for (k, v) in headers_map {
            if let (Ok(h_name), Ok(h_val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
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

    Ok(Json(ProbeResponse {
        status,
        headers: resp_headers,
        body,
        elapsed_ms,
    }))
}
