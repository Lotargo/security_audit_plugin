# API Gateway & Reverse Proxy Signature Headers

| Technology | Signature Headers / Cookies | Error Payload Fingerprint |
| :--- | :--- | :--- |
| **Envoy Proxy** | `x-envoy-upstream-service-time`, `x-envoy-decorator-operation` | `503 Service Unavailable: upstream connect error` |
| **Kong Gateway** | `kong-request-id`, `x-kong-proxy-latency`, `x-kong-upstream-latency` | `{"message":"An invalid response was received from the upstream server"}` |
| **AWS API Gateway** | `x-amzn-requestid`, `x-amz-cf-id`, `x-amzn-trace-id` | `{"message":"Forbidden"}` / `{"message":"Internal server error"}` |
| **Cloudflare** | `cf-ray`, `cf-cache-status`, `expect-ct` | Cloudflare 52x error HTML / challenge page |
| **Nginx / OpenResty** | `server: nginx`, `x-accel-expires`, `x-accel-buffering` | Standard HTML 502/504 Bad Gateway |
| **Traefik** | `x-traefik-router`, `x-traefik-service` | `404 page not found` plain text |
| **Spring Cloud Gateway** | `x-application-context` | Spring Boot Whitelabel Error Page JSON |
