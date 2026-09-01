# Rate Limiting Algorithms & Architecture Comparison

| Algorithm | Mechanism | Memory Footprint | Burst Handling | Edge vs App Suitability |
| :--- | :--- | :--- | :--- | :--- |
| **Token Bucket** | Tokens added at fixed rate; requests consume tokens | $O(1)$ per key | Handles bursts gracefully up to bucket capacity | Ideal for API Gateways (Envoy/Kong) |
| **Leaky Bucket** | Requests queue and exit at constant rate | $O(1)$ per key | Smooths out bursts to constant egress rate | Good for downstream DB protection |
| **Fixed Window** | Counter reset at fixed intervals (e.g. 1 min) | $O(1)$ per key | Vulnerable to $2\times$ burst at window boundaries | Simple, but prone to boundary spikes |
| **Sliding Window Log** | Timestamps stored in sorted set | $O(N)$ requests in window | High precision, no boundary spike | Memory intensive, unsuitable for high traffic |
| **Sliding Window Counter** | Hybrid weighted sum of previous & current window | $O(1)$ per key | Balanced accuracy with low memory footprint | Industry standard for Redis implementations |
