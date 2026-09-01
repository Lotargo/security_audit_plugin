# Backend Topology Cartography Report: Example Service

```mermaid
graph TD
    Client[SPA Frontend Client] -->|HTTPS / W3C Traceparent| GW[API Gateway: Envoy]
    GW -->|/api/v1/auth/*| SvcAuth[Auth Microservice: Node.js]
    GW -->|/api/v1/orders/*| SvcOrders[Orders Microservice: Go gRPC]
    GW -->|/api/v1/users/*| SvcUsers[User Profile Service: Python]
    SvcOrders -.->|Async Message Queue| ExtPayment[Stripe API]
```

## Discovered Microservices
1. **`auth-service`**: Handles session issuance, `/api/v1/auth/login`, `/api/v1/auth/refresh`.
2. **`orders-service`**: Internal gRPC service mapped via Envoy gRPC-Web bridge.
3. **`users-service`**: Exposes GraphQL sub-graph.
