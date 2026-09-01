# Rego Policy-as-Code Authorization Patterns (Open Policy Agent)

```rego
package authz

default allow = false

# Allow tenant admin to manage resources in their own tenant
allow {
    input.user.role == "tenant_admin"
    input.user.tenant_id == input.resource.tenant_id
}

# Allow regular user to read/update only their own resources
allow {
    input.user.role == "user"
    input.user.tenant_id == input.resource.tenant_id
    input.user.id == input.resource.owner_id
    input.action in ["read", "update"]
}

# Global platform admin override
allow {
    input.user.role == "super_admin"
}
```
