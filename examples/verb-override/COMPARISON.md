# Comparison: resource-attributes vs verb-override

This document shows the key differences between the standard `resource-attributes` example and the `verb-override` example.

## Configuration Differences

### Standard resource-attributes example
```yaml
authorization:
  resourceAttributes:
    namespace: default
    apiVersion: v1
    resource: services
    subresource: proxy
    name: kube-rbac-proxy
    # No verb specified - uses HTTP method mapping
```

**Behavior**:
- `GET` request → requires `get` permission on `services/proxy`
- `POST` request → requires `create` permission on `services/proxy`
- `DELETE` request → requires `delete` permission on `services/proxy`

### Verb-override example
```yaml
authorization:
  resourceAttributes:
    namespace: monitoring
    apiVersion: v1
    resource: pods
    verb: "list"  # Static verb override
```

**Behavior**:
- `GET` request → requires `list` permission on `pods`
- `POST` request → requires `list` permission on `pods`
- `DELETE` request → requires `list` permission on `pods`
- **Any HTTP method** → requires `list` permission on `pods`

## When to Use Each

### Use standard resource-attributes when:
- Your API follows standard REST conventions
- HTTP methods accurately represent the Kubernetes operations
- You want different permissions for different HTTP methods

### Use verb-override when:
- You want consistent permissions regardless of HTTP method
- Your endpoint semantics don't match HTTP method conventions
- You're building monitoring/metrics endpoints that should always require "list"
- You want to simplify RBAC by using a single verb for all operations
