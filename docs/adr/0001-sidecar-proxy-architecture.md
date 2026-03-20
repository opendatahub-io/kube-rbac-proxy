# ADR-0001: Sidecar Proxy Architecture for RBAC Enforcement

## Status

Accepted

## Context

Kubernetes services need authorization enforcement, but not all applications implement RBAC natively. Adding authorization logic to each service creates duplication and inconsistency.

## Decision

Use a sidecar proxy pattern: kube-rbac-proxy runs as a container alongside the target service, intercepting all incoming requests and enforcing RBAC via Kubernetes SubjectAccessReview before forwarding to the upstream service.

Authentication supports multiple methods: OIDC tokens, client certificates, and Kubernetes TokenReview. Authorization maps requests to Kubernetes resource or non-resource attributes and delegates to the API server's SubjectAccessReview.

## Consequences

- Services do not need to implement their own authorization logic
- Authorization is consistent across all services using the proxy
- The proxy adds latency per request (SubjectAccessReview API call)
- Configuration is declarative via flags and static authorization files
- Metric rewrites allow safe exposure of service metrics with RBAC protection
