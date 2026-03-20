# AI Agent Instructions

## Build & Test

```bash
make build        # Build the binary
make test-unit    # Run unit tests
make test-e2e     # Run e2e tests (requires cluster)
make check-license # Verify license headers
```

## Project Structure

- `cmd/` — Main entry point
- `pkg/` — Core proxy logic (authentication, authorization, rewrites, filters)
- `test/e2e/` — End-to-end tests
- `examples/` — Example configurations for various auth scenarios

## Key Patterns

- This is a Kubernetes auth proxy: it sits in front of a service and enforces RBAC via SubjectAccessReview.
- Authentication supports OIDC, client certificates, and token review.
- Authorization uses Kubernetes SubjectAccessReview with configurable resource/non-resource attributes.
