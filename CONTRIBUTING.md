# Contributing to kube-rbac-proxy

## Development Setup

1. **Prerequisites:** Go 1.25+, `make`, access to a Kubernetes cluster for e2e tests.
2. **Build:**
   ```bash
   make build
   ```
3. **Run tests:**
   ```bash
   make test-unit    # Run unit tests
   make test-e2e     # Run e2e tests (requires cluster)
   ```
4. **Lint:**
   Linting runs in CI via golangci-lint.

## Pull Requests

1. Fork the repository and create a branch.
2. Ensure all tests pass and license headers are present (`make check-license`).
3. Open a PR against `master` with a clear description of the changes.
4. Debug any CI failures before requesting review.
