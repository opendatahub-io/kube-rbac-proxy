# Per-Endpoint Rewrite in kube-rbac-proxy: Tutorial and Security Analysis

## Table of Contents

1. [Overview](#overview)
2. [Concepts](#concepts)
3. [Configuration Formats](#configuration-formats)
4. [Request Flow](#request-flow)
5. [Template Variables](#template-variables)
6. [Hands-On: Running in a Kind Cluster](#hands-on-running-in-a-kind-cluster)
7. [Security Analysis](#security-analysis)

---

## Overview

kube-rbac-proxy is a reverse proxy that authenticates and authorizes incoming HTTP requests using Kubernetes RBAC before forwarding them to an upstream service. The **per-endpoint rewrite** feature lets you define path-scoped authorization rules that extract values from HTTP headers or query parameters and inject them into Kubernetes `SubjectAccessReview` (SAR) requests.

This enables **multi-tenant authorization**: a single proxy can enforce different RBAC policies per URL path and derive the authorization namespace (or other SAR fields) dynamically from the request itself.

---

## Concepts

### SubjectAccessReview (SAR)

A SAR is how Kubernetes answers "can user X perform verb Y on resource Z?". kube-rbac-proxy constructs SARs from its config and delegates the decision to the Kubernetes API server. The key fields are:

| Field         | Example                       | Purpose                            |
|---------------|-------------------------------|-------------------------------------|
| `namespace`   | `tenant-a`                    | Scope the check to a namespace      |
| `apiGroup`    | `trustyai.opendatahub.io`     | API group of the virtual resource    |
| `resource`    | `status-events`               | Virtual resource name                |
| `verb`        | `create`                      | Kubernetes API verb                  |
| `subresource` | `metrics`                     | Optional sub-resource                |
| `name`        | `my-job`                      | Specific resource instance           |

### Rewrite

A **rewrite** extracts a value from the incoming HTTP request (header or query parameter) and substitutes it into the SAR fields using Go templates. This is what makes authorization dynamic rather than static.

---

## Configuration Formats

kube-rbac-proxy supports two configuration formats. Both live under `authorization:` in the config file.

### Format 1: Global Rewrites (Legacy)

A single set of rewrite rules and resource attributes applied to **all** requests:

```yaml
authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    apiVersion: v1
    resource: namespace
    subresource: metrics
    namespace: "{{ .Value }}"
```

- Extracts the `namespace` query parameter from the URL.
- `{{ .Value }}` is replaced with each collected value.
- Multiple values (e.g. `?namespace=ns1&namespace=ns2`) produce multiple SARs; **all must pass**.

### Format 2: Per-Endpoint Rules

Path-scoped rules with per-method mappings. This is the more powerful format:

```yaml
authorization:
  endpoints:
    - path: /api/v1/evaluations/jobs/*/events
      mappings:
        - methods: [post]
          resources:
            - rewrites:
                byHttpHeader:
                  name: X-Tenant
              resourceAttributes:
                namespace: "{{ .FromHeader }}"
                apiGroup: trustyai.opendatahub.io
                resource: status-events
                verb: create
        - methods: [get]
          resources:
            - resourceAttributes:
                namespace: default
                apiGroup: trustyai.opendatahub.io
                resource: status-events
                verb: get
```

Key properties:
- `path` supports `*` wildcards that match exactly one path segment.
- Each mapping binds HTTP methods to resource rules.
- Each resource rule can have its own `rewrites` and `resourceAttributes`.
- When Format 2 matches a path, Format 1 rules are **skipped entirely** for that request.

### Precedence

```
Incoming request
  |
  +--> Does path match any Format2 endpoint?
  |      YES --> Use Format2 rules (ignore Format1)
  |      |         Does method match a mapping?
  |      |           YES --> Build SAR from endpoint resource rules
  |      |           NO  --> 403 Forbidden (method not allowed)
  |      |
  |      NO --> Fall through to Format1
  |               Has resourceAttributes? --> Resource SAR
  |               No resourceAttributes?  --> Non-resource SAR (path-based)
```

---

## Request Flow

Here is the complete flow from HTTP request to authorization decision:

```
1. HTTP Request arrives at kube-rbac-proxy
     |
2. Authentication (filters.WithAuthentication)
   - TokenReview against Kubernetes API server
   - Extracts user identity (name, groups, UID)
     |
3. Authorization (filters.WithAuthorization)
   - Calls GetRequestAttributes(user, request)
     |
   3a. Format2 path matching (endpoints.go:matchEndpoint)
       - path.Clean() normalizes the request path
       - Segment-by-segment comparison, "*" matches one segment
       - First matching endpoint wins
     |
   3b. Rewrite extraction (endpoints.go:attributesFromEndpointResourceRules)
       - Header: request.Header.Get(name) -- single value
       - Query:  request.URL.Query()[name][0] -- first value
       - Missing required values --> 400 Bad Request
     |
   3c. Template expansion (endpoints.go:applyEndpointFieldTemplate)
       - Go text/template parses and executes against TemplateData
       - Each resourceAttributes field is expanded independently
     |
   3d. SAR construction
       - One authorizer.AttributesRecord per resource rule
       - verb defaults to HTTPToKubeVerb(request.Method) if not set
     |
4. For EACH generated SAR:
   - Call az.Authorize(ctx, attrs) --> SubjectAccessReview to API server
   - ANY denial --> 403 Forbidden (fail-secure, short-circuit)
     |
5. ALL SARs passed --> Forward request to upstream
```

Source code locations:
- Authentication filter: `pkg/filters/auth.go:37`
- Authorization filter: `pkg/filters/auth.go:65`
- GetRequestAttributes: `pkg/proxy/proxy.go:49`
- Endpoint matching: `pkg/authz/endpoints.go:131`
- Attribute building: `pkg/authz/endpoints.go:298`
- Template expansion: `pkg/authz/endpoints.go:240`

---

## Template Variables

### Format 1

| Variable      | Source                      |
|---------------|-----------------------------|
| `{{ .Value }}` | Each header or query value  |

Format 1 creates one SAR per value. Multiple query params or headers produce multiple SARs.

### Format 2

| Variable              | Source                                          |
|-----------------------|-------------------------------------------------|
| `{{ .Value }}`        | Header value if set, else query value (compat)  |
| `{{ .FromHeader }}`   | HTTP header value (from `byHttpHeader.name`)    |
| `{{ .FromQueryString }}` | Query parameter value (from `byQueryParameter.name`) |
| `{{ .FromMethod }}`   | Kubernetes verb derived from HTTP method        |

HTTP method to Kubernetes verb mapping (`pkg/authz/endpoints.go:219`):

| HTTP Method | Kube Verb |
|-------------|-----------|
| GET         | get       |
| POST        | create    |
| PUT         | update    |
| DELETE      | delete    |
| PATCH       | patch     |

---

## Hands-On: Running in a Kind Cluster

This section walks through deploying kube-rbac-proxy with per-endpoint rewrite rules in a local Kind cluster, then testing the authorization behavior.

### Prerequisites

- [kind](https://kind.sigs.k8s.io/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [docker](https://docs.docker.com/get-docker/)
- Go 1.26+ (to build kube-rbac-proxy from source)

### Step 1: Create a Kind Cluster

```bash
kind create cluster --name rbac-proxy-demo
```

### Step 2: Build and Load the Image

```bash
# From the kube-rbac-proxy repository root
make build
make container CONTAINER_NAME=kube-rbac-proxy:demo

# Load into Kind
kind load docker-image kube-rbac-proxy:demo --name rbac-proxy-demo
```

### Step 3: Deploy the Manifests

Create `demo-endpoint-rewrite.yaml`:

```yaml
# ServiceAccount for kube-rbac-proxy
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-rbac-proxy
  namespace: default
---
# ClusterRole: permissions for kube-rbac-proxy to call TokenReview and SubjectAccessReview
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
  - apiGroups: ["authorization.k8s.io"]
    resources: ["subjectaccessreviews"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy
subjects:
  - kind: ServiceAccount
    name: kube-rbac-proxy
    namespace: default
---
# Create a test namespace for tenant isolation
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-a
---
# ConfigMap with per-endpoint rewrite configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-rbac-proxy-config
  namespace: default
data:
  config-file.yaml: |
    authorization:
      endpoints:
        # Endpoint 1: tenant-scoped event ingestion
        - path: /api/v1/jobs/*/events
          mappings:
            - methods: [post]
              resources:
                - rewrites:
                    byHttpHeader:
                      name: X-Tenant
                  resourceAttributes:
                    namespace: "{{ .FromHeader }}"
                    apiGroup: demo.example.io
                    resource: events
                    verb: create
            - methods: [get]
              resources:
                - rewrites:
                    byQueryParameter:
                      name: ns
                  resourceAttributes:
                    namespace: "{{ .FromQueryString }}"
                    apiGroup: demo.example.io
                    resource: events
                    verb: get

        # Endpoint 2: tenant-scoped metrics (query param rewrite)
        - path: /api/v1/metrics
          mappings:
            - methods: [get]
              resources:
                - rewrites:
                    byQueryParameter:
                      name: namespace
                  resourceAttributes:
                    namespace: "{{ .Value }}"
                    apiVersion: v1
                    resource: namespace
                    subresource: metrics
---
# Service
apiVersion: v1
kind: Service
metadata:
  name: kube-rbac-proxy
  namespace: default
spec:
  ports:
    - name: https
      port: 8443
      targetPort: 8443
  selector:
    app: kube-rbac-proxy
---
# Deployment: kube-rbac-proxy + a simple upstream (echo server)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-rbac-proxy
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kube-rbac-proxy
  template:
    metadata:
      labels:
        app: kube-rbac-proxy
    spec:
      securityContext:
        runAsUser: 65532
      serviceAccountName: kube-rbac-proxy
      containers:
        - name: kube-rbac-proxy
          image: kube-rbac-proxy:demo
          imagePullPolicy: Never
          args:
            - "--secure-listen-address=0.0.0.0:8443"
            - "--upstream=http://127.0.0.1:8081/"
            - "--config-file=/etc/kube-rbac-proxy/config-file.yaml"
            - "--logtostderr=true"
            - "--v=10"
          ports:
            - containerPort: 8443
              name: https
          volumeMounts:
            - name: config
              mountPath: /etc/kube-rbac-proxy
          securityContext:
            allowPrivilegeEscalation: false
        - name: upstream-echo
          image: quay.io/brancz/prometheus-example-app:v0.5.0
          args: ["--bind=127.0.0.1:8081"]
      volumes:
        - name: config
          configMap:
            name: kube-rbac-proxy-config
```

Apply it:

```bash
kubectl apply -f demo-endpoint-rewrite.yaml
kubectl wait --for=condition=available deployment/kube-rbac-proxy --timeout=60s
```

### Step 4: Create RBAC for a Test User

Grant a service account permission to `create events` in `tenant-a` only:

```yaml
# test-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-user
  namespace: default
---
# Allow test-user to create demo.example.io/events in tenant-a ONLY
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tenant-a-event-writer
  namespace: tenant-a
rules:
  - apiGroups: ["demo.example.io"]
    resources: ["events"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: test-user-event-writer
  namespace: tenant-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: tenant-a-event-writer
subjects:
  - kind: ServiceAccount
    name: test-user
    namespace: default
```

```bash
kubectl apply -f test-rbac.yaml
```

### Step 5: Test the Authorization

Get a token for the test service account and set up port-forwarding:

```bash
# Get test-user token
TOKEN=$(kubectl create token test-user -n default)

# Port-forward in background
kubectl port-forward svc/kube-rbac-proxy 8443:8443 &
```

**Test 1: Authorized request (X-Tenant: tenant-a)**

```bash
curl -sk https://localhost:8443/api/v1/jobs/job-1/events \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant: tenant-a"

# Expected: 200 OK (forwarded to upstream)
# The SAR checks: can test-user create demo.example.io/events in namespace tenant-a? --> YES
```

**Test 2: Unauthorized request (X-Tenant: tenant-b)**

```bash
curl -sk https://localhost:8443/api/v1/jobs/job-1/events \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant: tenant-b"

# Expected: 403 Forbidden
# The SAR checks: can test-user create demo.example.io/events in namespace tenant-b? --> NO
```

**Test 3: Missing required header**

```bash
curl -sk https://localhost:8443/api/v1/jobs/job-1/events \
  -X POST \
  -H "Authorization: Bearer $TOKEN"

# Expected: 400 Bad Request
# X-Tenant header is required by the rewrite config but missing
```

**Test 4: Wrong HTTP method**

```bash
curl -sk https://localhost:8443/api/v1/jobs/job-1/events \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant: tenant-a"

# Expected: 403 Forbidden ("HTTP method is not permitted for this endpoint")
# DELETE is not listed in any mapping for this path
```

**Test 5: Non-matching path falls through to Format1 (or non-resource)**

```bash
curl -sk https://localhost:8443/some/other/path \
  -H "Authorization: Bearer $TOKEN"

# Expected: 403 Forbidden (no Format1 rules configured, non-resource SAR on this path)
```

### Step 6: Cleanup

```bash
kind delete cluster --name rbac-proxy-demo
```

---

## Security Analysis

### 1. Fail-Secure Design

The proxy defaults to **deny** on every failure path:

| Condition                          | HTTP Status | Behavior                |
|------------------------------------|-------------|-------------------------|
| Missing required header/query      | 400         | Request rejected        |
| No attributes generated            | 400         | Request rejected        |
| Path matched, method not in config | 403         | Request rejected        |
| SAR returns Deny or NoOpinion      | 403         | Request rejected        |
| SAR API call fails                 | 500         | Request rejected        |
| Any one SAR of many fails          | 403         | Short-circuit, rejected |

There is no fallback to "allow" on error. This is the correct security posture.

**Source:** `pkg/filters/auth.go:74-116`

### 2. Input Extraction Safety

**Headers:** Format 2 uses `request.Header.Get()` which returns a single value. This prevents ambiguity from multiple header values that could lead to authorization bypass.

**Query parameters:** Format 2 takes `queryValues[0]` (first value only). This avoids the "parameter pollution" class of attacks where multiple values could confuse authorization logic.

**Format 1 difference:** Format 1 uses `request.Header.Values()` and collects *all* query values, creating one SAR per value. Since **all** must pass, this is also safe (more restrictive, not less).

**Source:** `pkg/authz/endpoints.go:298-322` and `pkg/authz/endpoints.go:382-401`

### 3. Template Injection Risk

Templates are parsed using Go's `text/template`. User-controlled data (header/query values) flows into the template **as data**, not as template syntax. The template string itself comes from the config file (trusted, admin-controlled).

```go
// The template is the config value like "{{ .FromHeader }}" -- admin-controlled
// The data is the TemplateData struct -- user-controlled but only fills struct fields
tmpl.Execute(output, templateData)
```

Since user input populates `TemplateData` struct fields (not the template string), template injection is **not possible**. The user cannot inject `{{ }}` directives through headers or query parameters.

However, a subtle risk exists: `text/template` (unlike `html/template`) does not escape output. If the expanded SAR field value is logged or reflected elsewhere, it could contain arbitrary strings. In this context, SAR fields are sent to the Kubernetes API server which validates them, so this is low risk.

**Source:** `pkg/authz/endpoints.go:240-253`

### 4. Path Traversal Protection

Request paths are normalized with `path.Clean()` before matching:

```go
requestPath = path.Clean(requestPath)  // endpoints.go:139
```

This collapses `//`, resolves `.` and `..`, and strips trailing slashes. This prevents path traversal bypasses like:

- `/api/v1/jobs/../../../etc/passwd` -- cleaned before matching
- `/api/v1/jobs//job-1/events` -- collapsed to `/api/v1/jobs/job-1/events`
- `/api/v1/jobs/job-1/events/` -- trailing slash stripped

The `*` wildcard matches **exactly one** segment (not zero, not multiple), preventing wildcard over-matching.

**Source:** `pkg/authz/endpoints.go:131-153`

### 5. Format Precedence Safety

When both Format 1 and Format 2 are configured, Format 2 takes strict precedence for matching paths. This is important because:

- Format 1 might have more permissive rules.
- An attacker cannot bypass Format 2 endpoint rules by crafting a request that "falls through" to Format 1 for a path that should be governed by Format 2.

Once a path matches an endpoint, Format 1 is **never consulted** for that request, even if the endpoint match results in an error.

**Source:** `pkg/proxy/proxy.go:57-71`

### 6. Error Message Information Leakage

Error responses are intentionally generic:

```go
const authorizationBadRequestBody = "Bad Request. The request or configuration is malformed."
```

Detailed error information (which header was missing, which template failed) is logged server-side at appropriate verbosity levels but **not** returned to the client. This prevents attackers from probing the configuration structure.

**Source:** `pkg/filters/auth.go:35, 89-90`

### 7. Configuration Validation

Config is validated at startup (`ValidateAuthorizationConfig`), catching:

- Empty endpoint paths
- Missing mappings or methods
- Empty rewrite header/query names
- Missing resource rules

This prevents "fail-open" scenarios where a misconfigured rule silently passes all requests.

**Source:** `pkg/authz/endpoints.go:171-216`

### 8. Recommendations

1. **Restrict header sources:** When using `byHttpHeader`, ensure the upstream load balancer or ingress strips or overwrites the rewrite header (e.g., `X-Tenant`) to prevent clients from spoofing authorization scope. kube-rbac-proxy trusts the header value as-is.

2. **Avoid broad wildcards:** A path like `/*` or `/api/*` matches many endpoints. Prefer specific paths to minimize unintended matches.

3. **Audit verb mappings:** If only `POST` should be allowed, don't include `GET` in the methods list. Unmapped methods get a hard 403, which is the safest default.

4. **Use Format 2 for multi-tenant:** Format 2's single-value extraction (`.Get()` for headers, `[0]` for query params) is safer for deriving authorization scope than Format 1's multi-value approach, because it avoids ambiguity.

5. **Monitor SAR denials:** Enable verbose logging (`--v=5` or higher) to audit authorization decisions. Denied SARs are logged with user, verb, resource, and namespace.
