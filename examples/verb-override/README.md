# verb-override example

> Note to try this out with minikube, make sure you enable RBAC correctly as explained [here](../minikube-rbac).

This example demonstrates the `verb` attribute in `resourceAttributes` configuration. The verb attribute allows you to specify a static custom verb that overrides the HTTP method-derived verb for RBAC authorization checks.

## Use Case

In this example, we deploy a [prometheus-example-app](https://github.com/brancz/prometheus-example-app) and protect it with the kube-rbac-proxy. Instead of using the default HTTP method mapping (GET → `get`), we configure the proxy to always require `list` permissions on pods in the monitoring namespace, regardless of the HTTP method used.

This is useful when:
- Your API endpoint should always require the same RBAC permission regardless of HTTP method
- You want to standardize on specific verbs like `list` for monitoring endpoints
- The HTTP method doesn't accurately represent the Kubernetes operation being performed

## Configuration

The key difference from the standard resource-attributes example is the addition of the `verb: "list"` field in the resourceAttributes configuration:

```yaml
authorization:
  resourceAttributes:
    namespace: monitoring
    apiGroup: ""
    apiVersion: v1
    resource: pods
    verb: "list"  # Override: always require "list" permission instead of HTTP method-derived verb
```

With this configuration:
- A `GET` request would normally require `get` permission, but now requires `list`
- A `POST` request would normally require `create` permission, but now requires `list`
- Any HTTP method will require `list` permission on pods in the monitoring namespace

## Deployment

```bash
$ kubectl create -f deployment.yaml
```

## Testing

Deploy a Job that performs a `curl` against the deployment. The client RBAC requires `list` permission on pods (see `client-rbac.yaml`).

```bash
$ kubectl create -f client-rbac.yaml client.yaml
```

## Testing Different HTTP Methods

All HTTP methods should require the same `list` permission:

```bash
# Test GET request (normally requires "get", now requires "list")
kubectl exec -it <pod-name> -- curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy-verb-override.default.svc:8443/metrics

# Test POST request (normally requires "create", now requires "list")
kubectl exec -it <pod-name> -- curl -X POST -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy-verb-override.default.svc:8443/metrics
```

Both requests will succeed because they both require `list` permission on pods.
