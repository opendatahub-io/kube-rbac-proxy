# Named path captures example

This example demonstrates named endpoint path parameters:

- `{tenant}` becomes the SAR namespace.
- `{id}` becomes the SAR resource name.

The endpoint authorizes `GET /api/v1/tenants/{tenant}/jobs/{id}` as a `get` on
the named `batch.example.io/jobs` resource. Both values come from the request
path and are used to evaluate targeted RBAC.

## Run

Build the image from this checkout and load it into Kind:

```bash
make container CONTAINER_NAME=kube-rbac-proxy:named-path-captures
kind load docker-image kube-rbac-proxy:named-path-captures
```

For another Kubernetes cluster, push this image to a registry and update the
image in `deployment.yaml`.

Apply the example:

```bash
kubectl apply -f deployment.yaml
kubectl rollout status deployment/kube-rbac-proxy -n named-captures
kubectl port-forward -n named-captures service/kube-rbac-proxy 8443:8443
```

In another terminal, create a token for the example client:

```bash
TOKEN="$(kubectl create token -n tenant-a job-reader)"
```

The named resource is allowed:

```bash
curl -k -H "Authorization: Bearer ${TOKEN}" \
  https://127.0.0.1:8443/api/v1/tenants/tenant-a/jobs/job-123
```

The same path with a different resource name is denied by the `resourceNames`
restriction in the Role:

```bash
curl -k -i -H "Authorization: Bearer ${TOKEN}" \
  https://127.0.0.1:8443/api/v1/tenants/tenant-a/jobs/job-999
```
