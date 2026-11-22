# Kubernetes deployment

Plain manifests, applied with kustomize (built into `kubectl`). CI renders them and validates
the output against the Kubernetes schemas with kubeconform.

```bash
docker build -t ghcr.io/ashin-06/agentwall:latest .   # or push to your own registry
kubectl create namespace agentwall
kubectl -n agentwall create secret generic agentwall-secrets --from-env-file=.env
kubectl apply -k deploy/k8s
kubectl -n agentwall port-forward svc/agentwall 8000:8000
```

The pod runs with `AGENTWALL_ENV=production`, so it refuses to start unless the secret holds a
strong `AGENTWALL_ADMIN_PASSWORD` (16+ chars), `AGENTWALL_JWT_SECRET` and `AGENTWALL_HMAC_KEY`
(32+ chars each), and 32+ char `AGENTWALL_API_KEYS`. Change the image in `kustomization.yaml`.

Limits, by design of the current code:

- One replica with a `Recreate` strategy. The audit log is a single-writer DuckDB file on a
  ReadWriteOnce volume, and session lockdown and rate-limit state live in process memory.
  Scaling out needs the Redis and PostgreSQL backends, which are not wired up here.
- The NetworkPolicy only admits traffic from the same namespace or from namespaces labelled
  `agentwall-client=true`. It has no effect unless your CNI enforces NetworkPolicy.
- No Ingress is included. The dashboard and API share port 8000; put your own TLS-terminating
  Ingress in front if it must be reachable from outside the cluster.
