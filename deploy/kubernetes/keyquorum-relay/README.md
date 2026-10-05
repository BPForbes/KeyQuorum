# keyquorum-relay Helm chart

Deploys the hosted KeyQuorum relay as stateless replicas behind a
TLS-terminating ingress, with every piece of relay state in a MongoDB
replica set. The chart renders no credential: the relay private key and the
MongoDB connection string are read from Secrets (or a Secrets Store CSI
volume) the operator provides, and the provider certificate and revocation
list from a ConfigMap.

The runbook, including how the secrets are produced and where the offline
provider root stays, is `docs/operator/relay-deployment.md` in this
repository.

```sh
helm lint deploy/kubernetes/keyquorum-relay
helm template relay deploy/kubernetes/keyquorum-relay --namespace keyquorum
helm upgrade --install relay deploy/kubernetes/keyquorum-relay \
  --namespace keyquorum --create-namespace \
  --set ingress.host=relay.example.com \
  --set image.digest=sha256:...
```
