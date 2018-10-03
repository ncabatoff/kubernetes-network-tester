# kubernetes-network-tester
Tests Kubernetes pod-to-pod network connectivity using Prometheus and blackbox-exporter.

## Usage
Download from the [Releases][release] page, then run:

```
./kubernetes-network-tester \
  -numhosts 3
  -resolver $(kubectl get svc -n kube-system kube-dns -o jsonpath='{.spec.clusterIP}'):53 \
  checksvc1 checksvc2 checksvc3
```

This will create daemonsets and services named checksvc2, checksvc2, and
checksvc3. It will also create a Prometheus deployment and service named
'prometheus'.

The Prometheus configuration is designed to have every checksvc pod query
every checksvc pod. kubernetes-network-tester will exit with an error if it
can't validate every pod-to-pod connection via Prometheus before it times
out.