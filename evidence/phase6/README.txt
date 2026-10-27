Phase 6 evidence capture

- cluster-nodes.txt: Kubernetes node information
- spire-pods.txt: SPIRE component status
- spiffe-registrations.txt and spiffe-registration-details.yaml: workload registration
- mtls-client-success.log and mtls-client-current.log: client-side mTLS test output
- mtls-server.log: server-side request logs
- mtls-server-negative-test.log and unauthenticated-tls-rejection.log: evidence of TLS rejection without an accepted client certificate
- mtls-server-rotation.log and server-svid-metadata-*.txt: SVID rotation and metadata observations
- mtls-workloads-and-service.yaml: deployment and internal service configuration
- workload-pods.txt: workload status
- unauthenticated-test-* files: earlier negative-test attempts and supporting evidence

The successful client test and TLS rejection evidence are separate test cases. Review the corresponding logs when interpreting the results.
