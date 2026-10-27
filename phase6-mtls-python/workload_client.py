import os
import grpc

from spiffe import workloadapi_pb2, workloadapi_pb2_grpc

SOCKET_PATH = os.getenv(
    "SPIFFE_ENDPOINT_SOCKET",
    "unix:///spiffe-workload-api/api.sock",
)


def fetch_svid():
    channel = grpc.insecure_channel(SOCKET_PATH)
    try:
        stub = workloadapi_pb2_grpc.SpiffeWorkloadAPIStub(channel)
        responses = stub.FetchX509SVID(
            workloadapi_pb2.X509SVIDRequest(),
            timeout=10,
        )

        response = next(iter(responses), None)
        if response is None or not response.svids:
            raise RuntimeError("SPIRE returned no X.509 SVIDs")

        for svid in response.svids:
            print(f"SPIFFE ID: {svid.spiffe_id}")
            print(f"Certificate chain bytes: {len(svid.x509_svid)}")
            print(f"Private key bytes: {len(svid.x509_svid_key)}")
            print(f"Trust bundle bytes: {len(svid.bundle)}")

        return response.svids
    finally:
        channel.close()


if __name__ == "__main__":
    fetch_svid()
