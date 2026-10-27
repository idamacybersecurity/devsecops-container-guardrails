import os
import tempfile

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from spiffe import workloadapi_pb2, workloadapi_pb2_grpc

SOCKET_PATH = os.getenv(
    "SPIFFE_ENDPOINT_SOCKET",
    "unix:///spiffe-workload-api/api.sock",
)


def split_der_certificates(data):
    """Split concatenated DER-encoded X.509 certificates."""
    certificates = []
    offset = 0

    while offset < len(data):
        if data[offset] != 0x30:
            raise ValueError("Invalid DER certificate sequence")

        first_length = data[offset + 1]
        if first_length < 0x80:
            content_length = first_length
            header_length = 2
        else:
            length_bytes = first_length & 0x7F
            if length_bytes == 0 or length_bytes > 4:
                raise ValueError("Invalid DER length")
            header_length = 2 + length_bytes
            content_length = int.from_bytes(
                data[offset + 2:offset + header_length], "big"
            )

        total_length = header_length + content_length
        end = offset + total_length
        if end > len(data):
            raise ValueError("Truncated DER certificate")

        certificates.append(data[offset:end])
        offset = end

    return certificates


def fetch_svid(expected_spiffe_id):
    channel = grpc.insecure_channel(SOCKET_PATH)
    try:
        stub = workloadapi_pb2_grpc.SpiffeWorkloadAPIStub(channel)
        responses = stub.FetchX509SVID(
            workloadapi_pb2.X509SVIDRequest(), metadata=(("workload.spiffe.io", "true"),), timeout=10
        )
        response = next(iter(responses), None)

        if response is None:
            raise RuntimeError("SPIRE returned no SVID response")

        for svid in response.svids:
            if svid.spiffe_id == expected_spiffe_id:
                return svid

        found = [s.spiffe_id for s in response.svids]
        raise RuntimeError(
            f"Expected SPIFFE ID {expected_spiffe_id!r}; received {found}"
        )
    finally:
        channel.close()


def write_tls_material(svid):
    directory = tempfile.mkdtemp(prefix="spiffe-tls-")
    cert_path = os.path.join(directory, "identity-chain.pem")
    key_path = os.path.join(directory, "identity-key.pem")
    bundle_path = os.path.join(directory, "trust-bundle.pem")

    with open(cert_path, "wb") as cert_file:
        for der in split_der_certificates(svid.x509_svid):
            cert = x509.load_der_x509_certificate(der)
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    private_key = serialization.load_der_private_key(
        svid.x509_svid_key, password=None
    )
    with open(key_path, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)

    with open(bundle_path, "wb") as bundle_file:
        for der in split_der_certificates(svid.bundle):
            cert = x509.load_der_x509_certificate(der)
            bundle_file.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path, bundle_path
