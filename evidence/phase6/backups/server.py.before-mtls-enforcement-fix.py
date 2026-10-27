import os
import ssl
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from spiffe import workloadapi_pb2, workloadapi_pb2_grpc
from spiffe_credentials import split_der_certificates, write_tls_material

SERVER_ID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-server"
AUTHORIZED_CLIENT_ID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-client"
SOCKET_PATH = os.getenv(
    "SPIFFE_ENDPOINT_SOCKET", "unix:///spiffe-workload-api/api.sock"
)
PORT = int(os.getenv("MTLS_PORT", "8443"))

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.verify_mode = ssl.CERT_REQUIRED
reload_lock = threading.Lock()


def install_svid(svid, initial=False):
    if svid.spiffe_id != SERVER_ID:
        return

    cert_path, key_path, bundle_path = write_tls_material(svid)
    leaf = x509.load_der_x509_certificate(
        split_der_certificates(svid.x509_svid)[0]
    )

    with reload_lock:
        context.load_verify_locations(cafile=bundle_path)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        # Reassert mandatory client-certificate verification after SVID updates.
        context.verify_mode = ssl.CERT_REQUIRED

    print(
        "SVID_INSTALLED",
        "initial" if initial else "rotated",
        "serial=" + format(leaf.serial_number, "x"),
        "fingerprint=" + leaf.fingerprint(hashes.SHA256()).hex(),
        "not_after=" + leaf.not_valid_after_utc.isoformat(),
        "at=" + datetime.now(timezone.utc).isoformat(),
        flush=True,
    )


def watch_svid_updates():
    while True:
        channel = grpc.insecure_channel(SOCKET_PATH)
        try:
            stub = workloadapi_pb2_grpc.SpiffeWorkloadAPIStub(channel)
            stream = stub.FetchX509SVID(
                workloadapi_pb2.X509SVIDRequest(),
                metadata=(("workload.spiffe.io", "true"),),
            )
            for response in stream:
                for svid in response.svids:
                    if svid.spiffe_id == SERVER_ID:
                        install_svid(svid)
        except Exception as exc:
            print("SVID_STREAM_RECONNECT", repr(exc), flush=True)
        finally:
            channel.close()
        time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.connection.getpeercert()
        uris = [
            value for kind, value in peer.get("subjectAltName", ())
            if kind == "URI"
        ]

        if AUTHORIZED_CLIENT_ID not in uris:
            self.send_error(403, "Unauthorized SPIFFE identity")
            return

        body = (
            "mTLS SUCCESS\n"
            f"server_identity={SERVER_ID}\n"
            f"client_identity={AUTHORIZED_CLIENT_ID}\n"
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("HTTP:", fmt % args, flush=True)


def main():
    channel = grpc.insecure_channel(SOCKET_PATH)
    try:
        stub = workloadapi_pb2_grpc.SpiffeWorkloadAPIStub(channel)
        stream = stub.FetchX509SVID(
            workloadapi_pb2.X509SVIDRequest(),
            metadata=(("workload.spiffe.io", "true"),),
        )
        first_response = next(iter(stream), None)
        if first_response is None:
            raise RuntimeError("SPIRE returned no initial SVID")

        initial = next(
            (s for s in first_response.svids if s.spiffe_id == SERVER_ID),
            None,
        )
        if initial is None:
            raise RuntimeError(f"SPIRE did not return {SERVER_ID}")

        install_svid(initial, initial=True)
    finally:
        channel.close()

    # Keep a separate long-lived stream for future SVID updates.
    threading.Thread(target=watch_svid_updates, daemon=True).start()

    # Enforce client certificates on the actual listening TLS context.
    context.verify_mode = ssl.CERT_REQUIRED
    print(f"TLS client certificate verification mode: {context.verify_mode}", flush=True)

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"SPIFFE server identity: {SERVER_ID}", flush=True)
    print(f"mTLS server listening on port {PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
