import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

from spiffe_credentials import fetch_svid, write_tls_material

SERVER_ID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-server"
AUTHORIZED_CLIENT_ID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-client"
PORT = int(os.getenv("MTLS_PORT", "8443"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.connection.getpeercert()
        uris = [
            value
            for kind, value in peer.get("subjectAltName", ())
            if kind == "URI"
        ]

        if AUTHORIZED_CLIENT_ID not in uris:
            self.send_error(403, "Unauthorized SPIFFE identity")
            return

        body = (
            f"mTLS SUCCESS\n"
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
    svid = fetch_svid(SERVER_ID)
    cert_path, key_path, bundle_path = write_tls_material(svid)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    context.load_verify_locations(cafile=bundle_path)
    context.verify_mode = ssl.CERT_REQUIRED

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"SPIFFE server identity: {svid.spiffe_id}", flush=True)
    print(f"mTLS server listening on port {PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
