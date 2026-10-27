import os
import socket
import ssl

from spiffe_credentials import fetch_svid, write_tls_material

CLIENT_ID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-client"
SERVER_ID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-server"
SERVER_HOST = os.getenv("MTLS_SERVER_HOST", "mtls-server")
SERVER_PORT = int(os.getenv("MTLS_SERVER_PORT", "8443"))


def main():
    svid = fetch_svid(CLIENT_ID)
    cert_path, key_path, bundle_path = write_tls_material(svid)

    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=bundle_path
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=SERVER_HOST) as connection:
            peer = connection.getpeercert()
            uris = [
                value
                for kind, value in peer.get("subjectAltName", ())
                if kind == "URI"
            ]

            if SERVER_ID not in uris:
                raise RuntimeError(
                    f"Server SPIFFE identity mismatch: expected {SERVER_ID}; "
                    f"received {uris}"
                )

            connection.sendall(
                b"GET / HTTP/1.1\r\n"
                + f"Host: {SERVER_HOST}\r\n".encode()
                + b"Connection: close\r\n\r\n"
            )

            chunks = []
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                chunks.append(data)

    response = b"".join(chunks).decode("utf-8", errors="replace")
    print(f"Client SPIFFE identity: {svid.spiffe_id}")
    print(f"Verified server SPIFFE identity: {SERVER_ID}")
    print(response)


if __name__ == "__main__":
    main()
