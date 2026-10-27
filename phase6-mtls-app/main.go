package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	serverSPIFFEID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-server"
	clientSPIFFEID = "spiffe://devsecops.local/ns/devsecops-test/sa/mtls-client"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: app server|client")
	}

	ctx := context.Background()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("Connect to SPIFFE Workload API: %v", err)
	}
	defer source.Close()

	switch os.Args[1] {
	case "server":
		runServer(source)
	case "client":
		runClient(source)
	default:
		log.Fatal("Mode must be server or client")
	}
}

func runServer(source *workloadapi.X509Source) {
	serverID, err := spiffeid.FromString(serverSPIFFEID)
	if err != nil {
		log.Fatal(err)
	}
	clientID, err := spiffeid.FromString(clientSPIFFEID)
	if err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		peerID, err := spiffeid.FromURI(r.TLS.PeerCertificates[0].URIs[0])
		if err != nil || peerID != clientID {
			http.Error(w, "client SPIFFE ID not authorized", http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "mTLS success: authorized client SPIFFE ID", peerID)
	})

	server := &http.Server{
		Addr:              ":8443",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return source.GetX509SVID().TLSConfig()
			},
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  source.GetX509Bundle().X509CertPool(),
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("client certificate missing")
				}
				return nil
			},
		},
	}

	log.Println("mTLS server listening on :8443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func runClient(source *workloadapi.X509Source) {
	_ = source

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				svid, err := source.GetX509SVID()
				if err != nil {
					return nil, err
				}
				cert := svid.Marshal()
				return &cert, nil
			},
			RootCAs: source.GetX509Bundle().X509CertPool(),
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return fmt.Errorf("server certificate missing")
				}
				id, err := spiffeid.FromURI(state.PeerCertificates[0].URIs[0])
				if err != nil {
					return err
				}
				if id.String() != serverSPIFFEID {
					return fmt.Errorf("unexpected server SPIFFE ID: %s", id)
				}
				return nil
			},
		},
	}

	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Get("https://mtls-server:8443/")
	if err != nil {
		log.Fatalf("mTLS request failed: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("Server returned: %s", resp.Status)
}
