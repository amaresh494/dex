package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"os"
	"strings"

	"github.com/dexidp/dex/api/v2"
)

func newDexClient(hostAndPort, caPath, clientCrt, clientKey string) (api.DexClient, error) {
	cPool := x509.NewCertPool()
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("invalid CA crt file: %s", caPath)
	}
	if cPool.AppendCertsFromPEM(caCert) != true {
		return nil, fmt.Errorf("failed to parse CA crt")
	}

	clientCert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client crt file: %s", caPath)
	}

	clientTLSConfig := &tls.Config{
		RootCAs:      cPool,
		Certificates: []tls.Certificate{clientCert},
	}
	creds := credentials.NewTLS(clientTLSConfig)

	conn, err := grpc.Dial(hostAndPort, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial: %v", err)
	}
	return api.NewDexClient(conn), nil
}

func main() {
	host := flag.String("host", "", "Host with Port")
	caCrt := flag.String("ca-crt", "", "CA certificate")
	clientCrt := flag.String("client-crt", "", "Client certificate")
	clientKey := flag.String("client-key", "", "Client key")
	clientId := flag.String("client-id", "", "Client ID")
	clientName := flag.String("client-name", "", "Client Name")
	clientSecret := flag.String("client-secret", "", "Client Secret")
	redirectURIs := flag.String("redirect-uris", "", "Redirect URIs")
	remove := flag.Bool("remove", false, "Remove client")
	flag.Parse()

	usage := "(Usage: --host=<host:port> --ca-crt=<ca-cert-path> --client-crt=<path client.crt> --client-key=<path client key>" +
		" --client-id=<client-id> --client-name=<client-name> --client-secret=<client-secret> " +
		"--redirect-uris=<comma separated uris> --delete=<delete flag>)"

	if *host == "" {
		log.Fatal("Please provide Host with Port. " + usage)
	}

	if *caCrt == "" {
		log.Fatal("Please provide CA certificate. " + usage)
	}

	if *clientCrt == "" {
		log.Fatal("Please provide Client certificate. " + usage)
	}

	if *clientKey == "" {
		log.Fatal("Please provide Client key. " + usage)
	}

	if *clientId == "" {
		log.Fatal("Please provide Client ID. " + usage)
	}

	client, err := newDexClient(*host, *caCrt, *clientCrt, *clientKey)
	if err != nil {
		log.Fatalf("failed creating dex client: %v ", err)
	}

	if !*remove {
		if *clientName == "" {
			log.Fatal("Please provide Client Name. " + usage)
		}

		if *clientSecret == "" {
			log.Fatal("Please provide Client Secret. " + usage)
		}

		if *redirectURIs == "" {
			log.Fatal("Please provide Client Secret. " + usage)
		}
		redirectUriList := strings.Split(*redirectURIs, ",")

		req := &api.CreateClientReq{
			Client: &api.Client{
				Id:           *clientId,
				Name:         *clientName,
				Secret:       *clientSecret,
				RedirectUris: redirectUriList,
			},
		}

		if _, err := client.CreateClient(context.TODO(), req); err != nil {
			log.Fatalf("failed creating oauth2 client: %v", err)
		}
	} else {
		req := &api.DeleteClientReq{
			Id: *clientId,
		}

		if _, err := client.DeleteClient(context.TODO(), req); err != nil {
			log.Fatalf("failed deleting oauth2 client: %v", err)
		}
	}
}
