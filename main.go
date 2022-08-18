// Copyright 2016 Mathieu Lonjaret

// program getcert gets an HTTPS certificate from Let's Encrypt
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/acme/autocert"
)

const stagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

var (
	flagHostname = flag.String("hostname", "", "the name you want a cert for")
	flagVerbose  = flag.Bool("v", false, "be verbose")
)

func main() {
	flag.Parse()

	if *flagHostname == "" {
		log.Fatal("-hostname is needed")
	}

	dirCache := filepath.Join(os.Getenv("HOME"), ".cache", "letsencrypt")
	m := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		// TODO(mpl): allow multiple hostnames and/or IPs (i.e. -> SAN)
		HostPolicy: autocert.HostWhitelist(*flagHostname),
		Cache:      autocert.DirCache(dirCache),
	}
	getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if *flagVerbose {
			spew.Dump(hello)
		}
		cert, err := m.GetCertificate(hello)
		if err != nil {
			log.Println(err)
		}
		return cert, err
	}

	tlsConfig := m.TLSConfig()
	tlsConfig.GetCertificate = getCertificate

	ln, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	})
	log.Fatal(http.Serve(ln, nil))
}
