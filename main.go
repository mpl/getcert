// Copyright 2016 Mathieu Lonjaret

// program getcert gets an HTTPS certificate from Let's Encrypt
package main

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

var flagHostname = flag.String("hostname", "", "the name you want a cert for")

func main() {
	flag.Parse()

	if *flagHostname == "" {
		log.Fatal("-hostname is needed")
	}
	dirCache := filepath.Join(os.Getenv("HOME"), ".cache", "letsencrypt")
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*flagHostname),
		Cache:      autocert.DirCache(dirCache),
	}
	ln, err := tls.Listen("tcp", ":443", &tls.Config{
		Rand:           rand.Reader,
		Time:           time.Now,
		NextProtos:     []string{http2.NextProtoTLS, "http/1.1"},
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
	})
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	})
	log.Fatal(http.Serve(ln, nil))
}
