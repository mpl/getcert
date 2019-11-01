// Copyright 2016 Mathieu Lonjaret

// program getcert gets an HTTPS certificate from Let's Encrypt
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
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
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*flagHostname),
		// HostPolicy: func(ctx context.Context, host string) error { return nil },
		Cache: autocert.DirCache(dirCache),
	}
	getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if *flagVerbose {
			spew.Dump(hello)
		}
		return m.GetCertificate(hello)
	}

	//	tlsConfig := m.TLSConfig()
	//	tlsConfig.GetCertificate = getCertificate

	tlsConfig := &tls.Config{
		Rand: rand.Reader,
		Time: time.Now,
		// NextProtos: []string{http2.NextProtoTLS, "http/1.1", "acme-tls/1"},
		NextProtos: []string{http2.NextProtoTLS, "http/1.1", acme.ALPNProto},
		//	   		MinVersion: tls.VersionTLS12,
		GetCertificate: getCertificate,
	}

	ln, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	})
	log.Fatal(http.Serve(ln, nil))
}

// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func dolego() {

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: "mathieu.lonjaret@gmail.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	// config.CADirURL = stagingURL
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "443"))
	if err != nil {
		log.Fatal(err)
	}

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{*flagHostname},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)
}
