/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ssl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/ingress-nginx/pkg/util/file"
)

// generateRSACerts generates a self signed certificate using a self generated ca
func generateRSACerts(host string) (newCert, newCa *keyPair, err error) {
	ca, err := newCA("self-sign-ca")
	if err != nil {
		return nil, nil, err
	}

	key, err := newPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a server private key: %v", err)
	}

	config := certutil.Config{
		CommonName: host,
		Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	cert, err := newSignedCert(&config, key, ca.Cert, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to sign the server certificate: %v", err)
	}

	return &keyPair{
		Key:  key,
		Cert: cert,
	}, ca, nil
}

func TestStoreSSLCertOnDisk(t *testing.T) {
	cert, _, err := generateRSACerts("echoheaders")
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	name := fmt.Sprintf("test-%v", time.Now().UnixNano())

	c := encodeCertPEM(cert.Cert)
	k := encodePrivateKeyPEM(cert.Key)

	sslCert, err := CreateSSLCert(c, k, FakeSSLCertificateUID)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	_, err = StoreSSLCertOnDisk(name, sslCert)
	if err != nil {
		t.Fatalf("unexpected error storing SSL certificate: %v", err)
	}

	if sslCert.PemCertKey == "" {
		t.Fatalf("expected a pem certificate returned empty")
	}

	if len(sslCert.CN) == 0 {
		t.Fatalf("expected at least one cname but none returned")
	}

	if sslCert.CN[0] != "echoheaders" {
		t.Fatalf("expected cname echoheaders but %v returned", sslCert.CN[0])
	}
}

func TestCACert(t *testing.T) {
	cert, CA, err := generateRSACerts("echoheaders")
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	name := fmt.Sprintf("test-%v", time.Now().UnixNano())

	c := encodeCertPEM(cert.Cert)
	k := encodePrivateKeyPEM(cert.Key)
	ca := encodeCertPEM(CA.Cert)

	sslCert, err := CreateSSLCert(c, k, FakeSSLCertificateUID)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	path, err := StoreSSLCertOnDisk(name, sslCert)
	if err != nil {
		t.Fatalf("unexpected error storing SSL certificate: %v", err)
	}

	sslCert.CAFileName = path

	err = ConfigureCACertWithCertAndKey(name, ca, sslCert)
	if err != nil {
		t.Fatalf("unexpected error configuring CA certificate: %v", err)
	}

	if sslCert.CAFileName == "" {
		t.Fatalf("expected a valid CA file name")
	}
}

func TestGetFakeSSLCert(t *testing.T) {
	sslCert := GetFakeSSLCert()

	if sslCert.PemCertKey == "" {
		t.Fatalf("expected PemCertKey to not be empty")
	}

	if sslCert.PemFileName == "" {
		t.Fatalf("expected PemFileName to not be empty")
	}

	if len(sslCert.CN) != 2 {
		t.Fatalf("expected 2 entries in CN, but got %v", len(sslCert.CN))
	}

	if sslCert.CN[0] != "Kubernetes Ingress Controller Fake Certificate" {
		t.Fatalf("expected common name to be \"Kubernetes Ingress Controller Fake Certificate\" but got %v", sslCert.CN[0])
	}

	if sslCert.CN[1] != "ingress.local" {
		t.Fatalf("expected a DNS name \"ingress.local\" but got: %v", sslCert.CN[1])
	}
}

func TestConfigureCACert(t *testing.T) {
	cn := "demo-ca"
	_, ca, err := generateRSACerts(cn)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	c := encodeCertPEM(ca.Cert)

	sslCert, err := CreateCACert(c)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	if sslCert.CAFileName != "" {
		t.Fatalf("expected CAFileName to be empty")
	}
	if sslCert.CACertificate == nil {
		t.Fatalf("expected Certificate to be set")
	}

	err = ConfigureCACert(cn, c, sslCert)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	caFilename := fmt.Sprintf("%v/ca-%v.pem", file.DefaultSSLDirectory, cn)

	if sslCert.CAFileName != caFilename {
		t.Fatalf("expected a valid CA file name")
	}
}

func TestConfigureCRL(t *testing.T) {
	// Demo CRL from https://csrc.nist.gov/projects/pki-testing/sample-certificates-and-crls
	// Converted to PEM to be tested
	// SHA: ef21f9c97ec2ef84ba3b2ab007c858a6f760d813
	crl := []byte(`-----BEGIN X509 CRL-----
MIIBYDCBygIBATANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQBGRYDY29t
MRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQRcN
MDUwMjA1MTIwMDAwWhcNMDUwMjA2MTIwMDAwWjAiMCACARIXDTA0MTExOTE1NTcw
M1owDDAKBgNVHRUEAwoBAaAvMC0wHwYDVR0jBBgwFoAUCGivhTPIOUp6+IKTjnBq
SiCELDIwCgYDVR0UBAMCAQwwDQYJKoZIhvcNAQEFBQADgYEAItwYffcIzsx10NBq
m60Q9HYjtIFutW2+DvsVFGzIF20f7pAXom9g5L2qjFXejoRvkvifEBInr0rUL4Xi
NkR9qqNMJTgV/wD9Pn7uPSYS69jnK2LiK8NGgO94gtEVxtCccmrLznrtZ5mLbnCB
fUNCdMGmr8FVF6IzTNYGmCuk/C4=
-----END X509 CRL-----`)

	cn := "demo-crl"
	_, ca, err := generateRSACerts(cn)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	c := encodeCertPEM(ca.Cert)

	sslCert, err := CreateCACert(c)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	if sslCert.CRLFileName != "" {
		t.Fatalf("expected CRLFileName to be empty")
	}
	if sslCert.CACertificate == nil {
		t.Fatalf("expected Certificate to be set")
	}

	err = ConfigureCRL(cn, crl, sslCert)
	if err != nil {
		t.Fatalf("unexpected error creating CRL file: %v", err)
	}

	crlFilename := fmt.Sprintf("%v/crl-%v.pem", file.DefaultSSLDirectory, cn)
	if sslCert.CRLFileName != crlFilename {
		t.Fatalf("expected a valid CRL file name")
	}
	if sslCert.CRLSHA != "ef21f9c97ec2ef84ba3b2ab007c858a6f760d813" {
		t.Fatalf("the expected CRL SHA wasn't found")
	}
}

func TestCreateSSLCert(t *testing.T) {
	cert, _, err := generateRSACerts("echoheaders")
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	c := encodeCertPEM(cert.Cert)
	k := encodePrivateKeyPEM(cert.Key)

	sslCert, err := CreateSSLCert(c, k, FakeSSLCertificateUID)
	if err != nil {
		t.Fatalf("unexpected error checking SSL certificate: %v", err)
	}

	var certKeyBuf bytes.Buffer
	certKeyBuf.Write(c)
	certKeyBuf.Write([]byte("\n"))
	certKeyBuf.Write(k)

	if sslCert.PemCertKey != certKeyBuf.String() {
		t.Fatalf("expected concatenated PEM cert and key but returned %v", sslCert.PemCertKey)
	}

	if len(sslCert.CN) == 0 {
		t.Fatalf("expected at least one CN but none returned")
	}

	if sslCert.CN[0] != "echoheaders" {
		t.Fatalf("expected cname echoheaders but %v returned", sslCert.CN[0])
	}
}

type keyPair struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

func newCA(name string) (*keyPair, error) {
	key, err := newPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to create a private key for a new CA: %v", err)
	}
	config := certutil.Config{
		CommonName: name,
	}
	cert, err := certutil.NewSelfSignedCACert(config, key)
	if err != nil {
		return nil, fmt.Errorf("unable to create a self-signed certificate for a new CA: %v", err)
	}
	return &keyPair{
		Key:  key,
		Cert: cert,
	}, nil
}

func TestIsValidHostname(t *testing.T) {
	cases := map[string]struct {
		Hostname string
		CN       []string
		Valid    bool
	}{
		"when there is no common names": {
			"foo.bar",
			[]string{},
			false,
		},
		"when there is a match for foo.bar": {
			"foo.bar",
			[]string{"foo.bar"},
			true,
		},
		"when there is a wildcard match for foo.bar": {
			"foo.bar",
			[]string{"*.bar"},
			true,
		},
		"when there is a wrong wildcard for *.bar": {
			"invalid.foo.bar",
			[]string{"*.bar"},
			false,
		},
	}

	for k, tc := range cases {
		valid := IsValidHostname(tc.Hostname, tc.CN)
		if valid != tc.Valid {
			t.Errorf("%s: expected '%v' but returned %v", k, tc.Valid, valid)
		}
	}
}

const (
	duration365d = time.Hour * 24 * 365
	rsaKeySize   = 2048
)

// newPrivateKey creates an RSA private key
func newPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeySize)
}

// newSignedCert creates a signed certificate using the given CA certificate and key
func newSignedCert(cfg *certutil.Config, key crypto.Signer, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	if cfg.CommonName == "" {
		return nil, errors.New("must specify a CommonName")
	}
	if len(cfg.Usages) == 0 {
		return nil, errors.New("must specify at least one ExtKeyUsage")
	}

	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(duration365d).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  cfg.Usages,
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

// encodePrivateKeyPEM returns PEM-encoded private key data
func encodePrivateKeyPEM(key *rsa.PrivateKey) []byte {
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(&block)
}

// encodeCertPEM returns PEM-encoded certificate data
func encodeCertPEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  certutil.CertificateBlockType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

func newFakeCertificate(t *testing.T) (sslCert []byte, certFileName, keyFileName string) {
	cert, key := getFakeHostSSLCert("localhost")

	certFile, err := os.CreateTemp("", "crt-")
	if err != nil {
		t.Errorf("failed to write test key: %v", err)
	}

	if _, err := certFile.Write(cert); err != nil {
		t.Errorf("failed to write cert: %v", err)
	}
	defer certFile.Close()

	keyFile, err := os.CreateTemp("", "key-")
	if err != nil {
		t.Errorf("failed to write test key: %v", err)
	}

	if _, err := keyFile.Write(key); err != nil {
		t.Errorf("failed to write key: %v", err)
	}
	defer keyFile.Close()

	return cert, certFile.Name(), keyFile.Name()
}

func dialTestServer(port string, rootCertificates ...[]byte) error {
	roots := x509.NewCertPool()
	for _, cert := range rootCertificates {
		ok := roots.AppendCertsFromPEM(cert)
		if !ok {
			return fmt.Errorf("failed to add root certificate")
		}
	}
	resp, err := tls.Dial("tcp", "localhost:"+port, &tls.Config{ //nolint:gosec // Ignore the gosec error in testing
		RootCAs: roots,
	})
	if err != nil {
		return err
	}
	if resp.Handshake() != nil {
		return fmt.Errorf("TLS handshake should succeed: %v", err)
	}
	return nil
}

func TestTLSKeyReloader(t *testing.T) {
	cert, certFile, keyFile := newFakeCertificate(t)

	watcher := TLSListener{
		certificatePath: certFile,
		keyPath:         keyFile,
		lock:            sync.Mutex{},
	}
	watcher.load()

	s := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	s.Config.TLSConfig = watcher.TLSConfig()
	s.Listener = tls.NewListener(s.Listener, s.Config.TLSConfig)
	go s.Start()
	defer s.Close()
	port := strings.Split(s.Listener.Addr().String(), ":")[1]

	t.Run("without the trusted certificate", func(t *testing.T) {
		if dialTestServer(port) == nil {
			t.Errorf("TLS dial should fail")
		}
	})

	t.Run("with the certificate trustes as root certificate", func(t *testing.T) {
		if err := dialTestServer(port, cert); err != nil {
			t.Errorf("TLS dial should succeed, got error: %v", err)
		}
	})

	t.Run("with a new certificate", func(t *testing.T) {
		cert, certFile, keyFile = newFakeCertificate(t)
		t.Run("when the certificate is not reloaded", func(t *testing.T) {
			if dialTestServer(port, cert) == nil {
				t.Errorf("TLS dial should fail")
			}
		})

		/*TODO: fix
		// simulate watch.NewFileWatcher to call the load function
		watcher.load()
		t.Run("when the certificate is reloaded", func(t *testing.T) {
			if err := dialTestServer(port, cert); err != nil {
				t.Errorf("TLS dial should succeed, got error: %v", err)
			}
		})
		*/
	})
}

func newTestCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSListenerWithClientCA(t *testing.T) {
	serverCert, certFile, keyFile := newFakeCertificate(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	ca, caKey, caPEM := newTestCA(t, "webhook-client-ca")
	clientCAFile, err := os.CreateTemp("", "client-ca-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(clientCAFile.Name())
	if _, err := clientCAFile.Write(caPEM); err != nil {
		t.Fatal(err)
	}
	clientCAFile.Close()

	listener := TLSListener{certificatePath: certFile, keyPath: keyFile, clientCAPath: clientCAFile.Name()}
	listener.load()
	listener.loadClientCA()

	cfg := listener.TLSConfig()
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected ClientAuth RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}

	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	s.Config.TLSConfig = cfg
	s.Listener = tls.NewListener(s.Listener, cfg)
	go s.Start()
	defer s.Close()
	url := "https://localhost:" + strings.Split(s.Listener.Addr().String(), ":")[1]

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(serverCert)
	post := func(clientCerts ...tls.Certificate) error {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			Certificates: clientCerts,
			MinVersion:   tls.VersionTLS12,
		}}}
		resp, err := client.Post(url, "application/json", strings.NewReader("{}"))
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		return nil
	}

	t.Run("without a client certificate", func(t *testing.T) {
		if post() == nil {
			t.Errorf("request without a client certificate should be rejected")
		}
	})

	t.Run("with a client certificate from an untrusted CA", func(t *testing.T) {
		otherCA, otherKey, _ := newTestCA(t, "attacker-ca")
		if post(newTestClientCert(t, otherCA, otherKey, "kube-apiserver")) == nil {
			t.Errorf("request with an untrusted client certificate should be rejected")
		}
	})

	t.Run("with a client certificate signed by the client CA", func(t *testing.T) {
		if err := post(newTestClientCert(t, ca, caKey, "kube-apiserver")); err != nil {
			t.Errorf("request with a trusted client certificate should succeed: %v", err)
		}
	})

	t.Run("when the client CA cannot be loaded", func(t *testing.T) {
		if err := os.WriteFile(clientCAFile.Name(), []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		listener.loadClientCA()
		if post(newTestClientCert(t, ca, caKey, "kube-apiserver")) == nil {
			t.Errorf("requests should be rejected while the client CA is invalid")
		}
	})
}

func TestTLSListenerClientCAAddedAfterStartup(t *testing.T) {
	dir := t.TempDir()
	clientCAPath := dir + "/ca.crt"
	_, _, caPEM := newTestCA(t, "webhook-client-ca")

	listener := &TLSListener{clientCAPath: clientCAPath}
	listener.loadClientCA()
	if _, err := listener.getConfigForClient(nil); err == nil {
		t.Fatalf("expected handshakes to be rejected while the client CA is missing")
	}

	go listener.watchClientCAWhenAvailable(10 * time.Millisecond)
	if err := os.WriteFile(clientCAPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		cfg, err := listener.getConfigForClient(nil)
		if err == nil {
			if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil {
				t.Fatalf("unexpected TLS config %+v", cfg)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("client CA added after startup was not loaded: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
