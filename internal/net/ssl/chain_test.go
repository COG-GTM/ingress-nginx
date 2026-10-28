/*
Copyright 2025 The Kubernetes Authors.

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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var testSerial atomic.Int64

// issueTestCert creates a certificate for key, named subject, signed by signerKey as issuer.
func issueTestCert(t *testing.T, subject, issuer string, key *ecdsa.PrivateKey, signerKey crypto.Signer, isCA bool, aia ...string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(testSerial.Add(1)),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		IssuingCertificateURL: aia,
		DNSNames:              []string{subject},
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	parent := &x509.Certificate{Subject: pkix.Name{CommonName: issuer}}
	if subject == issuer {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func allowLoopbackForTest(t *testing.T) {
	t.Helper()
	prev := allowIssuerAddr
	allowIssuerAddr = func(ip netip.Addr) bool { return ip.Unmap().IsLoopback() || isPublicAddr(ip) }
	t.Cleanup(func() { allowIssuerAddr = prev })
}

// countingServer serves the given paths and counts every request it receives.
func countingServer(t *testing.T, handlers map[string]http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if h, ok := handlers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func writeBody(w http.ResponseWriter, body []byte) {
	if _, err := w.Write(body); err != nil {
		panic(err)
	}
}

func serveDER(c **x509.Certificate) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		writeBody(w, (*c).Raw)
	}
}

func TestIsPublicAddr(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":                true,
		"2606:4700:4700::1111":   true,
		"127.0.0.1":              false,
		"10.0.0.1":               false,
		"172.16.5.4":             false,
		"192.168.1.1":            false,
		"169.254.169.254":        false,
		"100.100.100.200":        false,
		"0.0.0.0":                false,
		"255.255.255.255":        false,
		"224.0.0.1":              false,
		"::1":                    false,
		"::":                     false,
		"fe80::1":                false,
		"fd00:ec2::254":          false,
		"::ffff:169.254.169.254": false,
		"::ffff:127.0.0.1":       false,
		"64:ff9b::a9fe:a9fe":     false,
	}
	for in, want := range cases {
		if got := isPublicAddr(netip.MustParseAddr(in)); got != want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestValidateIssuerURL(t *testing.T) {
	cases := map[string]bool{
		"http://crt.example.com/ca.crt":                  true,
		"https://crt.example.com/ca.crt":                 true,
		"http://8.8.8.8/ca.crt":                          true,
		"file:///etc/passwd":                             false,
		"ftp://crt.example.com/ca.crt":                   false,
		"gopher://crt.example.com/":                      false,
		"ldap://ldap.example.com/cn=ca":                  false,
		"http:///ca.crt":                                 false,
		"http://user:pass@crt.example.com/ca.crt":        false,
		"http://169.254.169.254/latest/meta-data/":       false,
		"http://127.0.0.1:10254/metrics":                 false,
		"http://[::1]/":                                  false,
		"http://[::ffff:169.254.169.254]/":               false,
		"http://10.96.0.1/api":                           false,
		"http://[fd00:ec2::254]/latest/meta-data/":       false,
		"http://kubernetes.default.svc/api/v1/namespace": true, // hostnames are checked at dial time
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		err = validateIssuerURL(u)
		if want && err != nil {
			t.Errorf("validateIssuerURL(%q) unexpected error: %v", in, err)
		}
		if !want && !errors.Is(err, errIssuerURLNotAllowed) {
			t.Errorf("validateIssuerURL(%q) = %v, want errIssuerURLNotAllowed", in, err)
		}
	}
}

func TestFullChainCertRejectsInternalIssuerURLs(t *testing.T) {
	var issuer *x509.Certificate
	srv, hits := countingServer(t, map[string]http.HandlerFunc{"/ca.crt": serveDER(&issuer)})
	caKey := newTestKey(t)
	issuer = issueTestCert(t, "Tenant CA", "Tenant CA", caKey, caKey, true)
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]

	for _, aia := range []string{
		srv.URL + "/ca.crt",                         // 127.0.0.1 literal
		"http://localhost:" + port + "/ca.crt",      // hostname resolving to loopback, rejected at dial time
		"http://169.254.169.254/latest/meta-data/",  // cloud metadata
		"http://[::ffff:127.0.0.1]:" + port + "/ca", // IPv4-mapped loopback
		"file:///etc/passwd",
	} {
		t.Run(aia, func(t *testing.T) {
			leaf := issueTestCert(t, "tenant.example.com", "Tenant CA", newTestKey(t), caKey, false, aia)
			out, err := fullChainCert(pemOf(leaf))
			if !errors.Is(err, errIssuerURLNotAllowed) {
				t.Fatalf("expected errIssuerURLNotAllowed, got out=%d bytes err=%v", len(out), err)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("expected no requests to the internal server, got %d", n)
	}
}

func TestFullChainCertFetchesIntermediate(t *testing.T) {
	allowLoopbackForTest(t)

	var intermediate *x509.Certificate
	srv, hits := countingServer(t, map[string]http.HandlerFunc{"/intermediate.crt": serveDER(&intermediate)})

	rootKey, intKey := newTestKey(t), newTestKey(t)
	issueTestCert(t, "Test Root", "Test Root", rootKey, rootKey, true)
	intermediate = issueTestCert(t, "Test Intermediate", "Test Root", intKey, rootKey, true)
	leaf := issueTestCert(t, "app.example.com", "Test Intermediate", newTestKey(t), intKey, false, srv.URL+"/intermediate.crt")

	out, err := fullChainCert(pemOf(leaf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := append(pemOf(leaf), pemOf(intermediate)...)
	if !bytes.Equal(bytes.TrimSpace(out), bytes.TrimSpace(want)) {
		t.Fatalf("unexpected chain:\n%s", out)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("expected 1 request, got %d", n)
	}
}

func TestFullChainCertRejectsBadIssuerResponses(t *testing.T) {
	allowLoopbackForTest(t)

	caKey := newTestKey(t)
	unrelatedKey := newTestKey(t)
	unrelated := issueTestCert(t, "Unrelated CA", "Unrelated CA", unrelatedKey, unrelatedKey, true)

	srv, _ := countingServer(t, map[string]http.HandlerFunc{
		"/big": func(w http.ResponseWriter, _ *http.Request) {
			writeBody(w, bytes.Repeat([]byte("A"), maxIssuerCertSize+1))
		},
		"/status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"/unrelated": serveDER(&unrelated),
		"/redirect-metadata": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		},
		"/redirect-file": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		},
	})

	for path, wantNotAllowed := range map[string]bool{
		"/big":               false,
		"/status":            false,
		"/unrelated":         false,
		"/redirect-metadata": true,
		"/redirect-file":     true,
	} {
		t.Run(path, func(t *testing.T) {
			leaf := issueTestCert(t, "tenant.example.com", "Tenant CA", newTestKey(t), caKey, false, srv.URL+path)
			_, err := fullChainCert(pemOf(leaf))
			if err == nil {
				t.Fatal("expected an error")
			}
			if wantNotAllowed != errors.Is(err, errIssuerURLNotAllowed) {
				t.Fatalf("errIssuerURLNotAllowed=%v expected, got %v", wantNotAllowed, err)
			}
		})
	}
}

func TestFullChainCertBoundsHops(t *testing.T) {
	allowLoopbackForTest(t)

	t.Run("loop", func(t *testing.T) {
		var a, b *x509.Certificate
		srv, hits := countingServer(t, map[string]http.HandlerFunc{"/a": serveDER(&a), "/b": serveDER(&b)})
		keyA, keyB := newTestKey(t), newTestKey(t)
		a = issueTestCert(t, "CA A", "CA B", keyA, keyB, true, srv.URL+"/b")
		b = issueTestCert(t, "CA B", "CA A", keyB, keyA, true, srv.URL+"/a")
		leaf := issueTestCert(t, "loop.example.com", "CA A", newTestKey(t), keyA, false, srv.URL+"/a")

		_, err := fullChainCert(pemOf(leaf))
		if err == nil || !strings.Contains(err.Error(), "loop") {
			t.Fatalf("expected loop error, got %v", err)
		}
		if n := hits.Load(); n > 3 {
			t.Fatalf("expected at most 3 requests, got %d", n)
		}
	})

	t.Run("long chain", func(t *testing.T) {
		const depth = maxChainCompletionHops + 3
		certs := make([]*x509.Certificate, depth)
		handlers := map[string]http.HandlerFunc{}
		for i := range certs {
			handlers["/"+string(rune('a'+i))] = serveDER(&certs[i])
		}
		srv, hits := countingServer(t, handlers)

		keys := make([]*ecdsa.PrivateKey, depth+1)
		for i := range keys {
			keys[i] = newTestKey(t)
		}
		name := func(i int) string { return "CA " + string(rune('a'+i)) }
		for i := 0; i < depth; i++ {
			var aia []string
			if i+1 < depth {
				aia = []string{srv.URL + "/" + string(rune('a'+i+1))}
			}
			certs[i] = issueTestCert(t, name(i), name(i+1), keys[i], keys[i+1], true, aia...)
		}
		leaf := issueTestCert(t, "deep.example.com", name(0), newTestKey(t), keys[0], false, srv.URL+"/a")

		_, err := fullChainCert(pemOf(leaf))
		if err == nil || !strings.Contains(err.Error(), "issuer hops") {
			t.Fatalf("expected hop limit error, got %v", err)
		}
		if n := hits.Load(); n != maxChainCompletionHops {
			t.Fatalf("expected %d requests, got %d", maxChainCompletionHops, n)
		}
	})
}
