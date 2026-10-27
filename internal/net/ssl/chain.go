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
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/zakjan/cert-chain-resolver/certUtil"
)

const (
	// maxChainCompletionHops bounds how many issuer certificates are fetched for one certificate.
	maxChainCompletionHops = 5
	// maxIssuerURLsPerCert bounds how many AIA "CA Issuers" URLs are tried per certificate.
	maxIssuerURLsPerCert = 2
	// maxIssuerCertSize caps the size of a downloaded issuer certificate.
	maxIssuerCertSize      = 64 << 10
	maxIssuerRedirects     = 3
	issuerFetchTimeout     = 5 * time.Second
	chainCompletionTimeout = 15 * time.Second
)

// errIssuerURLNotAllowed is returned when an AIA issuer URL (or a redirect target)
// uses a scheme other than http/https or points at a non-public address.
var errIssuerURLNotAllowed = errors.New("issuer certificate URL not allowed")

// nonPublicPrefixes lists special-purpose ranges not covered by the netip.Addr helpers.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// isPublicAddr reports whether ip is a globally routable unicast address.
func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// allowIssuerAddr decides which addresses the controller may connect to when
// downloading issuer certificates. It is a variable so tests can override it.
var allowIssuerAddr = isPublicAddr

// validateIssuerURL checks the scheme and, for IP literals, the destination of an issuer URL.
// Hostnames are checked against the resolved address at dial time.
func validateIssuerURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", errIssuerURLNotAllowed, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in URL", errIssuerURLNotAllowed)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", errIssuerURLNotAllowed)
	}
	if ip, err := netip.ParseAddr(host); err == nil && !allowIssuerAddr(ip) {
		return fmt.Errorf("%w: non-public address %v", errIssuerURLNotAllowed, ip)
	}
	return nil
}

// issuerDialControl runs after DNS resolution, so it also rejects hostnames
// that resolve (or re-resolve) to non-public addresses.
func issuerDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", errIssuerURLNotAllowed, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !allowIssuerAddr(ip) {
		return fmt.Errorf("%w: non-public address %v", errIssuerURLNotAllowed, host)
	}
	return nil
}

func newIssuerHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: issuerFetchTimeout,
		Control: issuerDialControl,
	}
	return &http.Client{
		Timeout: issuerFetchTimeout,
		Transport: &http.Transport{
			// No proxy: a proxy would make the connection on our behalf and bypass issuerDialControl.
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    issuerFetchTimeout,
			ResponseHeaderTimeout:  issuerFetchTimeout,
			MaxResponseHeaderBytes: 16 << 10,
			DisableKeepAlives:      true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxIssuerRedirects {
				return fmt.Errorf("stopped after %d redirects", maxIssuerRedirects)
			}
			return validateIssuerURL(req.URL)
		},
	}
}

var issuerHTTPClient = newIssuerHTTPClient()

// fetchIssuerCertificate downloads and decodes the certificate at rawURL.
func fetchIssuerCertificate(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errIssuerURLNotAllowed, err)
	}
	if err := validateIssuerURL(u); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := issuerHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIssuerCertSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIssuerCertSize {
		return nil, fmt.Errorf("issuer certificate larger than %d bytes", maxIssuerCertSize)
	}

	return certUtil.DecodeCertificate(data)
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
}

// fetchCertificateChain follows the AIA "CA Issuers" URLs of cert and returns
// cert followed by the downloaded issuer certificates. Only http/https URLs that
// resolve to public addresses are fetched, every downloaded certificate must have
// signed the previous one, and the number of hops is bounded.
func fetchCertificateChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), chainCompletionTimeout)
	defer cancel()

	certs := []*x509.Certificate{cert}
	seen := map[string]struct{}{string(cert.Raw): {}}

	current := cert
	for hops := 0; len(current.IssuingCertificateURL) > 0 && !isSelfSigned(current); hops++ {
		if hops >= maxChainCompletionHops {
			return nil, fmt.Errorf("certificate chain exceeds %d issuer hops", maxChainCompletionHops)
		}

		urls := current.IssuingCertificateURL
		if len(urls) > maxIssuerURLsPerCert {
			urls = urls[:maxIssuerURLsPerCert]
		}

		var parent *x509.Certificate
		var errs []error
		for _, issuerURL := range urls {
			candidate, err := fetchIssuerCertificate(ctx, issuerURL)
			if err == nil {
				err = current.CheckSignatureFrom(candidate)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("fetching issuer certificate from %q: %w", issuerURL, err))
				continue
			}
			parent = candidate
			break
		}
		if parent == nil {
			return nil, errors.Join(errs...)
		}

		if _, ok := seen[string(parent.Raw)]; ok {
			return nil, fmt.Errorf("issuer certificate loop detected at %q", parent.Subject)
		}
		seen[string(parent.Raw)] = struct{}{}

		certs = append(certs, parent)
		current = parent
	}

	return certs, nil
}
