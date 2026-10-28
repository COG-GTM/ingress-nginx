/*
Copyright 2019 The Kubernetes Authors.

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

package mirror

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	networking "k8s.io/api/networking/v1"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
	"k8s.io/ingress-nginx/internal/nginx"
	"k8s.io/klog/v2"
)

const (
	mirrorRequestBodyAnnotation = "mirror-request-body"
	mirrorTargetAnnotation      = "mirror-target"
	mirrorHostAnnotation        = "mirror-host"
)

var OnOffRegex = regexp.MustCompile(`^(on|off)$`)

var mirrorAnnotation = parser.Annotation{
	Group: "mirror",
	Annotations: parser.AnnotationFields{
		mirrorRequestBodyAnnotation: {
			Validator:     parser.ValidateRegex(OnOffRegex, true),
			Scope:         parser.AnnotationScopeIngress,
			Risk:          parser.AnnotationRiskLow,
			Documentation: `This annotation defines if the request-body should be sent to the mirror backend. Can be 'on' or 'off'`,
		},
		mirrorTargetAnnotation: {
			Validator:     parser.ValidateServerName,
			Scope:         parser.AnnotationScopeIngress,
			Risk:          parser.AnnotationRiskHigh,
			Documentation: `This annotation enables a request to be mirrored to a mirror backend.`,
		},
		mirrorHostAnnotation: {
			Validator:     parser.ValidateServerName,
			Scope:         parser.AnnotationScopeIngress,
			Risk:          parser.AnnotationRiskHigh,
			Documentation: `This annotation defines if a specific Host header should be set for mirrored request.`,
		},
	},
}

// Config returns the mirror to use in a given location
type Config struct {
	Source      string `json:"source"`
	RequestBody string `json:"requestBody"`
	Target      string `json:"target"`
	Host        string `json:"host"`
}

// Equal tests for equality between two Configuration types
func (m1 *Config) Equal(m2 *Config) bool {
	if m1 == m2 {
		return true
	}

	if m1 == nil || m2 == nil {
		return false
	}

	if m1.Source != m2.Source {
		return false
	}

	if m1.RequestBody != m2.RequestBody {
		return false
	}

	if m1.Target != m2.Target {
		return false
	}

	if m1.Host != m2.Host {
		return false
	}

	return true
}

type mirror struct {
	r                resolver.Resolver
	annotationConfig parser.Annotation
}

// NewParser creates a new mirror configuration annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return mirror{
		r:                r,
		annotationConfig: mirrorAnnotation,
	}
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to configure mirror
func (a mirror) Parse(ing *networking.Ingress) (interface{}, error) {
	config := &Config{
		Source: fmt.Sprintf("/_mirror-%v", ing.UID),
	}

	var err error
	config.RequestBody, err = parser.GetStringAnnotation(mirrorRequestBodyAnnotation, ing, a.annotationConfig.Annotations)
	if err != nil || config.RequestBody != "off" {
		if errors.IsValidationError(err) {
			klog.Warningf("annotation %s contains invalid value", mirrorRequestBodyAnnotation)
		}
		config.RequestBody = "on"
	}

	config.Target, err = parser.GetStringAnnotation(mirrorTargetAnnotation, ing, a.annotationConfig.Annotations)
	if err != nil {
		if errors.IsValidationError(err) {
			klog.Warningf("annotation %s contains invalid value, defaulting", mirrorTargetAnnotation)
		}
		config.Target = ""
		config.Source = ""
	}

	if config.Target != "" {
		if err := validateMirrorTarget(config.Target); err != nil {
			return &Config{RequestBody: config.RequestBody}, errors.ValidationError{
				Reason: fmt.Errorf("annotation %s: %w", mirrorTargetAnnotation, err),
			}
		}
	}

	config.Host, err = parser.GetStringAnnotation(mirrorHostAnnotation, ing, a.annotationConfig.Annotations)
	if err != nil {
		if errors.IsValidationError(err) {
			klog.Warningf("annotation %s contains invalid value, defaulting", mirrorHostAnnotation)
		}
		config.Host = ""
		if config.Target != "" {
			target := strings.Split(config.Target, "$")

			url, err := parser.StringToURL(target[0])
			if err == nil {
				config.Host = url.Hostname()
			}
		}
	} else if err := validateMirrorHost(config.Host); err != nil {
		return &Config{RequestBody: config.RequestBody}, errors.ValidationError{
			Reason: fmt.Errorf("annotation %s: %w", mirrorHostAnnotation, err),
		}
	}

	return config, nil
}

// validateMirrorTarget rejects mirror targets that point at the controller pod
// itself (loopback, unspecified or link-local addresses, unix sockets) or at the
// internal NGINX status/configuration and stream ports. The mirror location uses a
// static proxy_pass, so none of the Lua balancer protections apply to it.
func validateMirrorTarget(target string) error {
	// NGINX variables cannot be resolved here; only the static prefix is checked
	// and a variable that is part of the scheme, host or port is rejected.
	static := strings.SplitN(target, "$", 2)[0]

	u, err := url.Parse(static)
	if err != nil {
		return fmt.Errorf("invalid mirror target %q: %w", target, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("mirror target %q must use the http or https scheme", target)
	}

	if u.User != nil {
		return fmt.Errorf("mirror target %q must not contain user information", target)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("mirror target %q must contain a static host", target)
	}

	if static != target && u.Path == "" && u.RawQuery == "" && !uriVariable.MatchString(target[len(static):]) {
		return fmt.Errorf("mirror target %q must not use variables in the host or port", target)
	}

	if err := validateMirrorHost(host); err != nil {
		return err
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("mirror target %q has an invalid port", target)
	}

	if p == nginx.StatusPort || p == nginx.StreamPort {
		return fmt.Errorf("mirror target %q must not use the internal port %d", target, p)
	}

	return nil
}

// validateMirrorHost rejects host names that refer to the controller pod itself.
func validateMirrorHost(host string) error {
	h := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if h == "" {
		return nil
	}

	// NGINX treats "unix:" as a unix domain socket in proxy_pass
	if h == "unix" || strings.HasPrefix(h, "unix:") {
		return fmt.Errorf("mirror host %q must not be a unix socket", host)
	}

	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("mirror host %q must not be a loopback address", host)
	}

	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}

	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
			return fmt.Errorf("mirror host %q must not be a loopback, unspecified or link-local address", host)
		}
		return nil
	}

	// The resolver accepts numeric shorthands such as 127.1, 2130706433 or
	// 0x7f000001 for IPv4 addresses. No valid top level domain is numeric.
	labels := strings.Split(h, ".")
	if numericLabel.MatchString(labels[len(labels)-1]) {
		return fmt.Errorf("mirror host %q is not a valid IP address or host name", host)
	}

	return nil
}

var (
	numericLabel = regexp.MustCompile(`^(0x[0-9a-f]*|[0-9]+)$`)
	// variables that always start with "/" and so cannot change the host or port
	uriVariable = regexp.MustCompile(`^\$(request_uri|uri|document_uri)\b`)
)

func (a mirror) GetDocumentation() parser.AnnotationFields {
	return a.annotationConfig.Annotations
}

func (a mirror) Validate(anns map[string]string) error {
	maxrisk := parser.StringRiskToRisk(a.r.GetSecurityConfiguration().AnnotationsRiskLevel)
	return parser.CheckAnnotationRisk(anns, maxrisk, mirrorAnnotation.Annotations)
}
