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

package controller

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type recordingAdmissionController struct {
	calls int
}

func (r *recordingAdmissionController) HandleAdmission(obj runtime.Object) (runtime.Object, error) {
	r.calls++
	review, ok := obj.(*admissionv1.AdmissionReview)
	if !ok {
		return nil, fmt.Errorf("unexpected object %T", obj)
	}
	review.Response = &admissionv1.AdmissionResponse{Allowed: true}
	return review, nil
}

const admissionReviewBody = `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"1"}}`

func newAdmissionRequest(method, contentType, body string, clientCert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(method, "/networking/v1/ingresses", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if clientCert != nil {
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{clientCert}}}
	}
	return req
}

func TestServeHTTPAuthentication(t *testing.T) {
	apiServerCert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "kube-apiserver-webhook-client"},
		DNSNames: []string{"apiserver.kube-system.svc"},
	}
	otherCert := &x509.Certificate{Subject: pkix.Name{CommonName: "mallory"}}

	tests := []struct {
		name         string
		requireCert  bool
		allowedNames []string
		clientCert   *x509.Certificate
		wantCode     int
		wantHandled  bool
	}{
		{"no client auth configured", false, nil, nil, http.StatusOK, true},
		{"client cert required but missing", true, nil, nil, http.StatusUnauthorized, false},
		{"client cert required and verified", true, nil, otherCert, http.StatusOK, true},
		{"allowed name matches CN", true, []string{"kube-apiserver-webhook-client"}, apiServerCert, http.StatusOK, true},
		{"allowed name matches DNS SAN", true, []string{"APIServer.kube-system.svc"}, apiServerCert, http.StatusOK, true},
		{"allowed name does not match", true, []string{"kube-apiserver-webhook-client"}, otherCert, http.StatusUnauthorized, false},
		{"allowed names without verified cert", false, []string{"kube-apiserver-webhook-client"}, nil, http.StatusUnauthorized, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &recordingAdmissionController{}
			server := NewAdmissionControllerServer(ac)
			server.RequireClientCert = tt.requireCert
			server.AllowedClientNames = tt.allowedNames

			w := httptest.NewRecorder()
			server.ServeHTTP(w, newAdmissionRequest(http.MethodPost, "application/json", admissionReviewBody, tt.clientCert))

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, w.Code)
			}
			if handled := ac.calls > 0; handled != tt.wantHandled {
				t.Errorf("expected admission controller called=%v, got %v", tt.wantHandled, handled)
			}
		})
	}
}

func TestServeHTTPRejectsMalformedRequests(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		contentType string
		body        string
		wantCode    int
	}{
		{"GET request", http.MethodGet, "application/json", admissionReviewBody, http.StatusMethodNotAllowed},
		{"missing content type", http.MethodPost, "", admissionReviewBody, http.StatusUnsupportedMediaType},
		{"wrong content type", http.MethodPost, "text/plain", admissionReviewBody, http.StatusUnsupportedMediaType},
		{"oversized body", http.MethodPost, "application/json", string(bytes.Repeat([]byte(" "), maxRequestBodyBytes+1)), http.StatusRequestEntityTooLarge},
		{"undecodable body", http.MethodPost, "application/json", "{", http.StatusBadRequest},
		{"valid request with charset", http.MethodPost, "application/json; charset=utf-8", admissionReviewBody, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &recordingAdmissionController{}
			w := httptest.NewRecorder()
			NewAdmissionControllerServer(ac).ServeHTTP(w, newAdmissionRequest(tt.method, tt.contentType, tt.body, nil))
			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, w.Code)
			}
			if tt.wantCode != http.StatusOK && ac.calls != 0 {
				t.Errorf("admission controller should not be called for rejected requests")
			}
		})
	}
}
