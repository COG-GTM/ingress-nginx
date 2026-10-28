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
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

type recordingAdmissionController struct {
	called bool
}

func (r *recordingAdmissionController) HandleAdmission(obj runtime.Object) (runtime.Object, error) {
	r.called = true
	return obj, nil
}

const admissionReviewBody = `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"1"}}`

func TestServeHTTPRequiresClientCert(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		require    bool
		tlsState   *tls.ConnectionState
		wantStatus int
		wantCalled bool
	}{
		{
			name:       "rejects non-POST requests",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "rejects requests without TLS when client cert is required",
			method:     http.MethodPost,
			require:    true,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "rejects requests without a verified client cert when required",
			method:     http.MethodPost,
			require:    true,
			tlsState:   &tls.ConnectionState{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "accepts requests with a verified client cert when required",
			method:     http.MethodPost,
			require:    true,
			tlsState:   &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}},
			wantStatus: http.StatusOK,
			wantCalled: true,
		},
		{
			name:       "accepts requests when client cert is not required",
			method:     http.MethodPost,
			wantStatus: http.StatusOK,
			wantCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &recordingAdmissionController{}
			acs := NewAdmissionControllerServer(ac)
			acs.RequireClientCert = tt.require

			req := httptest.NewRequest(tt.method, "/", bytes.NewBufferString(admissionReviewBody))
			req.TLS = tt.tlsState
			w := httptest.NewRecorder()

			acs.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %v, got %v", tt.wantStatus, w.Code)
			}
			if ac.called != tt.wantCalled {
				t.Errorf("expected HandleAdmission called=%v, got %v", tt.wantCalled, ac.called)
			}
		})
	}
}
