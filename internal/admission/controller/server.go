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

package controller

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/klog/v2"
)

var scheme = runtime.NewScheme()

func init() {
	if err := admissionv1.AddToScheme(scheme); err != nil {
		klog.ErrorS(err, "Failed to add scheme")
	}
}

// AdmissionController checks if an object
// is allowed in the cluster
type AdmissionController interface {
	HandleAdmission(runtime.Object) (runtime.Object, error)
}

// AdmissionControllerServer implements an HTTP server
// for kubernetes validating webhook
// https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook
type AdmissionControllerServer struct {
	AdmissionController AdmissionController

	// RequireClientCert rejects requests that did not present a client certificate
	// verified against the webhook client CA during the TLS handshake.
	RequireClientCert bool

	// AllowedClientNames, when not empty, only accepts verified client certificates
	// whose Common Name or one of its DNS SANs is in the list. Requires RequireClientCert.
	AllowedClientNames []string
}

// maxRequestBodyBytes bounds the AdmissionReview size. The API server never sends more
// than two objects capped by etcd's request size limit.
const maxRequestBodyBytes = 8 << 20

// NewAdmissionControllerServer instantiates an admission controller server with
// a default codec
func NewAdmissionControllerServer(ac AdmissionController) *AdmissionControllerServer {
	return &AdmissionControllerServer{
		AdmissionController: ac,
	}
}

// ServeHTTP implements http.Server method
func (acs *AdmissionControllerServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	if err := acs.authenticate(req); err != nil {
		klog.ErrorS(err, "Rejecting unauthenticated admission request", "remoteAddr", req.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxRequestBodyBytes))
	if err != nil {
		klog.ErrorS(err, "Failed to read request body")
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	codec := json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme, scheme, json.SerializerOptions{
		Pretty: true,
	})

	obj, _, err := codec.Decode(data, nil, nil)
	if err != nil {
		klog.ErrorS(err, "Failed to decode request body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	result, err := acs.AdmissionController.HandleAdmission(obj)
	if err != nil {
		klog.ErrorS(err, "failed to process webhook request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := codec.Encode(result, w); err != nil {
		klog.ErrorS(err, "failed to encode response body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// authenticate verifies the caller identity established by the TLS handshake before
// any part of the request is processed.
func (acs *AdmissionControllerServer) authenticate(req *http.Request) error {
	if !acs.RequireClientCert && len(acs.AllowedClientNames) == 0 {
		return nil
	}

	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 {
		return errors.New("no verified client certificate presented")
	}

	if len(acs.AllowedClientNames) == 0 {
		return nil
	}

	leaf := req.TLS.VerifiedChains[0][0]
	for _, allowed := range acs.AllowedClientNames {
		if strings.EqualFold(leaf.Subject.CommonName, allowed) {
			return nil
		}
		for _, name := range leaf.DNSNames {
			if strings.EqualFold(name, allowed) {
				return nil
			}
		}
	}

	return errors.New("client certificate " + leaf.Subject.CommonName + " is not allowed to call the admission webhook")
}
