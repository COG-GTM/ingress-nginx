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
	"net/http"
	goruntime "runtime"
	"time"

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

const (
	// MaxRequestBodyBytes caps the size of an AdmissionReview request body.
	// The API server limits objects to 1.5MiB in etcd and an AdmissionReview
	// carries at most the object and the old object.
	MaxRequestBodyBytes int64 = 4 << 20

	// MaxInFlightRequests caps the number of requests being read, decoded or
	// queued at the same time; further requests are rejected with 429.
	MaxInFlightRequests = 32

	// minConcurrentAdmissions is the lower bound for the number of admission
	// checks (config render and nginx -t) allowed to run at the same time.
	minConcurrentAdmissions = 2

	// AdmissionQueueTimeout is how long a request may wait for an admission
	// slot before it is rejected with 429.
	AdmissionQueueTimeout = 10 * time.Second
)

// AdmissionControllerServer implements an HTTP server
// for kubernetes validating webhook
// https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook
type AdmissionControllerServer struct {
	AdmissionController AdmissionController

	maxRequestBodyBytes int64
	queueTimeout        time.Duration
	inFlight            chan struct{}
	admissions          chan struct{}
}

// NewAdmissionControllerServer instantiates an admission controller server with
// a default codec
func NewAdmissionControllerServer(ac AdmissionController) *AdmissionControllerServer {
	return &AdmissionControllerServer{
		AdmissionController: ac,
		maxRequestBodyBytes: MaxRequestBodyBytes,
		queueTimeout:        AdmissionQueueTimeout,
		inFlight:            make(chan struct{}, MaxInFlightRequests),
		admissions:          make(chan struct{}, maxConcurrentAdmissions()),
	}
}

// maxConcurrentAdmissions caps concurrent admission checks to the CPUs
// available to the controller; further requests queue.
func maxConcurrentAdmissions() int {
	return max(goruntime.GOMAXPROCS(0), minConcurrentAdmissions)
}

func tooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
}

// ServeHTTP implements http.Server method
func (acs *AdmissionControllerServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	select {
	case acs.inFlight <- struct{}{}:
		defer func() { <-acs.inFlight }()
	default:
		klog.Warning("Rejecting admission request: too many requests in flight")
		tooManyRequests(w)
		return
	}

	if req.ContentLength > acs.maxRequestBodyBytes {
		klog.Warningf("Rejecting admission request: body of %d bytes exceeds limit of %d bytes", req.ContentLength, acs.maxRequestBodyBytes)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, acs.maxRequestBodyBytes))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			klog.Warningf("Rejecting admission request: body exceeds limit of %d bytes", acs.maxRequestBodyBytes)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		klog.ErrorS(err, "Failed to read request body")
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

	timer := time.NewTimer(acs.queueTimeout)
	defer timer.Stop()
	select {
	case acs.admissions <- struct{}{}:
		defer func() { <-acs.admissions }()
	case <-timer.C:
		klog.Warning("Rejecting admission request: timed out waiting for an admission slot")
		tooManyRequests(w)
		return
	case <-req.Context().Done():
		klog.Warning("Admission request canceled while waiting for an admission slot")
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
