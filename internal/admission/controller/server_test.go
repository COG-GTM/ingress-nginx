/*
Copyright 2026 The Kubernetes Authors.

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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const admissionReviewBody = `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"1"}}`

type countingAdmissionController struct {
	calls   atomic.Int32
	running atomic.Int32
	peak    atomic.Int32
	release chan struct{}
	started chan struct{}
}

func (c *countingAdmissionController) HandleAdmission(obj runtime.Object) (runtime.Object, error) {
	c.calls.Add(1)
	n := c.running.Add(1)
	defer c.running.Add(-1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if c.started != nil {
		c.started <- struct{}{}
	}
	if c.release != nil {
		<-c.release
	}
	review, ok := obj.(*admissionv1.AdmissionReview)
	if !ok {
		return obj, nil
	}
	review.Response = &admissionv1.AdmissionResponse{UID: review.Request.UID, Allowed: true}
	return review, nil
}

func newTestServer(ac AdmissionController, admissions, inFlight int, queueTimeout time.Duration) *AdmissionControllerServer {
	s := NewAdmissionControllerServer(ac)
	s.admissions = make(chan struct{}, admissions)
	s.inFlight = make(chan struct{}, inFlight)
	s.queueTimeout = queueTimeout
	return s
}

func post(s http.Handler, body io.Reader, contentLength int64) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/networking/v1/ingresses", body)
	req.ContentLength = contentLength
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestServeHTTPAcceptsAdmissionReview(t *testing.T) {
	ac := &countingAdmissionController{}
	w := post(NewAdmissionControllerServer(ac), strings.NewReader(admissionReviewBody), int64(len(admissionReviewBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ac.calls.Load() != 1 {
		t.Fatalf("expected one admission call, got %d", ac.calls.Load())
	}
}

func TestServeHTTPRejectsDeclaredOversizedBody(t *testing.T) {
	ac := &countingAdmissionController{}
	s := NewAdmissionControllerServer(ac)
	body := &countingReader{limit: MaxRequestBodyBytes + 1}
	w := post(s, body, MaxRequestBodyBytes+1)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
	if body.read != 0 {
		t.Fatalf("expected body not to be read, read %d bytes", body.read)
	}
	if ac.calls.Load() != 0 {
		t.Fatal("admission controller must not be called")
	}
}

func TestServeHTTPRejectsStreamedOversizedBody(t *testing.T) {
	ac := &countingAdmissionController{}
	s := NewAdmissionControllerServer(ac)
	body := &countingReader{limit: 1 << 30}
	w := post(s, body, -1)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
	if body.read > MaxRequestBodyBytes+64<<10 {
		t.Fatalf("expected reading to stop near the limit, read %d bytes", body.read)
	}
	if ac.calls.Load() != 0 {
		t.Fatal("admission controller must not be called")
	}
}

func TestServeHTTPAcceptsBodyAtLimit(t *testing.T) {
	ac := &countingAdmissionController{}
	s := NewAdmissionControllerServer(ac)
	pad := int(MaxRequestBodyBytes) - len(admissionReviewBody)
	body := admissionReviewBody + strings.Repeat(" ", pad)
	w := post(s, strings.NewReader(body), int64(len(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestServeHTTPBoundsConcurrentAdmissions(t *testing.T) {
	const limit, requests = 2, 8
	ac := &countingAdmissionController{release: make(chan struct{}), started: make(chan struct{}, requests)}
	s := newTestServer(ac, limit, requests, time.Minute)

	var wg sync.WaitGroup
	codes := make(chan int, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- post(s, strings.NewReader(admissionReviewBody), int64(len(admissionReviewBody))).Code
		}()
	}

	for i := 0; i < limit; i++ {
		<-ac.started
	}
	time.Sleep(100 * time.Millisecond)
	if got := ac.running.Load(); got != limit {
		t.Fatalf("expected %d running admissions while blocked, got %d", limit, got)
	}
	close(ac.release)
	wg.Wait()
	close(codes)

	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("expected queued requests to succeed, got %d", code)
		}
	}
	if ac.peak.Load() != limit {
		t.Fatalf("expected peak concurrency %d, got %d", limit, ac.peak.Load())
	}
	if ac.calls.Load() != requests {
		t.Fatalf("expected %d admission calls, got %d", requests, ac.calls.Load())
	}
}

func TestServeHTTPRejectsWhenAdmissionQueueTimesOut(t *testing.T) {
	ac := &countingAdmissionController{release: make(chan struct{}), started: make(chan struct{}, 1)}
	s := newTestServer(ac, 1, 4, 50*time.Millisecond)

	done := make(chan int)
	go func() {
		done <- post(s, strings.NewReader(admissionReviewBody), int64(len(admissionReviewBody))).Code
	}()
	<-ac.started

	w := post(s, strings.NewReader(admissionReviewBody), int64(len(admissionReviewBody)))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}

	close(ac.release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d", code)
	}
	if ac.calls.Load() != 1 {
		t.Fatalf("expected one admission call, got %d", ac.calls.Load())
	}
}

func TestServeHTTPRejectsWhenTooManyInFlight(t *testing.T) {
	ac := &countingAdmissionController{}
	s := newTestServer(ac, 1, 1, time.Minute)
	s.inFlight <- struct{}{}

	body := &countingReader{limit: 1 << 10}
	w := post(s, body, -1)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if body.read != 0 {
		t.Fatalf("expected body not to be read, read %d bytes", body.read)
	}
	if ac.calls.Load() != 0 {
		t.Fatal("admission controller must not be called")
	}
}

// countingReader yields up to limit bytes of padding and records how many were read.
type countingReader struct {
	limit int64
	read  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.read >= r.limit {
		return 0, io.EOF
	}
	n := int64(len(p))
	if remaining := r.limit - r.read; n > remaining {
		n = remaining
	}
	copy(p, bytes.Repeat([]byte(" "), int(n)))
	r.read += n
	return int(n), nil
}
