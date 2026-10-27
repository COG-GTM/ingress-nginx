/*
Copyright 2018 The Kubernetes Authors.

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

package collectors

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestNewUDPLogListener(t *testing.T) {
	var count uint64

	fn := func(message []byte) { //nolint:unparam,revive // Unused `message` param is required by the handleMessages function
		atomic.AddUint64(&count, 1)
	}

	tmpFile := fmt.Sprintf("/tmp/test-socket-%v", time.Now().Nanosecond())

	l, err := net.Listen("unix", tmpFile)
	if err != nil {
		t.Fatalf("unexpected error creating unix socket: %v", err)
	}
	if l == nil {
		t.Fatalf("expected a listener but none returned")
	}

	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}

			go handleMessages(conn, fn)
		}
	}()

	conn, err := net.Dial("unix", tmpFile)
	if err != nil {
		t.Errorf("unexpected error connecting to unix socket: %v", err)
	}
	if _, err := conn.Write([]byte("message")); err != nil {
		t.Errorf("unexpected error writing to unix socket: %v", err)
	}
	conn.Close()

	time.Sleep(1 * time.Millisecond)
	if atomic.LoadUint64(&count) != 1 {
		t.Errorf("expected only one message from the socket listener but %v returned", atomic.LoadUint64(&count))
	}
}

func TestCollector(t *testing.T) {
	buckets := struct {
		TimeBuckets   []float64
		LengthBuckets []float64
		SizeBuckets   []float64
	}{
		prometheus.DefBuckets,
		prometheus.LinearBuckets(10, 10, 10),
		prometheus.ExponentialBuckets(10, 10, 7),
	}

	bucketFactor := 1.1
	maxBuckets := uint32(100)

	cases := []struct {
		name                    string
		data                    []string
		metrics                 []string
		metricsPerUndefinedHost bool
		useStatusClasses        bool
		excludeMetrics          []string
		wantBefore              string
		removeIngresses         []string
		wantAfter               string
	}{
		{
			name: "invalid metric object should not increase prometheus metrics",
			data: []string{`#missing {
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}`},
			metrics: []string{"nginx_ingress_controller_response_duration_seconds"},
			wantBefore: `

			`,
		},
		{
			name: "valid metric object should update prometheus metrics",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			metrics: []string{
				"nginx_ingress_controller_connect_duration_seconds",
				"nginx_ingress_controller_header_duration_seconds",
				"nginx_ingress_controller_response_duration_seconds",
			},
			wantBefore: `
			# HELP nginx_ingress_controller_connect_duration_seconds The time spent on establishing a connection with the upstream server
			# TYPE nginx_ingress_controller_connect_duration_seconds histogram
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.005"} 0
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.01"} 0
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.025"} 0
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.05"} 0
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.1"} 0
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.25"} 0
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.5"} 0
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="1"} 1
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="2.5"} 1
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="5"} 1
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="10"} 1
			nginx_ingress_controller_connect_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="+Inf"} 1
			nginx_ingress_controller_connect_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 1
			nginx_ingress_controller_connect_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 1
			# HELP nginx_ingress_controller_header_duration_seconds The time spent on receiving first header from the upstream server
			# TYPE nginx_ingress_controller_header_duration_seconds histogram
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.005"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.01"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.025"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.05"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.1"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.25"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.5"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="1"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="2.5"} 0
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="5"} 1
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="10"} 1
			nginx_ingress_controller_header_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="+Inf"} 1
			nginx_ingress_controller_header_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 5
			nginx_ingress_controller_header_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 1
			# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
			# TYPE nginx_ingress_controller_response_duration_seconds histogram
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.005"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.01"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.025"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.05"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.1"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.25"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.5"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="1"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="2.5"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="5"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="10"} 0
			nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="+Inf"} 1
			nginx_ingress_controller_response_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 200
			nginx_ingress_controller_response_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 1
			`,
			removeIngresses: []string{"test-app-production/web-yml"},
			wantAfter: `
			`,
		},
		{
			name: "valid metric object should update requests metrics",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			metrics: []string{"nginx_ingress_controller_requests"},
			wantBefore: `
				# HELP nginx_ingress_controller_requests The total number of client requests
				# TYPE nginx_ingress_controller_requests counter
				nginx_ingress_controller_requests{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 1
			`,
			removeIngresses: []string{"test-app-production/web-yml"},
			wantAfter: `
			`,
		},
		{
			name: "valid metric object with canary information should update prometheus metrics",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":"test-app-production-test-app-canary-80"
			}]`},
			metrics: []string{"nginx_ingress_controller_response_duration_seconds"},
			wantBefore: `
				# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
				# TYPE nginx_ingress_controller_response_duration_seconds histogram
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.005"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.01"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.025"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.05"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.25"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="2.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="10"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="+Inf"} 1
				nginx_ingress_controller_response_duration_seconds_sum{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 200
				nginx_ingress_controller_response_duration_seconds_count{canary="test-app-production-test-app-canary-80",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 1
			`,
			removeIngresses: []string{"test-app-production/web-yml"},
			wantAfter: `
			`,
		},

		{
			name: "multiple messages should increase prometheus metric by two",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`, `[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-qa",
				"ingress":"web-yml-qa",
				"service":"test-app-qa",
				"canary":""
			}]`, `[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-qa",
				"ingress":"web-yml-qa",
				"service":"test-app-qa",
				"canary":""
			}]`},
			metrics: []string{"nginx_ingress_controller_response_duration_seconds"},
			wantBefore: `
				# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
				# TYPE nginx_ingress_controller_response_duration_seconds histogram
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.005"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.01"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.025"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.05"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.25"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="2.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="10"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="+Inf"} 1
				nginx_ingress_controller_response_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 200
				nginx_ingress_controller_response_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 1
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="0.005"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="0.01"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="0.025"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="0.05"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="0.1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="0.25"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="0.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="2.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="10"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200",le="+Inf"} 2
				nginx_ingress_controller_response_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200"} 400
				nginx_ingress_controller_response_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml-qa",method="GET",namespace="test-app-qa",path="/admin",service="test-app-qa",status="200"} 2
			`,
		},

		{
			name: "collector should be able to handle batched metrics correctly",
			data: []string{`[
			{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			},
			{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":100,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			metrics: []string{"nginx_ingress_controller_response_duration_seconds"},
			wantBefore: `
				# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
				# TYPE nginx_ingress_controller_response_duration_seconds histogram
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.005"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.01"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.025"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.05"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.25"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="0.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="2.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="10"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200",le="+Inf"} 2
				nginx_ingress_controller_response_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 300
				nginx_ingress_controller_response_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="200"} 2
			`,
			removeIngresses: []string{"test-app-production/web-yml"},
			wantAfter: `
			`,
		},
		{
			name: "valid metric object with status classes should update prometheus metrics",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			metrics:          []string{"nginx_ingress_controller_response_duration_seconds"},
			useStatusClasses: true,
			wantBefore: `
				# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
				# TYPE nginx_ingress_controller_response_duration_seconds histogram
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.005"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.01"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.025"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.05"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.25"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="2.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="10"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="+Inf"} 1
				nginx_ingress_controller_response_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx"} 200
				nginx_ingress_controller_response_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx"} 1
			`,
			wantAfter: `
			`,
		},
		{
			name: "basic exclude metrics test",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			excludeMetrics:   []string{"nginx_ingress_controller_connect_duration_seconds"},
			metrics:          []string{"nginx_ingress_controller_connect_duration_seconds", "nginx_ingress_controller_response_duration_seconds"},
			useStatusClasses: true,
			wantBefore: `
				# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
				# TYPE nginx_ingress_controller_response_duration_seconds histogram
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.005"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.01"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.025"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.05"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.25"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="2.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="10"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="+Inf"} 1
				nginx_ingress_controller_response_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx"} 200
				nginx_ingress_controller_response_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx"} 1
			`,
		},
		{
			name: "remove metrics with the short metric name",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			excludeMetrics:   []string{"response_duration_seconds"},
			metrics:          []string{"nginx_ingress_controller_response_duration_seconds"},
			useStatusClasses: true,
			wantBefore: `
			`,
		},
		{
			name: "exclude metrics make sure to only remove exactly matched metrics",
			data: []string{`[{
				"host":"testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			excludeMetrics:   []string{"response_duration_seconds2", "test.*", "nginx_ingress_.*", "response_duration_secon"},
			metrics:          []string{"nginx_ingress_controller_response_duration_seconds"},
			useStatusClasses: true,
			wantBefore: `
				# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
				# TYPE nginx_ingress_controller_response_duration_seconds histogram
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.005"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.01"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.025"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.05"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.25"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="0.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="1"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="2.5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="5"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="10"} 0
				nginx_ingress_controller_response_duration_seconds_bucket{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx",le="+Inf"} 1
				nginx_ingress_controller_response_duration_seconds_sum{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx"} 200
				nginx_ingress_controller_response_duration_seconds_count{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx"} 1
			`,
		},
		{
			name: "metrics with a host should not be dropped when the host is not in the hosts slice but metricsPerUndefinedHost is true",
			data: []string{`[{
				"host":"wildcard.testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			excludeMetrics:          []string{"response_duration_seconds2", "test.*", "nginx_ingress_.*", "response_duration_secon"},
			metrics:                 []string{"nginx_ingress_controller_requests"},
			metricsPerUndefinedHost: true,
			useStatusClasses:        true,
			wantBefore: `
				# HELP nginx_ingress_controller_requests The total number of client requests
				# TYPE nginx_ingress_controller_requests counter
				nginx_ingress_controller_requests{canary="",controller_class="ingress",controller_namespace="default",controller_pod="pod",host="wildcard.testshop.com",ingress="web-yml",method="GET",namespace="test-app-production",path="/admin",service="test-app",status="2xx"} 1
			`,
		},
		{
			name: "metrics with a host should be dropped when the host is not in the hosts slice",
			data: []string{`[{
				"host":"wildcard.testshop.com",
				"status":"200",
				"bytesSent":150.0,
				"method":"GET",
				"path":"/admin",
				"requestLength":300.0,
				"requestTime":60.0,
				"upstreamLatency":1.0,
				"upstreamHeaderTime":5.0,
				"upstreamName":"test-upstream",
				"upstreamIP":"1.1.1.1:8080",
				"upstreamResponseTime":200,
				"upstreamStatus":"220",
				"namespace":"test-app-production",
				"ingress":"web-yml",
				"service":"test-app",
				"canary":""
			}]`},
			excludeMetrics:   []string{"response_duration_seconds2", "test.*", "nginx_ingress_.*", "response_duration_secon"},
			metrics:          []string{"nginx_ingress_controller_requests"},
			useStatusClasses: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			registry := prometheus.NewPedanticRegistry()

			sc, err := NewSocketCollector("pod", "default", "ingress", true, c.metricsPerUndefinedHost, c.useStatusClasses, buckets, bucketFactor, maxBuckets, c.excludeMetrics)
			if err != nil {
				t.Errorf("%v: unexpected error creating new SocketCollector: %v", c.name, err)
			}

			if err := registry.Register(sc); err != nil {
				t.Errorf("registering collector failed: %s", err)
			}

			sc.SetHosts(sets.New[string]("testshop.com"))

			for _, d := range c.data {
				sc.handleMessage([]byte(d))
			}

			if err := GatherAndCompare(sc, c.wantBefore, c.metrics, registry); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if len(c.removeIngresses) > 0 {
				sc.RemoveMetrics(c.removeIngresses, registry)
				time.Sleep(1 * time.Second)

				if err := GatherAndCompare(sc, c.wantAfter, c.metrics, registry); err != nil {
					t.Errorf("unexpected collecting result:\n%s", err)
				}
			}

			sc.Stop()

			registry.Unregister(sc)
		})
	}
}

func TestNormalizeMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "PROPFIND", "MKCOL"} {
		if got := normalizeMethod(m); got != m {
			t.Errorf("normalizeMethod(%q) = %q, want %q", m, got, m)
		}
	}
	for _, m := range []string{"", "-", "get", "AAAAAAAAAAAAAAAAAAAA", "GET ", "X_CUSTOM-METHOD"} {
		if got := normalizeMethod(m); got != otherMethod {
			t.Errorf("normalizeMethod(%q) = %q, want %q", m, got, otherMethod)
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	cases := map[string]string{
		"200":  "200",
		"499":  "499",
		"000":  "000",
		"":     "-",
		"-":    "-",
		"20":   "-",
		"2000": "-",
		"2x0":  "-",
		"abc":  "-",
	}
	for in, want := range cases {
		if got := normalizeStatus(in); got != want {
			t.Errorf("normalizeStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectorBoundsMethodCardinality(t *testing.T) {
	for _, useStatusClasses := range []bool{false, true} {
		t.Run(fmt.Sprintf("statusClasses=%v", useStatusClasses), func(t *testing.T) {
			registry := prometheus.NewPedanticRegistry()

			sc, err := NewSocketCollector("pod", "default", "ingress", true, false, useStatusClasses,
				HistogramBuckets{prometheus.DefBuckets, prometheus.LinearBuckets(10, 10, 10), prometheus.ExponentialBuckets(10, 10, 7)},
				1.1, 100, nil)
			if err != nil {
				t.Fatalf("unexpected error creating new SocketCollector: %v", err)
			}
			if err := registry.Register(sc); err != nil {
				t.Fatalf("registering collector failed: %s", err)
			}
			defer registry.Unregister(sc)
			defer sc.Stop()

			sc.SetHosts(sets.New[string]("testshop.com"))

			send := func(method, status string) {
				sc.handleMessage([]byte(fmt.Sprintf(`[{
					"host":"testshop.com",
					"status":%q,
					"method":%q,
					"path":"/",
					"requestLength":300.0,
					"requestTime":60.0,
					"responseLength":100.0,
					"upstreamLatency":1.0,
					"upstreamHeaderTime":5.0,
					"upstreamResponseTime":200,
					"namespace":"ns",
					"ingress":"ing",
					"service":"svc",
					"canary":""
				}]`, status, method)))
			}

			send("GET", "200")
			for i := 0; i < 1000; i++ {
				send(fmt.Sprintf("RANDOM_METHOD_%04d", i), "200")
				send("GET", fmt.Sprintf("2%02d%d", i%100, i))
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatalf("gather failed: %v", err)
			}

			found := false
			for _, mf := range mfs {
				if mf.GetName() != "nginx_ingress_controller_requests" {
					continue
				}
				found = true
				counts := map[string]float64{}
				for _, m := range mf.GetMetric() {
					var method, status string
					for _, lp := range m.GetLabel() {
						switch lp.GetName() {
						case "method":
							method = lp.GetValue()
						case "status":
							status = lp.GetValue()
						}
					}
					counts[method+" "+status] += m.GetCounter().GetValue()
				}
				okStatus := "200"
				if useStatusClasses {
					okStatus = "2xx"
				}
				want := map[string]float64{
					"GET " + okStatus:   1,
					"OTHER " + okStatus: 1000,
					"GET -":             1000,
				}
				if len(counts) != len(want) {
					t.Fatalf("expected %d series, got %d: %v", len(want), len(counts), counts)
				}
				for k, v := range want {
					if counts[k] != v {
						t.Errorf("series %q = %v, want %v (all: %v)", k, counts[k], v, counts)
					}
				}
			}
			if !found {
				t.Fatal("nginx_ingress_controller_requests not gathered")
			}
		})
	}
}
