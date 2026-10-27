/*
Copyright 2021 The Kubernetes Authors.

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

package ingresses

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"

	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestGetIngressInformation(t *testing.T) {
	testcases := map[string]struct {
		ServiceBackend *networking.IngressServiceBackend
		wantName       string
		wantPort       intstr.IntOrString
	}{
		"empty ingressServiceBackend": {
			ServiceBackend: &networking.IngressServiceBackend{},
			wantName:       "",
			wantPort:       intstr.IntOrString{},
		},
		"ingressServiceBackend with port 8080": {
			ServiceBackend: &networking.IngressServiceBackend{
				Name: "test",
				Port: networking.ServiceBackendPort{
					Number: 8080,
				},
			},
			wantName: "test",
			wantPort: intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 8080,
			},
		},
		"ingressServiceBackend with port name a-svc": {
			ServiceBackend: &networking.IngressServiceBackend{
				Name: "test",
				Port: networking.ServiceBackendPort{
					Name: "a-svc",
				},
			},
			wantName: "test",
			wantPort: intstr.IntOrString{
				Type:   intstr.String,
				StrVal: "a-svc",
			},
		},
	}

	for title, testCase := range testcases {
		gotName, gotPort := serviceToNameAndPort(testCase.ServiceBackend)
		if gotName != testCase.wantName {
			t.Fatalf("%s: expected '%v' but returned %v", title, testCase.wantName, gotName)
		}
		if gotPort != testCase.wantPort {
			t.Fatalf("%s: expected '%v' but returned %v", title, testCase.wantPort, gotPort)
		}
	}
}

func TestWriteIngressRowEscapesControlCharacters(t *testing.T) {
	implSpecific := networking.PathTypeImplementationSpecific
	ingresses := []networking.Ingress{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "evil"},
			Spec: networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "pay.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path:     "/\x1b[2K\rfake\tcol\n",
										PathType: &implSpecific,
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{
												Name: "svc",
												Port: networking.ServiceBackendPort{Name: "http\x1b]0;t\x07"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: networking.IngressStatus{
				LoadBalancer: networking.IngressLoadBalancerStatus{
					Ingress: []networking.IngressLoadBalancerIngress{{Hostname: "lb\r.example.com"}},
				},
			},
		},
	}

	for _, allNamespaces := range []bool{false, true} {
		rows := getIngressRows(&ingresses)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		rows[0].NumEndpoints = "1"

		var buf bytes.Buffer
		printer := tabwriter.NewWriter(&buf, 6, 4, 3, ' ', 0)
		writeIngressHeader(printer, allNamespaces)
		writeIngressRow(printer, &rows[0], allNamespaces)
		if err := printer.Flush(); err != nil {
			t.Fatal(err)
		}
		out := buf.String()

		for _, r := range out {
			if r != '\n' && (r < 0x20 || r == 0x7f) {
				t.Fatalf("allNamespaces=%v: output contains control character %q: %q", allNamespaces, r, out)
			}
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("allNamespaces=%v: expected header + 1 row, got %d lines: %q", allNamespaces, len(lines), out)
		}
		for _, want := range []string{`pay.example.com/\x1b[2K\rfake\tcol\n`, `lb\r.example.com`, `http\x1b]0;t\a`} {
			if !strings.Contains(lines[1], want) {
				t.Errorf("allNamespaces=%v: row %q does not contain %q", allNamespaces, lines[1], want)
			}
		}
		if allNamespaces != strings.HasPrefix(lines[1], "team-b") {
			t.Errorf("allNamespaces=%v: unexpected namespace column in %q", allNamespaces, lines[1])
		}
	}
}
