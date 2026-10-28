/*
Copyright 2017 The Kubernetes Authors.

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

package upstreamhashby

import (
	"testing"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

func TestParse(t *testing.T) {
	annotation := parser.GetAnnotationWithPrefix(upstreamHashByAnnotation)

	ap := NewParser(&resolver.Mock{})
	if ap == nil {
		t.Fatalf("expected a parser.IngressAnnotation but returned nil")
	}

	testCases := []struct {
		annotations map[string]string
		expected    string
		expectErr   bool
	}{
		{map[string]string{annotation: "$request_URI"}, "$request_URI", false},
		{map[string]string{annotation: "$request_uri$scheme"}, "$request_uri$scheme", false},
		{map[string]string{annotation: "xpto;[]"}, "", true},
		{map[string]string{annotation: "lalal${scheme_test}"}, "lalal${scheme_test}", false},
		{map[string]string{annotation: "false"}, "false", false},
		{map[string]string{}, "", false},
		{nil, "", false},
	}

	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
		},
		Spec: networking.IngressSpec{},
	}

	for _, testCase := range testCases {
		ing.SetAnnotations(testCase.annotations)
		result, err := ap.Parse(ing)
		if (err != nil) != testCase.expectErr {
			t.Fatalf("expected error: %t got error: %t err value: %s. %+v", testCase.expectErr, err != nil, err, testCase.annotations)
		}
		if !testCase.expectErr {
			uc, ok := result.(*Config)
			if !ok {
				t.Fatalf("expected a Config type")
			}

			if uc.UpstreamHashBy != testCase.expected {
				t.Errorf("expected %v but returned %v, annotations: %s", testCase.expected, result, testCase.annotations)
			}
		}
	}
}

func TestParseSubsetSize(t *testing.T) {
	annotation := parser.GetAnnotationWithPrefix(upstreamHashBySubsetSize)
	ap := NewParser(&resolver.Mock{})

	testCases := []struct {
		value     string
		expected  int
		expectErr bool
	}{
		{"0", 3, false},
		{"1", 1, false},
		{"3", 3, false},
		{"1024", 1024, false},
		{"1025", 0, true},
		{"1000000000", 0, true},
		{"9223372036854775807", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
	}

	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
		},
		Spec: networking.IngressSpec{},
	}

	for _, testCase := range testCases {
		ing.SetAnnotations(map[string]string{
			parser.GetAnnotationWithPrefix(upstreamHashByAnnotation):       "$request_uri",
			parser.GetAnnotationWithPrefix(upstreamHashBySubsetAnnotation): "true",
			annotation: testCase.value,
		})
		result, err := ap.Parse(ing)
		if (err != nil) != testCase.expectErr {
			t.Fatalf("value %q: expected error: %t got error: %v", testCase.value, testCase.expectErr, err)
		}
		if testCase.expectErr {
			continue
		}
		cfg, ok := result.(*Config)
		if !ok {
			t.Fatalf("value %q: expected a *Config", testCase.value)
		}
		if got := cfg.UpstreamHashBySubsetSize; got != testCase.expected {
			t.Errorf("value %q: expected subset size %d, got %d", testCase.value, testCase.expected, got)
		}
	}
}

func TestParseSubsetSizeWithoutAnnotationValidation(t *testing.T) {
	parser.EnableAnnotationValidation = false
	defer func() { parser.EnableAnnotationValidation = true }()

	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{Name: "foo", Namespace: api.NamespaceDefault},
	}
	ing.SetAnnotations(map[string]string{
		parser.GetAnnotationWithPrefix(upstreamHashBySubsetSize): "1000000000",
	})
	if _, err := NewParser(&resolver.Mock{}).Parse(ing); err == nil {
		t.Fatalf("expected an error for an oversized subset size with annotation validation disabled")
	}
}
