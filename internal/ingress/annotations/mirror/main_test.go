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
	"reflect"
	"testing"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

func TestParse(t *testing.T) {
	requestBody := parser.GetAnnotationWithPrefix("mirror-request-body")
	backendURL := parser.GetAnnotationWithPrefix("mirror-target")
	host := parser.GetAnnotationWithPrefix("mirror-host")

	ap := NewParser(&resolver.Mock{})
	if ap == nil {
		t.Fatalf("expected a parser.IngressAnnotation but returned nil")
	}

	ngxURI := "/_mirror-c89a5111-b2e9-4af8-be19-c2a4a924c256"
	testCases := []struct {
		annotations map[string]string
		expected    *Config
	}{
		{map[string]string{backendURL: "https://test.env.com/$request_uri"}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "https://test.env.com/$request_uri",
			Host:        "test.env.com",
		}},
		{map[string]string{backendURL: "https://test.env.com$request_uri"}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "https://test.env.com$request_uri",
			Host:        "test.env.com",
		}},
		{map[string]string{backendURL: "https://test.env.com:8080$request_uri"}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "https://test.env.com:8080$request_uri",
			Host:        "test.env.com",
		}},
		{map[string]string{backendURL: "https://test.env.com:8080/$request_uri"}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "https://test.env.com:8080/$request_uri",
			Host:        "test.env.com",
		}},
		{map[string]string{requestBody: "off"}, &Config{
			Source:      "",
			RequestBody: "off",
			Target:      "",
			Host:        "",
		}},
		{map[string]string{host: "test.env.com", backendURL: "http://some.test.env.com/$someparam"}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "http://some.test.env.com/$someparam",
			Host:        "test.env.com",
		}},
		{map[string]string{backendURL: "http://some.test.env.com:2121/$someparam=1&$someotherparam=2"}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "http://some.test.env.com:2121/$someparam=1&$someotherparam=2",
			Host:        "some.test.env.com",
		}},
		{map[string]string{backendURL: "http://some.test.env.com", host: "someInvalidParam.%^&*()_=!@#'\""}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "http://some.test.env.com",
			Host:        "some.test.env.com",
		}},
		{map[string]string{backendURL: "http://some.test.env.com", host: "_sbrubles-i\"@xpto:12345"}, &Config{
			Source:      ngxURI,
			RequestBody: "on",
			Target:      "http://some.test.env.com",
			Host:        "some.test.env.com",
		}},
	}

	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
			UID:       "c89a5111-b2e9-4af8-be19-c2a4a924c256",
		},
		Spec: networking.IngressSpec{},
	}

	for _, testCase := range testCases {
		ing.SetAnnotations(testCase.annotations)
		result, err := ap.Parse(ing)
		if err != nil {
			t.Errorf(err.Error())
		}
		if !reflect.DeepEqual(result, testCase.expected) {
			t.Errorf("expected %+v but returned %+v, annotations: %s", testCase.expected, result, testCase.annotations)
		}
	}
}

func TestParseRejectsConfigurationEndpoint(t *testing.T) {
	ap := NewParser(&resolver.Mock{})
	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
			UID:       "c89a5111-b2e9-4af8-be19-c2a4a924c256",
			Annotations: map[string]string{
				parser.GetAnnotationWithPrefix("mirror-target"): "http://127.0.0.1:10246/configuration/backends",
			},
		},
	}

	result, err := ap.Parse(ing)
	if !errors.IsValidationError(err) {
		t.Fatalf("expected a validation error, got %v", err)
	}
	config, ok := result.(*Config)
	if !ok {
		t.Fatalf("expected a *Config, got %T", result)
	}
	if config.Source != "" || config.Target != "" {
		t.Errorf("expected no mirror, got %+v", config)
	}
}

func TestParseRejectsInternalTargets(t *testing.T) {
	backendURL := parser.GetAnnotationWithPrefix("mirror-target")
	host := parser.GetAnnotationWithPrefix("mirror-host")

	ap := NewParser(&resolver.Mock{})

	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
			UID:       "c89a5111-b2e9-4af8-be19-c2a4a924c256",
		},
		Spec: networking.IngressSpec{},
	}

	testCases := []map[string]string{
		{backendURL: "IamNotAURL"},
		{backendURL: "http://127.0.0.1:10246/configuration/servers"},
		{backendURL: "http://127.0.0.1:8080/"},
		{backendURL: "http://127.1:8080/"},
		{backendURL: "http://2130706433/"},
		{backendURL: "http://0x7f000001/"},
		{backendURL: "http://0/"},
		{backendURL: "http://0.0.0.0:80/"},
		{backendURL: "http://localhost/"},
		{backendURL: "http://LocalHost./"},
		{backendURL: "http://foo.localhost/"},
		{backendURL: "http://[::1]:10246/configuration/backends"},
		{backendURL: "http://[::ffff:127.0.0.1]/"},
		{backendURL: "http://[::]/"},
		{backendURL: "http://169.254.169.254/latest/meta-data/"},
		{backendURL: "http://[fe80::1]/"},
		{backendURL: "http://unix:/var/run/nginx.sock:/"},
		{backendURL: "http://user@test.env.com/"},
		{backendURL: "http://test.env.com:10246/configuration/backends"},
		{backendURL: "http://test.env.com:10247/"},
		{backendURL: "ftp://test.env.com/"},
		{backendURL: "http://$host/"},
		{backendURL: "http://test.env.com$arg_host"},
		{backendURL: "http://test.env.com:$arg_port/"},
		{backendURL: "http://test.env.com/", host: "localhost"},
		{backendURL: "http://test.env.com/", host: "127.0.0.1"},
	}

	for _, annotations := range testCases {
		ing.SetAnnotations(annotations)
		result, err := ap.Parse(ing)
		if err != nil && !errors.IsValidationError(err) {
			t.Errorf("expected a validation error for annotations %v, got %v", annotations, err)
		}
		config, ok := result.(*Config)
		if !ok {
			t.Fatalf("expected a *Config, got %T", result)
		}
		if config.Source != "" || config.Target != "" {
			t.Errorf("expected no mirror for annotations %v, got %+v", annotations, config)
		}
	}
}

func TestParseAllowsExternalTargets(t *testing.T) {
	backendURL := parser.GetAnnotationWithPrefix("mirror-target")

	ap := NewParser(&resolver.Mock{})

	ing := &networking.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
			UID:       "c89a5111-b2e9-4af8-be19-c2a4a924c256",
		},
		Spec: networking.IngressSpec{},
	}

	for _, target := range []string{
		"https://1.2.3.4$request_uri",
		"http://10.0.0.12:8080/mirror",
		"http://mirror.default.svc.cluster.local$uri",
		"http://[2001:db8::1]:8080/",
		"https://test.env.com:443/$request_uri",
	} {
		ing.SetAnnotations(map[string]string{backendURL: target})
		result, err := ap.Parse(ing)
		if err != nil {
			t.Errorf("unexpected error for %v: %v", target, err)
			continue
		}
		config, ok := result.(*Config)
		if !ok {
			t.Errorf("expected a *Config for %v, got %T", target, result)
			continue
		}
		if config.Target != target || config.Source == "" {
			t.Errorf("expected mirror to %v, got %+v", target, config)
		}
	}
}
