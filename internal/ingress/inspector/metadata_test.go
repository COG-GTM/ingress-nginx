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

package inspector

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestValidateObjectMeta(t *testing.T) {
	tests := []struct {
		name    string
		meta    metav1.ObjectMeta
		wantErr bool
	}{
		{"valid", metav1.ObjectMeta{UID: "c89a5111-b2e9-4af8-be19-c2a4a924c256", Namespace: "default", Name: "my.ingress-1"}, false},
		{"empty fields", metav1.ObjectMeta{}, false},
		{"uid with nginx directives", metav1.ObjectMeta{UID: types.UID("x;\n}\n}\nssl_engine /proc/self/fd/9;\nhttp {\nserver {\nlocation /y {"), Namespace: "default", Name: "foo"}, true},
		{"uid with return", metav1.ObjectMeta{UID: types.UID("x;\nreturn 200;"), Namespace: "default", Name: "foo"}, true},
		{"uid not a uuid", metav1.ObjectMeta{UID: "not-a-uuid", Namespace: "default", Name: "foo"}, true},
		{"uuid with trailing newline", metav1.ObjectMeta{UID: "c89a5111-b2e9-4af8-be19-c2a4a924c256\n", Namespace: "default", Name: "foo"}, true},
		{"namespace with semicolon", metav1.ObjectMeta{UID: "c89a5111-b2e9-4af8-be19-c2a4a924c256", Namespace: "default;", Name: "foo"}, true},
		{"namespace with dot", metav1.ObjectMeta{Namespace: "a.b", Name: "foo"}, true},
		{"name with space", metav1.ObjectMeta{Namespace: "default", Name: "foo bar"}, true},
		{"name with brace", metav1.ObjectMeta{Namespace: "default", Name: "foo}"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateObjectMeta(&tc.meta)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateObjectMeta(%+v) error = %v, wantErr %v", tc.meta, err, tc.wantErr)
			}
		})
	}
}
