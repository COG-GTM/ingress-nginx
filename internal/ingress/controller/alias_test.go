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

import "testing"

func TestAliasConflictsWithHost(t *testing.T) {
	testCases := []struct {
		alias    string
		host     string
		conflict bool
	}{
		{"app.acme.example", "app.acme.example", true},
		{"App.acme.example", "app.acme.example", true},
		{"APP.ACME.EXAMPLE.", "app.acme.example", true},
		{".acme.example", "app.acme.example", true},
		{".acme.example", "acme.example", true},
		{"*.Acme.example", "app.acme.example", true},
		{"*.acme.example", "acme.example", false},
		{"app.*", "app.acme.example", true},
		{"other.*", "app.acme.example", false},
		{`~^app\.acme\.example$`, "app.acme.example", false},
		{"other.acme.example", "app.acme.example", false},
		{".other.example", "app.acme.example", false},
		{"*.other.example", "app.acme.example", false},

		{".acme.example", "*.acme.example", true},
		{"*.Acme.example", "*.acme.example", true},
		{".example", "*.acme.example", true},
		{"*.example", "*.acme.example", true},
		{".b.acme.example", "*.acme.example", true},
		{"b.acme.example", "*.acme.example", true},
		{"B.Acme.Example", "*.acme.example", true},
		{"c.b.acme.example", "*.acme.example", false},
		{"*.b.acme.example", "*.acme.example", false},
		{"www.*", "*.acme.example", true},
		{"www.acme.*", "*.acme.example", true},
		{"www.other.*", "*.acme.example", false},
		{`~^admin\.acme\.example$`, "*.acme.example", true},
		{`~^.+\.acme\.example$`, "*.acme.example", true},
		{`~^(?<sub>\w+)\.acme\.example$`, "*.acme.example", true},
		{`~^www\d+\.other\.example$`, "*.acme.example", false},
		{".other.example", "*.acme.example", false},

		{".acme.example", "_", false},
		{"", "app.acme.example", false},
	}

	for _, tc := range testCases {
		if got := aliasConflictsWithHost(tc.alias, tc.host); got != tc.conflict {
			t.Errorf("aliasConflictsWithHost(%q, %q) = %v, want %v", tc.alias, tc.host, got, tc.conflict)
		}
	}
}
