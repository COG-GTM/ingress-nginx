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

package util

import "testing"

func TestEscapeTerminal(t *testing.T) {
	testcases := map[string]struct {
		in            string
		wantLine      string
		wantMultiline string
	}{
		"plain path": {
			in:            "example.com/api/v1",
			wantLine:      "example.com/api/v1",
			wantMultiline: "example.com/api/v1",
		},
		"printable unicode is kept": {
			in:            "/caf\u00e9/\u65e5\u672c",
			wantLine:      "/caf\u00e9/\u65e5\u672c",
			wantMultiline: "/caf\u00e9/\u65e5\u672c",
		},
		"erase line and carriage return": {
			in:            "/\x1b[2K\rfake",
			wantLine:      `/\x1b[2K\rfake`,
			wantMultiline: `/\x1b[2K\rfake`,
		},
		"OSC window title": {
			in:            "/\x1b]0;pwned\x07",
			wantLine:      `/\x1b]0;pwned\a`,
			wantMultiline: `/\x1b]0;pwned\a`,
		},
		"backspace and C1 CSI": {
			in:            "/a\b\u009b2J",
			wantLine:      `/a\b\u009b2J`,
			wantMultiline: `/a\b\u009b2J`,
		},
		"bidi override": {
			in:            "/\u202eevil",
			wantLine:      `/\u202eevil`,
			wantMultiline: `/\u202eevil`,
		},
		"invalid utf-8": {
			in:            "/\xff\xfe",
			wantLine:      `/\xff\xfe`,
			wantMultiline: `/\xff\xfe`,
		},
		"tab and newline": {
			in:            "a\tb\nc",
			wantLine:      `a\tb\nc`,
			wantMultiline: "a\tb\nc",
		},
	}

	for title, tc := range testcases {
		if got := EscapeTerminal(tc.in); got != tc.wantLine {
			t.Errorf("%s: EscapeTerminal(%q) = %q, want %q", title, tc.in, got, tc.wantLine)
		}
		if got := EscapeTerminalMultiline(tc.in); got != tc.wantMultiline {
			t.Errorf("%s: EscapeTerminalMultiline(%q) = %q, want %q", title, tc.in, got, tc.wantMultiline)
		}
	}
}
