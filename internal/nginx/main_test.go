/*
Copyright 2025 The Kubernetes Authors.

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

package nginx

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func resetConfigurationToken(t *testing.T) {
	t.Helper()

	oldPath := LuaConfigPath
	t.Cleanup(func() {
		configurationToken = ""
		LuaConfigPath = oldPath
	})
	configurationToken = ""
}

func TestGenerateConfigurationToken(t *testing.T) {
	resetConfigurationToken(t)

	first, err := GenerateConfigurationToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(first) != 64 {
		t.Errorf("expected a 64 character token, got %q", first)
	}
	if ConfigurationToken() != first {
		t.Errorf("expected ConfigurationToken to return the generated token")
	}

	second, err := GenerateConfigurationToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first == second {
		t.Errorf("expected a new random token on every call")
	}
}

func TestConfigurationTokenFromLuaConfig(t *testing.T) {
	resetConfigurationToken(t)

	LuaConfigPath = filepath.Join(t.TempDir(), "cfg.json")
	if ConfigurationToken() != "" {
		t.Errorf("expected an empty token without a configuration file")
	}

	if err := os.WriteFile(LuaConfigPath, []byte(`{"configuration_token":"from-file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if token := ConfigurationToken(); token != "from-file" {
		t.Errorf("expected token from the configuration file, got %q", token)
	}
}

func TestStatusRequestsSendConfigurationToken(t *testing.T) {
	resetConfigurationToken(t)

	token, err := GenerateConfigurationToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get(ConfigurationTokenHeader))
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	oldPort := StatusPort
	StatusPort, err = strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { StatusPort = oldPort }()

	if _, _, err := NewGetStatusRequest("/configuration/backends"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, _, err := NewPostStatusRequest("/configuration/backends", "application/json", []string{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 2 || got[0] != token || got[1] != token {
		t.Errorf("expected both requests to carry the configuration token, got %v", got)
	}
}
