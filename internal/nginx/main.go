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

package nginx

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	ps "github.com/mitchellh/go-ps"
	klog "k8s.io/klog/v2"
)

// TODO: Check https://github.com/kubernetes/kubernetes/blob/master/pkg/master/ports/ports.go for ports already being used

// ProfilerPort port used by the ingress controller to expose the Go Profiler when it is enabled.
var ProfilerPort = 10245

// ProfilerAddress IP address used by the ingress controller to expose the Go Profiler when it is enabled.
var ProfilerAddress = "127.0.0.1"

// TemplatePath path of the NGINX template
var TemplatePath = "/etc/nginx/template/nginx.tmpl"

// PID defines the location of the pid file used by NGINX
var PID = "/tmp/nginx/nginx.pid"

// StatusPort port used by NGINX for the status server
var StatusPort = 10246

// HealthPath defines the path used to define the health check location in NGINX
var HealthPath = "/healthz"

// HealthCheckTimeout defines the time limit in seconds for a probe to health-check-path to succeed
var HealthCheckTimeout = 10 * time.Second

// StatusPath defines the path used to expose the NGINX status page
// http://nginx.org/en/docs/http/ngx_http_stub_status_module.html
var StatusPath = "/nginx_status"

// StreamPort defines the port used by NGINX for the NGINX stream configuration socket
var StreamPort = 10247

// LuaConfigPath is the configuration file written by the controller for the Lua modules
var LuaConfigPath = "/etc/nginx/lua/cfg.json"

// ConfigurationTokenHeader is the header that must carry the configuration token
// on every request to the /configuration endpoint of the status server.
const ConfigurationTokenHeader = "X-Ingress-Nginx-Configuration-Token" //nolint:gosec // header name, not a credential

var (
	configurationTokenMu sync.Mutex
	configurationToken   string
)

// GenerateConfigurationToken creates a new random token that authenticates the
// controller against the /configuration endpoint of the status server.
func GenerateConfigurationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating configuration token: %w", err)
	}

	configurationTokenMu.Lock()
	defer configurationTokenMu.Unlock()
	configurationToken = hex.EncodeToString(b)

	return configurationToken, nil
}

// ConfigurationToken returns the token used to authenticate requests to the
// /configuration endpoint. Processes other than the controller (e.g. dbg) read
// it from the Lua configuration file written by the controller.
func ConfigurationToken() string {
	configurationTokenMu.Lock()
	defer configurationTokenMu.Unlock()

	if configurationToken != "" {
		return configurationToken
	}

	data, err := os.ReadFile(LuaConfigPath)
	if err != nil {
		return ""
	}

	luaCfg := struct {
		ConfigurationToken string `json:"configuration_token"`
	}{}
	if err := json.Unmarshal(data, &luaCfg); err != nil {
		return ""
	}

	return luaCfg.ConfigurationToken
}

// NewGetStatusRequest creates a new GET request to the internal NGINX status server
func NewGetStatusRequest(path string) (statusCode int, data []byte, err error) {
	url := fmt.Sprintf("http://127.0.0.1:%v%v", StatusPort, path)

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set(ConfigurationTokenHeader, ConfigurationToken())

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, err
	}

	return res.StatusCode, data, nil
}

// NewPostStatusRequest creates a new POST request to the internal NGINX status server
func NewPostStatusRequest(path, contentType string, data interface{}) (statusCode int, body []byte, err error) {
	url := fmt.Sprintf("http://127.0.0.1:%v%v", StatusPort, path)

	buf, err := json.Marshal(data)
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(ConfigurationTokenHeader, ConfigurationToken())

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, err
	}

	return res.StatusCode, body, nil
}

// GetServerBlock takes an nginx.conf file and a host and tries to find the server block for that host
func GetServerBlock(conf, host string) (string, error) {
	startMsg := fmt.Sprintf("## start server %v\n", host)
	endMsg := fmt.Sprintf("## end server %v", host)

	blockStart := strings.Index(conf, startMsg)
	if blockStart < 0 {
		return "", fmt.Errorf("host %v was not found in the controller's nginx.conf", host)
	}
	blockStart += len(startMsg)

	blockEnd := strings.Index(conf, endMsg)
	if blockEnd < 0 {
		return "", fmt.Errorf("the end of the host server block could not be found, but the beginning was")
	}

	return conf[blockStart:blockEnd], nil
}

// ReadNginxConf reads the nginx configuration file into a string
func ReadNginxConf() (string, error) {
	return readFileToString("/etc/nginx/nginx.conf")
}

// readFileToString reads any file into a string
func readFileToString(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	contents, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(contents), nil
}

// Version return details about NGINX
func Version() string {
	flag := "-v"

	if klog.V(2).Enabled() {
		flag = "-V"
	}

	cmd := exec.Command("nginx", flag)
	out, err := cmd.CombinedOutput()
	if err != nil {
		klog.ErrorS(err, "unexpected error obtaining NGINX version")
		return "N/A"
	}

	return string(out)
}

// IsRunning returns true if a process with the name 'nginx' is found
func IsRunning() bool {
	processes, err := ps.Processes()
	if err != nil {
		klog.ErrorS(err, "unexpected error obtaining process list")
	}
	for _, p := range processes {
		if p.Executable() == "nginx" {
			return true
		}
	}

	return false
}
