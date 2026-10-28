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

package tcpproxy

import (
	"fmt"
	"sync"
	"testing"
)

func TestGet(t *testing.T) {
	def := &TCPServer{Hostname: "localhost", IP: "127.0.0.1", Port: 442}
	p := &TCPProxy{Default: def}

	if got := p.Get("a.example.com"); got != def {
		t.Errorf("expected default server with empty list, got %+v", got)
	}

	a := &TCPServer{Hostname: "a.example.com", IP: "10.0.0.1", Port: 443}
	p.SetServerList([]*TCPServer{a})

	if got := p.Get("a.example.com"); got != a {
		t.Errorf("expected %+v, got %+v", a, got)
	}
	if got := p.Get("b.example.com"); got != def {
		t.Errorf("expected default server for unknown host, got %+v", got)
	}
}

func TestSetServerListConcurrentWithGet(_ *testing.T) {
	p := &TCPProxy{Default: &TCPServer{Hostname: "localhost"}}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					p.Get("host-1.example.com")
				}
			}
		}()
	}

	for i := 0; i < 1000; i++ {
		p.SetServerList([]*TCPServer{{Hostname: fmt.Sprintf("host-%d.example.com", i%3)}})
	}
	close(stop)
	wg.Wait()
}
