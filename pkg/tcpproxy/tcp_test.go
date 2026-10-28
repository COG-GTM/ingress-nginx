/*
Copyright 2024 The Kubernetes Authors.

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
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type backend struct {
	server   *TCPServer
	received chan []byte
}

func newBackend(t *testing.T, hostname string) *backend {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected address type %T", l.Addr())
	}
	b := &backend{
		server:   &TCPServer{Hostname: hostname, IP: addr.IP.String(), Port: addr.Port},
		received: make(chan []byte, 1),
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		//nolint:errcheck // a short read is reported by the test via the payload
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 16384)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		b.received <- buf[:n]
	}()
	return b
}

func (b *backend) expect(t *testing.T, want []byte) {
	t.Helper()
	select {
	case got := <-b.received:
		if !bytes.Equal(got, want) {
			t.Fatalf("backend %q received %d bytes, want the %d byte ClientHello", b.server.Hostname, len(got), len(want))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("backend %q received no connection", b.server.Hostname)
	}
}

func (b *backend) expectNone(t *testing.T) {
	t.Helper()
	select {
	case <-b.received:
		t.Fatalf("backend %q unexpectedly received a connection", b.server.Hostname)
	case <-time.After(200 * time.Millisecond):
	}
}

// handle sends hello to p.Handle and waits for Handle to return after the
// client closes its end.
func handle(t *testing.T, p *TCPProxy, hello []byte) {
	t.Helper()

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Handle(server)
	}()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(hello); err != nil {
		t.Fatalf("writing ClientHello: %v", err)
	}
	go func() {
		//nolint:errcheck // drain until Handle closes the connection
		io.Copy(io.Discard, client)
	}()
	time.Sleep(100 * time.Millisecond)
	client.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

func TestHandleRoutesBySNI(t *testing.T) {
	passthrough := newBackend(t, "passthrough.example.com")
	def := newBackend(t, "default")
	p := &TCPProxy{ServerList: []*TCPServer{passthrough.server}, Default: def.server}

	hello := realClientHello(t, "passthrough.example.com")
	handle(t, p, hello)

	passthrough.expect(t, hello)
	def.expectNone(t)
}

func TestHandleRoutesPartialClientHelloBySNI(t *testing.T) {
	const host = "passthrough.example.com"
	passthrough := newBackend(t, host)
	def := newBackend(t, "default")
	p := &TCPProxy{ServerList: []*TCPServer{passthrough.server}, Default: def.server}

	hello := realClientHello(t, host)
	partial := hello[:bytes.Index(hello, []byte(host))+len(host)]
	handle(t, p, partial)

	passthrough.expect(t, partial)
	def.expectNone(t)
}

func TestHandleMalformedClientHelloFallsBackToDefault(t *testing.T) {
	passthrough := newBackend(t, "example.com")
	def := newBackend(t, "default")
	p := &TCPProxy{ServerList: []*TCPServer{passthrough.server}, Default: def.server}

	hello := buildClientHello(sniExtension(serverNameTypeHostName, []byte("example.com"), 0xFFFF, 0xFFFF))
	handle(t, p, hello)

	def.expect(t, hello)
	passthrough.expectNone(t)
}

func TestHandleMalformedClientHelloWithoutDefault(t *testing.T) {
	p := &TCPProxy{}
	handle(t, p, buildClientHello(sniExtension(serverNameTypeHostName, nil, 0xFFFF, 0xFFFF)))
}

type panicConn struct {
	net.Conn
}

func (panicConn) Read([]byte) (int, error) {
	panic("boom")
}

func TestHandleRecoversFromPanic(t *testing.T) {
	_, server := net.Pipe()
	p := &TCPProxy{}
	p.Handle(panicConn{Conn: server})
}
