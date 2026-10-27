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

package tcpproxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// startProxy accepts a single connection on a new listener and hands it to
// p.Handle. The returned channel is closed once Handle returns.
func startProxy(t *testing.T, p *TCPProxy) (addr string, done <-chan struct{}) {
	t.Helper()
	l := listen(t)
	ch := make(chan struct{})
	go func() {
		conn, err := l.Accept()
		if err != nil {
			close(ch)
			return
		}
		p.Handle(conn)
		close(ch)
	}()
	return l.Addr().String(), ch
}

func backendServer(t *testing.T) *TCPServer {
	t.Helper()
	l := listen(t)
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected address type %T", l.Addr())
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				//nolint:errcheck // drain until the proxy closes the connection
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return &TCPServer{Hostname: "backend", IP: "127.0.0.1", Port: addr.Port}
}

func waitDone(t *testing.T, done <-chan struct{}, within time.Duration, msg string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatal(msg)
	}
}

func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("expected the proxy to close the connection, got %v", err)
	}
}

func TestHandleClosesSilentConnection(t *testing.T) {
	p := &TCPProxy{Default: backendServer(t), HandshakeTimeout: 200 * time.Millisecond}
	addr, done := startProxy(t, p)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	start := time.Now()
	waitDone(t, done, 2*time.Second, "Handle did not return for a client that never sent data")
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("Handle returned after %v, before the handshake timeout", elapsed)
	}
	assertClosed(t, client)
}

func TestHandleClosesIdleProxiedConnection(t *testing.T) {
	p := &TCPProxy{
		Default:          backendServer(t),
		HandshakeTimeout: time.Second,
		IdleTimeout:      300 * time.Millisecond,
	}
	addr, done := startProxy(t, p)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("not a client hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitDone(t, done, 3*time.Second, "Handle did not return for an idle proxied connection")
	assertClosed(t, client)
}

func TestHandleKeepsConnectionWithOneWayTraffic(t *testing.T) {
	const chunks = 20
	const interval = 50 * time.Millisecond

	l := listen(t)
	backendAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected address type %T", l.Addr())
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < chunks; i++ {
			time.Sleep(interval)
			if _, err := conn.Write([]byte{'x'}); err != nil {
				return
			}
		}
	}()

	p := &TCPProxy{
		Default:          &TCPServer{Hostname: "backend", IP: "127.0.0.1", Port: backendAddr.Port},
		HandshakeTimeout: time.Second,
		IdleTimeout:      300 * time.Millisecond,
	}
	addr, done := startProxy(t, p)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	received, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(received) != chunks {
		t.Fatalf("expected %d bytes while the server kept sending, got %d", chunks, len(received))
	}
	waitDone(t, done, 2*time.Second, "Handle did not return after the backend closed")
}

// deadlineIgnoringConn mimics wrappers (like the PROXY protocol listener)
// that reset the read deadline set by the caller.
type deadlineIgnoringConn struct {
	net.Conn
}

func (deadlineIgnoringConn) SetReadDeadline(time.Time) error { return nil }

func TestReadWithTimeoutClosesWhenDeadlineIsIgnored(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := readWithTimeout(deadlineIgnoringConn{server}, make([]byte, 16), 100*time.Millisecond)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected an error for a silent connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readWithTimeout did not return for a silent connection")
	}
}

func TestReadWithTimeoutReturnsData(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		//nolint:errcheck // test writer
		client.Write([]byte("hello"))
	}()

	buf := make([]byte, 16)
	n, err := readWithTimeout(server, buf, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("unexpected data %q", buf[:n])
	}
}
