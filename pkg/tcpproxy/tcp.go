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

package tcpproxy

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/klog/v2"

	"pault.ag/go/sniff/parser"
)

// TCPServer describes a server that works in passthrough mode.
type TCPServer struct {
	Hostname      string
	IP            string
	Port          int
	ProxyProtocol bool
}

const (
	// DefaultHandshakeTimeout is used when TCPProxy.HandshakeTimeout is not set.
	DefaultHandshakeTimeout = 5 * time.Second
	// DefaultIdleTimeout is used when TCPProxy.IdleTimeout is not set.
	DefaultIdleTimeout = 600 * time.Second
)

// TCPProxy describes the passthrough servers and a default as catch all.
type TCPProxy struct {
	ServerList []*TCPServer
	Default    *TCPServer

	// handshakeTimeout bounds how long a client may take to send the
	// initial TLS ClientHello and how long dialing the backend may take.
	handshakeTimeout atomic.Int64
	// idleTimeout closes a proxied connection when no data is transferred
	// in either direction for this long.
	idleTimeout atomic.Int64
}

// SetTimeouts updates the handshake and idle timeouts used by new
// connections. Non-positive values select the defaults.
func (p *TCPProxy) SetTimeouts(handshake, idle time.Duration) {
	p.handshakeTimeout.Store(int64(handshake))
	p.idleTimeout.Store(int64(idle))
}

func (p *TCPProxy) getHandshakeTimeout() time.Duration {
	if d := time.Duration(p.handshakeTimeout.Load()); d > 0 {
		return d
	}
	return DefaultHandshakeTimeout
}

func (p *TCPProxy) getIdleTimeout() time.Duration {
	if d := time.Duration(p.idleTimeout.Load()); d > 0 {
		return d
	}
	return DefaultIdleTimeout
}

// Get returns the TCPServer to use for a given host.
func (p *TCPProxy) Get(host string) *TCPServer {
	if p.ServerList == nil {
		return p.Default
	}

	for _, s := range p.ServerList {
		if s.Hostname == host {
			return s
		}
	}

	return p.Default
}

// Handle reads enough information from the connection to extract the hostname
// and open a connection to the passthrough server.
func (p *TCPProxy) Handle(conn net.Conn) {
	defer conn.Close()
	// See: https://www.ibm.com/docs/en/ztpf/1.1.0.15?topic=sessions-ssl-record-format
	data := make([]byte, 16384)

	length, err := readWithTimeout(conn, data, p.getHandshakeTimeout())
	if err != nil {
		klog.V(4).ErrorS(err, "Error reading data from the connection")
		return
	}

	proxy := p.Default
	hostname, err := parser.GetHostname(data)
	if err == nil {
		klog.V(4).InfoS("TLS Client Hello", "host", hostname)
		proxy = p.Get(hostname)
	}

	if proxy == nil {
		klog.V(4).InfoS("There is no configured proxy for SSL connections.")
		return
	}

	hostPort := net.JoinHostPort(proxy.IP, fmt.Sprintf("%v", proxy.Port))
	klog.V(4).InfoS("passing to", "hostport", hostPort)
	clientConn, err := net.DialTimeout("tcp", hostPort, p.getHandshakeTimeout())
	if err != nil {
		klog.V(4).ErrorS(err, "error dialing proxy", "ip", proxy.IP, "port", proxy.Port, "hostname", proxy.Hostname)
		return
	}
	defer clientConn.Close()

	if proxy.ProxyProtocol {
		// write out the Proxy Protocol header
		localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
		if !ok {
			klog.Errorf("unexpected type: %T", conn.LocalAddr())
		}
		remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			klog.Errorf("unexpected type: %T", conn.RemoteAddr())
		}
		protocol := "UNKNOWN"
		if remoteAddr.IP.To4() != nil {
			protocol = "TCP4"
		} else if remoteAddr.IP.To16() != nil {
			protocol = "TCP6"
		}
		proxyProtocolHeader := fmt.Sprintf("PROXY %s %s %s %d %d\r\n", protocol, remoteAddr.IP.String(), localAddr.IP.String(), remoteAddr.Port, localAddr.Port)
		klog.V(4).InfoS("Writing Proxy Protocol", "header", proxyProtocolHeader)
		_, err = fmt.Fprint(clientConn, proxyProtocolHeader)
	}
	if err != nil {
		klog.ErrorS(err, "Error writing Proxy Protocol header")
		clientConn.Close()
	} else {
		_, err = clientConn.Write(data[:length])
		if err != nil {
			klog.Errorf("Error writing the first 4k of proxy data: %v", err)
			clientConn.Close()
		}
	}

	pipe(clientConn, conn, p.getIdleTimeout())
}

// readWithTimeout performs a single Read bounded by timeout. Besides the read
// deadline, the connection is closed when the timer fires, because wrappers
// such as the PROXY protocol listener reset the deadline after parsing the
// header.
func readWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) (int, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	timer := time.AfterFunc(timeout, func() {
		conn.Close()
	})
	n, err := conn.Read(buf)
	if !timer.Stop() && err == nil {
		err = errors.New("timeout reading from the connection")
	}
	if err != nil {
		return n, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return n, err
	}
	return n, nil
}

var copyBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

// pipe copies data in both directions until one side is closed or no data has
// been transferred in either direction for idleTimeout.
func pipe(client, server net.Conn, idleTimeout time.Duration) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	doCopy := func(dst, src net.Conn, cancel chan<- bool) {
		defer func() { cancel <- true }()

		bufp, ok := copyBufferPool.Get().(*[]byte)
		if !ok {
			return
		}
		defer copyBufferPool.Put(bufp)
		buf := *bufp

		for {
			deadline := time.Unix(0, lastActivity.Load()).Add(idleTimeout)
			if !deadline.After(time.Now()) {
				return
			}
			if err := src.SetReadDeadline(deadline); err != nil {
				return
			}

			n, err := src.Read(buf)
			if n > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if err := dst.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
					return
				}
				if _, err := dst.Write(buf[:n]); err != nil {
					return
				}
				lastActivity.Store(time.Now().UnixNano())
			}
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					// the other direction may still be active
					continue
				}
				return
			}
		}
	}

	cancel := make(chan bool, 2)

	go doCopy(server, client, cancel)
	go doCopy(client, server, cancel)

	<-cancel
}
