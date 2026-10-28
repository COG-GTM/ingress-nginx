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
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// realClientHello returns the first TLS record written by crypto/tls when
// dialing serverName.
func realClientHello(t testing.TB, serverName string) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer server.Close()

	go func() {
		//nolint:gosec // only the ClientHello is captured, no handshake completes
		c := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		//nolint:errcheck // the handshake fails once the server side closes
		c.Handshake()
		client.Close()
	}()

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, recordHeaderLength)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("reading record header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("reading record body: %v", err)
	}
	record := make([]byte, 0, len(header)+len(body))
	record = append(record, header...)
	return append(record, body...)
}

func u16(n int) []byte {
	return []byte{byte(n >> 8), byte(n)}
}

func u24(n int) []byte {
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}

// buildClientHello assembles a ClientHello record around the given
// extensions block. Length fields are computed from the actual contents.
func buildClientHello(extensions []byte) []byte {
	hello := []byte{0x03, 0x03}
	hello = append(hello, make([]byte, clientHelloRandomLength)...)
	hello = append(hello,
		0x00,                   // empty session id
		0x00, 0x02, 0x13, 0x01, // one cipher suite
		0x01, 0x00, // null compression
	)
	if extensions != nil {
		hello = append(hello, u16(len(extensions))...)
		hello = append(hello, extensions...)
	}

	handshake := append([]byte{handshakeTypeClientHello}, u24(len(hello))...)
	handshake = append(handshake, hello...)

	record := []byte{recordTypeHandshake, 0x03, 0x01}
	record = append(record, u16(len(handshake))...)
	return append(record, handshake...)
}

func sniExtension(nameType byte, name []byte, nameLen, listLen int) []byte {
	entry := append([]byte{nameType}, u16(nameLen)...)
	entry = append(entry, name...)
	list := append(u16(listLen), entry...)
	ext := append(u16(extensionServerName), u16(len(list))...)
	return append(ext, list...)
}

func validSNI(name string) []byte {
	return sniExtension(serverNameTypeHostName, []byte(name), len(name), len(name)+3)
}

func TestGetHostnameRealClientHello(t *testing.T) {
	for _, host := range []string{"example.com", "a.b.c.passthrough.example.org"} {
		data := realClientHello(t, host)
		got, err := getHostname(data)
		if err != nil {
			t.Fatalf("getHostname(%q): unexpected error %v", host, err)
		}
		if got != host {
			t.Fatalf("getHostname: got %q, want %q", got, host)
		}
	}
}

func TestGetHostname(t *testing.T) {
	otherExt := append(u16(0x000a), u16(4)...)
	otherExt = append(otherExt, 0x00, 0x02, 0x00, 0x1d)

	inflatedName := buildClientHello(sniExtension(serverNameTypeHostName, []byte("example.com"), 0xFFFF, 0xFFFF))
	inflatedExt := buildClientHello(validSNI("example.com"))
	// extensions block length (right after the null compression method)
	extLenOffset := recordHeaderLength + handshakeHeaderLength + 2 + clientHelloRandomLength + 1 + 4 + 2
	binary.BigEndian.PutUint16(inflatedExt[extLenOffset:], 0xFFFF)
	inflatedHandshake := buildClientHello(validSNI("example.com"))
	copy(inflatedHandshake[recordHeaderLength+1:], u24(0xFFFFFF))

	// a record body that claims more bytes than were received, followed by
	// zero padding as in the old 16 KiB buffer
	padded := append(buildClientHello(sniExtension(serverNameTypeHostName, []byte("ex"), 0x4000, 0x4000)), make([]byte, 16384)...)

	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr error
	}{
		{name: "valid", data: buildClientHello(validSNI("example.com")), want: "example.com"},
		{name: "sni after other extension", data: buildClientHello(append(otherExt, validSNI("foo.bar")...)), want: "foo.bar"},
		{name: "empty", data: nil, wantErr: errTruncated},
		{name: "short header", data: []byte{recordTypeHandshake, 0x03}, wantErr: errTruncated},
		{name: "not handshake", data: []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}, wantErr: errNotHandshake},
		{name: "plain http", data: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), wantErr: errNotHandshake},
		{name: "not client hello", data: []byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}, wantErr: errNotClientHello},
		{name: "no extensions", data: buildClientHello(nil), wantErr: errNoServerName},
		{name: "no sni", data: buildClientHello(otherExt), wantErr: errNoServerName},
		{name: "inflated server_name length", data: inflatedName, wantErr: errTruncated},
		{name: "extensions longer than input", data: inflatedExt, want: "example.com"},
		{name: "handshake longer than input", data: inflatedHandshake, want: "example.com"},
		{name: "length reaching into zero padding", data: padded, wantErr: errTruncated},
		{name: "empty host name", data: buildClientHello(validSNI("")), wantErr: errInvalidHostname},
		{name: "control char in host name", data: buildClientHello(validSNI("exa\x00mple.com")), wantErr: errInvalidHostname},
		{name: "non host_name type only", data: buildClientHello(sniExtension(0x01, []byte("x"), 1, 4)), wantErr: errNoServerName},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getHostname(tc.data)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error: got %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("hostname: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetHostnameAllTruncations(t *testing.T) {
	const host = "passthrough.example.com"
	data := realClientHello(t, host)
	sniEnd := bytes.Index(data, []byte(host)) + len(host)
	for i := 0; i <= len(data); i++ {
		got, err := getHostname(data[:i])
		switch {
		case i < sniEnd && err == nil:
			t.Fatalf("getHostname returned %q for %d bytes, before the server_name ends at %d", got, i, sniEnd)
		case i >= sniEnd && (err != nil || got != host):
			t.Fatalf("getHostname on the first %d of %d bytes: got %q, %v; want %q", i, len(data), got, err, host)
		}
	}
}

func FuzzGetHostname(f *testing.F) {
	f.Add(realClientHello(f, "example.com"))
	f.Add(buildClientHello(validSNI("example.com")))
	f.Add(buildClientHello(sniExtension(serverNameTypeHostName, []byte("example.com"), 0xFFFF, 0xFFFF)))
	f.Add([]byte{recordTypeHandshake, 0x03, 0x01, 0xFF, 0xFF, handshakeTypeClientHello, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		host, err := getHostname(data)
		if err == nil && (host == "" || len(host) > maxHostnameLength) {
			t.Fatalf("invalid hostname %q returned without error", host)
		}
	})
}
