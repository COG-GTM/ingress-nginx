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
	"errors"
)

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	extensionServerName      = 0x0000
	serverNameTypeHostName   = 0x00
	recordHeaderLength       = 5
	handshakeHeaderLength    = 4
	clientHelloRandomLength  = 32
	maxHostnameLength        = 255
)

var (
	errNotHandshake    = errors.New("not a TLS handshake record")
	errNotClientHello  = errors.New("not a TLS ClientHello")
	errTruncated       = errors.New("truncated TLS ClientHello")
	errNoServerName    = errors.New("no server_name extension in TLS ClientHello")
	errInvalidHostname = errors.New("invalid server_name in TLS ClientHello")
)

// byteReader consumes length-prefixed fields from untrusted input. Every
// read is checked against the remaining bytes, so malformed lengths yield
// errTruncated instead of a slice-bounds panic.
type byteReader []byte

func (r *byteReader) skip(n int) bool {
	if n < 0 || len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *byteReader) bytes(n int) ([]byte, bool) {
	if n < 0 || len(*r) < n {
		return nil, false
	}
	b := (*r)[:n]
	*r = (*r)[n:]
	return b, true
}

func (r *byteReader) uint8() (int, bool) {
	b, ok := r.bytes(1)
	if !ok {
		return 0, false
	}
	return int(b[0]), true
}

func (r *byteReader) uint16() (int, bool) {
	b, ok := r.bytes(2)
	if !ok {
		return 0, false
	}
	return int(b[0])<<8 | int(b[1]), true
}

func (r *byteReader) uint24() (int, bool) {
	b, ok := r.bytes(3)
	if !ok {
		return 0, false
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2]), true
}

// prefixed reads a length prefix of the given width (1, 2 or 3 bytes) and
// returns the bytes it covers.
func (r *byteReader) prefixed(width int) (byteReader, bool) {
	var n int
	var ok bool
	switch width {
	case 1:
		n, ok = r.uint8()
	case 2:
		n, ok = r.uint16()
	case 3:
		n, ok = r.uint24()
	}
	if !ok {
		return nil, false
	}
	b, ok := r.bytes(n)
	return b, ok
}

// getHostname extracts the SNI host_name from the TLS ClientHello at the
// start of data. data must contain only bytes received from the peer.
// It never panics on malformed input.
func getHostname(data []byte) (string, error) {
	r := byteReader(data)

	header, ok := r.bytes(recordHeaderLength)
	if !ok {
		return "", errTruncated
	}
	if header[0] != recordTypeHandshake {
		return "", errNotHandshake
	}
	recordLength := int(header[3])<<8 | int(header[4])
	if len(r) > recordLength {
		r = r[:recordLength]
	}

	handshakeType, ok := r.uint8()
	if !ok {
		return "", errTruncated
	}
	if handshakeType != handshakeTypeClientHello {
		return "", errNotClientHello
	}
	hello, ok := r.prefixed(3)
	if !ok {
		return "", errTruncated
	}

	// legacy_version, random
	if !hello.skip(2 + clientHelloRandomLength) {
		return "", errTruncated
	}
	// legacy_session_id, cipher_suites, legacy_compression_methods
	for _, width := range []int{1, 2, 1} {
		if _, ok := hello.prefixed(width); !ok {
			return "", errTruncated
		}
	}
	if len(hello) == 0 {
		return "", errNoServerName
	}

	extensions, ok := hello.prefixed(2)
	if !ok {
		return "", errTruncated
	}
	for len(extensions) > 0 {
		extType, ok := extensions.uint16()
		if !ok {
			return "", errTruncated
		}
		extData, ok := extensions.prefixed(2)
		if !ok {
			return "", errTruncated
		}
		if extType != extensionServerName {
			continue
		}
		return parseServerName(extData)
	}

	return "", errNoServerName
}

func parseServerName(ext byteReader) (string, error) {
	names, ok := ext.prefixed(2)
	if !ok {
		return "", errTruncated
	}
	for len(names) > 0 {
		nameType, ok := names.uint8()
		if !ok {
			return "", errTruncated
		}
		name, ok := names.prefixed(2)
		if !ok {
			return "", errTruncated
		}
		if nameType != serverNameTypeHostName {
			continue
		}
		if len(name) == 0 || len(name) > maxHostnameLength {
			return "", errInvalidHostname
		}
		for _, c := range name {
			if c <= 0x20 || c >= 0x7f {
				return "", errInvalidHostname
			}
		}
		return string(name), nil
	}
	return "", errNoServerName
}
