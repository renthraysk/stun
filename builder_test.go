package stun

import (
	"net"
	"testing"
)

var testTxID TxID
var testKey = []byte{16: 0}

func TestBuilderMessageIntegrityMessageIntegritySHA256Fingerprint(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AddMessageIntegrity(testKey)
	b.AddMessageIntegritySHA256(testKey)
	b.AddFingerprint()
	if _, err := b.Build(); err != nil {
		t.Fatalf("expected no error got %v", err)
	}
}

func TestBuilderIPAddressLengthValidation(t *testing.T) {
	tests := []struct {
		ip  []byte
		err error
	}{
		{ip: net.IP{127}, err: ErrInvalidIPAddress},
		{ip: net.IP{127, 0, 0, 1}, err: nil},
		{ip: net.IP{0xFF, 127, 0, 0, 1}, err: ErrInvalidIPAddress},
		{ip: net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, err: nil},
		{ip: net.IP{0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, err: ErrInvalidIPAddress},
	}

	var m Message

	for _, tt := range tests {
		{
			b := New(TypeBindingRequest, testTxID)
			b.SetXorMappingAddress(&net.UDPAddr{IP: tt.ip, Port: 1234})
			raw, err := b.Build()
			if err != tt.err {
				t.Fatalf("build: expected error %v, got %v", tt.err, err)
			}
			if err == nil {
				if err := m.Unmarshal(raw, testKey); err != nil {
					t.Fatalf("parse error: %v", err)
				}
			}
		}
		{
			b := New(TypeBindingRequest, testTxID)
			b.SetMappingAddress(&net.UDPAddr{IP: tt.ip, Port: 1234})
			raw, err := b.Build()
			if err != tt.err {
				t.Fatalf("build: expected error %v, got %v", tt.err, err)
			}
			if err == nil {
				if err := m.Unmarshal(raw, testKey); err != nil {
					t.Fatalf("parse error: %v", err)
				}
			}
		}
		{
			b := New(TypeBindingRequest, testTxID)
			b.SetAlternateServer(tt.ip, 1234)
			raw, err := b.Build()
			if err != tt.err {
				t.Fatalf("build: expected error %v, got %v", tt.err, err)
			}
			if err == nil {
				if err := m.Unmarshal(raw, testKey); err != nil {
					t.Fatalf("parse error: %v", err)
				}
			}
		}
	}
}
