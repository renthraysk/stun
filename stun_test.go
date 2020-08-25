package stun

import (
	"testing"
)

var txID TxID

func TestFingerprint(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendFingerprint(m)

	if _, ok := Parse(m); !ok {
		t.Fatalf("failed")
	}
	m[0] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
	// Reset first byte and muggle last byte of header
	m[0] ^= 0x01
	m[headerSize-1] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
}

func TestMessageIntegrity(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegrity(m, key)
	if _, ok := Parse(m); !ok {
		t.Fatalf("failed")
	}
	m[0] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
	// Reset first byte and muggle last byte of header
	m[0] ^= 0x01
	m[headerSize-1] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
}

func TestMessageIntegritySHA256(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)

	m[0] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
	// Reset first byte and muggle last byte of header
	m[0] ^= 0x01
	m[headerSize-1] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
}

func TestMessageIntegritySoftware(t *testing.T) {
	// Only attribute allowed after a MessageIntegrity is Fingerprint
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegrity(m, key)
	m = appendSoftware(m, "test")
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
}

func TestMessageIntegritySHA256Software(t *testing.T) {
	// Only attribute allowed after a MessageIntegritySHA256 is Fingerprint
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)
	m = appendSoftware(m, "test")
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
}

func TestFingerprintMessageIntegritySHA256(t *testing.T) {
	// Fingerprint should be last attribute
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendFingerprint(m)
	m = appendMessageIntegritySHA256(m, key)
	if _, ok := Parse(m); ok {
		t.Fatalf("expected failure")
	}
}

func BenchmarkMessageFingerprint(b *testing.B) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendFingerprint(m)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(m)
	}
}

func BenchmarkMessageIntegrity(b *testing.B) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegrity(m, key)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(m)
	}
}

func BenchmarkMessageIntegritySHA256(b *testing.B) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(m)
	}
}
