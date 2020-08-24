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
	m[len(m)-1] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("Failed")
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
		t.Fatalf("Failed")
	}
}

func TestMessageIntegritySHA256(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)

	if _, ok := Parse(m); !ok {
		t.Fatalf("failed")
	}
	m[0] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("Failed")
	}
}

func TestMessageIntegritySHA256Fingerprint(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)
	m = appendFingerprint(m)

	if _, ok := Parse(m); !ok {
		t.Fatalf("failed")
	}
	m[0] ^= 0x01
	if _, ok := Parse(m); ok {
		t.Fatalf("Failed")
	}
}

func TestFingerprintMessageIntegritySHA256(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendFingerprint(m)
	m = appendMessageIntegritySHA256(m, key)

	if _, ok := Parse(m); ok {
		t.Fatalf("should have failed")
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
