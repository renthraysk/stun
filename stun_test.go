package stun

import (
	"testing"
)

var txID TxID

func TestFingerprint(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendFingerprint(m)

	if _, err := Parse(m); err != nil {
		t.Fatalf("failed: %v", err)
	}
	m[0] ^= 0x01
	if _, err := Parse(m); err != ErrFingerprint {
		t.Fatal("expected ErrFingerprint error")
	}
	// Reset first byte and muggle last byte of header
	m[0] ^= 0x01
	m[headerSize-1] ^= 0x01
	if _, err := Parse(m); err != ErrFingerprint {
		t.Fatal("expected ErrFingerprint error")
	}
}

func TestMessageIntegrity(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegrity(m, key)
	if _, err := Parse(m); err != nil {
		t.Fatalf("failed: %v", err)
	}
	m[0] ^= 0x01
	if _, err := Parse(m); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity error")
	}
	// Reset first byte and muggle last byte of header
	m[0] ^= 0x01
	m[headerSize-1] ^= 0x01
	if _, err := Parse(m); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity error")
	}
}

func TestMessageIntegritySHA256(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)

	if _, err := Parse(m); err != nil {
		t.Fatalf("failed: %v", err)
	}
	m[0] ^= 0x01
	if _, err := Parse(m); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
	// Reset first byte and muggle last byte of header
	m[0] ^= 0x01
	m[headerSize-1] ^= 0x01
	if _, err := Parse(m); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestMessageIntegritySHA256Fingerprint(t *testing.T) {
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)
	m = appendFingerprint(m)
	if _, err := Parse(m); err != nil {
		t.Fatalf("failed: %v", err)
	}
	m[0] ^= 0x01
	if _, err := Parse(m); err == nil {
		t.Fatalf("expected failure")
	}
	// Reset first byte and muggle last byte of header
	m[0] ^= 0x01
	m[headerSize-1] ^= 0x01
	if _, err := Parse(m); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestMessageIntegrityShouldBeOnlyFollowedByFingerprint(t *testing.T) {
	// Only attribute allowed after a MessageIntegrity is Fingerprint
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegrity(m, key)
	m = appendSoftware(m, "test")
	if _, err := Parse(m); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity err")
	}
}

func TestMessageIntegritySHA256ShouldBeOnlyFollowedByFingerprint(t *testing.T) {
	// Only attribute allowed after a MessageIntegritySHA256 is Fingerprint
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)
	m = appendSoftware(m, "test")
	if _, err := Parse(m); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestFingerprintShouldBeLastAttribute(t *testing.T) {
	// Fingerprint should be last attribute
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendFingerprint(m)
	m = appendMessageIntegritySHA256(m, key)
	if _, err := Parse(m); err == nil {
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
