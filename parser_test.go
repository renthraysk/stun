package stun

import (
	"crypto/sha256"
	"testing"
)

var txID TxID

func TestRFC5769(t *testing.T) {
	t.Skip("@TODO key generation")

	in := []byte("\x00\x01\x00\x58" +
		"\x21\x12\xa4\x42" +
		"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
		"\x80\x22\x00\x10" +
		"STUN test client" +
		"\x00\x24\x00\x04" +
		"\x6e\x00\x01\xff" +
		"\x80\x29\x00\x08" +
		"\x93\x2f\xf9\xb1\x51\x26\x3b\x36" +
		"\x00\x06\x00\x09" +
		"\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20" +
		"\x00\x08\x00\x14" +
		"\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5" +
		"\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2" +
		"\x80\x28\x00\x04" +
		"\xe5\x7a\x3b\xcf")

	var m Message

	if err := m.Unmarshal(in); err != nil {
		t.Fatalf("parse failed: %v", err)
	}
}

func TestParseFingerprint(t *testing.T) {

	b := New(TypeBindingRequest, txID)
	b.AppendFingerprint()
	raw, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	var m Message

	if err := m.Unmarshal(raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrFingerprint {
		t.Fatal("expected ErrFingerprint error")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrFingerprint {
		t.Fatal("expected ErrFingerprint error")
	}
}

func TestParseMessageIntegrity(t *testing.T) {

	b := New(TypeBindingRequest, txID)
	b.AppendMessageIntegrity(key)
	raw, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	var m Message

	if err := m.Unmarshal(raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity error")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity error")
	}
}

func TestParseMessageIntegritySHA256(t *testing.T) {
	b := New(TypeBindingRequest, txID)
	b.AppendMessageIntegritySHA256(key)
	raw, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	var m Message
	if err := m.Unmarshal(raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestParseMessageIntegritySHA256Fingerprint(t *testing.T) {
	b := New(TypeBindingRequest, txID)
	b.AppendMessageIntegritySHA256(key)
	b.AppendFingerprint()
	raw, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	var m Message

	if err := m.Unmarshal(raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected messageintegritysha256 check failure")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := m.Unmarshal(raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestParseMessageIntegrityFingerprintIsAllowed(t *testing.T) {
	// Only attribute allowed after a MessageIntegrity is Fingerprint
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegrity(raw, key)
	raw = appendFingerprint(raw)
	setAttrSize(raw)

	var m Message

	if err := m.Unmarshal(raw); err != nil {
		t.Fatalf("allowed attribute sequence failed: %v", err)
	}
}
func TestParseMessageIntegrityFollowedByMessageIntegrity256IsAllowed(t *testing.T) {
	// MessageIntegrity followed by MessageIntegrity256 is allowed
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegrity(raw, key)
	raw = appendMessageIntegritySHA256(raw, key, sha256.Size)
	setAttrSize(raw)

	var m Message
	if err := m.Unmarshal(raw); err != nil {
		t.Fatalf("allowed attribute sequence failed: %v", err)
	}
}

func TestParseMessageIntegrityShouldBeOnlyFollowedByFingerprint(t *testing.T) {
	// Only attribute allowed after a MessageIntegrity is Fingerprint
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegrity(raw, key)
	raw = appendSoftware(raw, "test")
	setAttrSize(raw)

	var m Message
	if err := m.Unmarshal(raw); err != ErrInvalidAttributeSequence {
		t.Fatal("invalid attribute sequence did not cause expected invalid attribute sequence error")
	}
}

func TestParseMessageIntegritySHA256ShouldBeOnlyFollowedByFingerprint(t *testing.T) {
	// Only attribute allowed after a MessageIntegritySHA256 is Fingerprint
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegritySHA256(raw, key, sha256.Size)
	raw = appendSoftware(raw, "test")
	setAttrSize(raw)
	var m Message
	if err := m.Unmarshal(raw); err != ErrInvalidAttributeSequence {
		t.Fatal("invalid attribute sequence did not cause expected invalid attribute sequence error")
	}
}

func TestParseFingerprintShouldBeLastAttribute(t *testing.T) {
	// Fingerprint should be last attribute
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendFingerprint(raw)
	raw = appendMessageIntegritySHA256(raw, key, sha256.Size)
	setAttrSize(raw)

	var m Message
	if err := m.Unmarshal(raw); err != ErrInvalidAttributeSequence {
		t.Fatalf("invalid attribute sequence did not cause expected invalid attribute sequence error")
	}
}

func BenchmarkParseMessageFingerprint(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AppendFingerprint()
	raw, err := bb.Bytes()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var m Message

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Unmarshal(raw)
	}
}

func BenchmarkParseMessageIntegrity(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AppendMessageIntegrity(key)
	raw, err := bb.Bytes()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var m Message

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Unmarshal(raw)
	}
}

func BenchmarkParseMessageIntegritySHA256(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AppendMessageIntegritySHA256(key)
	raw, err := bb.Bytes()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var m Message
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Unmarshal(raw)
	}
}
