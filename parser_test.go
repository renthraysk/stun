package stun

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

var txID TxID

// setAttrSize fix the attrsSize attribute
func setAttrSize(m []byte) {
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize))
}

func TestParseFingerprint(t *testing.T) {

	b := New(TypeBindingRequest, txID)
	b.AddFingerprint()
	raw, err := b.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	var p Parser
	var m Message

	if err := p.Parse(&m, raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrFingerprint {
		t.Fatal("expected ErrFingerprint error")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrFingerprint {
		t.Fatal("expected ErrFingerprint error")
	}
}

func TestParseMessageIntegrity(t *testing.T) {

	b := New(TypeBindingRequest, txID)
	b.SetPassword(testPassword)
	b.AddMessageIntegrity()
	raw, err := b.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	var p Parser
	var m Message

	if err := p.Parse(&m, raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity error")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity error")
	}
}

func TestParseMessageIntegritySHA256(t *testing.T) {
	b := New(TypeBindingRequest, txID)
	b.SetPassword(testPassword)
	b.AddMessageIntegritySHA256()
	raw, err := b.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	var p Parser
	var m Message
	if err := p.Parse(&m, raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestParseMessageIntegritySHA256Fingerprint(t *testing.T) {
	b := New(TypeBindingRequest, txID)
	b.SetPassword(testPassword)
	b.AddMessageIntegritySHA256()
	b.AddFingerprint()
	raw, err := b.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	var p Parser
	var m Message

	if err := p.Parse(&m, raw); err != nil {
		t.Fatalf("failed: %v", err)
	}
	raw[0] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected messageintegritysha256 check failure")
	}
	// Reset first byte and muggle last byte of header
	raw[0] ^= 0x01
	raw[headerSize-1] ^= 0x01
	if err := p.Parse(&m, raw); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestParseMessageIntegrityFingerprintIsAllowed(t *testing.T) {
	// Only attribute allowed after a MessageIntegrity is Fingerprint
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegrity(raw, testKey)
	raw = appendFingerprint(raw)
	setAttrSize(raw)

	var p Parser
	var m Message

	if err := p.Parse(&m, raw); err != nil {
		t.Fatalf("allowed attribute sequence failed: %v", err)
	}
}
func TestParseMessageIntegrityFollowedByMessageIntegrity256IsAllowed(t *testing.T) {
	// MessageIntegrity followed by MessageIntegrity256 is allowed
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegrity(raw, testKey)
	raw = appendMessageIntegritySHA256(raw, testKey, sha256.Size)
	setAttrSize(raw)
	var p Parser
	var m Message
	if err := p.Parse(&m, raw); err != nil {
		t.Fatalf("allowed attribute sequence failed: %v", err)
	}
}

func TestParseMessageIntegrityShouldBeOnlyFollowedByFingerprint(t *testing.T) {
	// Only attribute allowed after a MessageIntegrity is Fingerprint
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegrity(raw, testKey)
	raw = appendSoftware(raw, "test")
	setAttrSize(raw)
	var p Parser
	var m Message
	if err := p.Parse(&m, raw); err != ErrInvalidAttributeSequence {
		t.Fatal("invalid attribute sequence did not cause expected invalid attribute sequence error")
	}
}

func TestParseMessageIntegritySHA256ShouldBeOnlyFollowedByFingerprint(t *testing.T) {
	// Only attribute allowed after a MessageIntegritySHA256 is Fingerprint
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendMessageIntegritySHA256(raw, testKey, sha256.Size)
	raw = appendSoftware(raw, "test")
	setAttrSize(raw)
	var p Parser
	var m Message
	if err := p.Parse(&m, raw); err != ErrInvalidAttributeSequence {
		t.Fatal("invalid attribute sequence did not cause expected invalid attribute sequence error")
	}
}

func TestParseFingerprintShouldBeLastAttribute(t *testing.T) {
	// Fingerprint should be last attribute
	raw := newHeader(nil, TypeBindingRequest, txID)
	raw = appendFingerprint(raw)
	raw = appendMessageIntegritySHA256(raw, testKey, sha256.Size)
	setAttrSize(raw)
	var p Parser
	var m Message
	if err := p.Parse(&m, raw); err != ErrInvalidAttributeSequence {
		t.Fatalf("invalid attribute sequence did not cause expected invalid attribute sequence error")
	}
}
