package stun

import "testing"

var testTxID TxID
var testKey = []byte{16: 0}

func TestBuilderAttributesAfterFingerprint(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendFingerprint()
	b.AppendSoftware("test")
	if _, err := b.Bytes(); err != ErrAttrAppendedAfterMessageIntegrity {
		t.Fatalf("expected ErrAttrAppendedAfterMessageIntegrity got %v", err)
	}
}

func TestBuilderAttributesAfterMessageIntegrity(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendMessageIntegrity(testKey)
	b.AppendSoftware("test")
	if _, err := b.Bytes(); err != ErrAttrAppendedAfterMessageIntegrity {
		t.Fatalf("expected ErrAttrAppendedAfterMessageIntegrity got %v", err)
	}
}

func TestBuilderAttributesAfterMessageIntegritySHA256(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendMessageIntegritySHA256(testKey)
	b.AppendSoftware("test")
	if _, err := b.Bytes(); err != ErrAttrAppendedAfterMessageIntegrity {
		t.Fatalf("expected ErrAttrAppendedAfterMessageIntegrity got %v", err)
	}
}

func TestBuilderMessageIntegrityAfterMessageIntegritySHA256(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendMessageIntegritySHA256(testKey)
	b.AppendMessageIntegrity(testKey)
	if _, err := b.Bytes(); err != ErrAttrAppendedAfterMessageIntegrity {
		t.Fatalf("expected ErrAttrAppendedAfterMessageIntegrity got %v", err)
	}
}

func TestBuilderMessageIntegrityMessageIntegritySHA256Fingerprint(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendMessageIntegrity(testKey)
	b.AppendMessageIntegritySHA256(testKey)
	b.AppendFingerprint()
	if _, err := b.Bytes(); err != nil {
		t.Fatalf("expected no error got %v", err)
	}
}
