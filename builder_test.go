package stun

import "testing"

var testTxID TxID
var testKey = []byte{16: 0}

func TestBuilderAttributesAfterFingerprint(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendFingerprint()
	b.AppendSoftware("test")
	if _, err := b.Bytes(); err != ErrAttrInvalidAttributeAppend {
		t.Fatalf("expected ErrAttrInvalidAttributeAppend got %v", err)
	}
}

func TestBuilderAttributesAfterMessageIntegrity(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendMessageIntegrity(testKey)
	b.AppendSoftware("test")
	if _, err := b.Bytes(); err != ErrAttrInvalidAttributeAppend {
		t.Fatalf("expected ErrAttrInvalidAttributeAppend got %v", err)
	}
}

func TestBuilderAttributesAfterMessageIntegritySHA256(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendMessageIntegritySHA256(testKey)
	b.AppendSoftware("test")
	if _, err := b.Bytes(); err != ErrAttrInvalidAttributeAppend {
		t.Fatalf("expected ErrAttrInvalidAttributeAppend got %v", err)
	}
}

func TestBuilderMessageIntegrityAfterMessageIntegritySHA256(t *testing.T) {
	b := New(TypeBindingRequest, testTxID)
	b.AppendMessageIntegritySHA256(testKey)
	b.AppendMessageIntegrity(testKey)
	if _, err := b.Bytes(); err != ErrAttrInvalidAttributeAppend {
		t.Fatalf("expected ErrAttrInvalidAttributeAppend got %v", err)
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

func TestBuilderTruncatedMessageIntegritySHA256(t *testing.T) {
	tests := []struct {
		n   int
		err error
	}{
		{n: 0, err: ErrInvalidMessageIntegritySHA256Length},
		{n: 15, err: ErrInvalidMessageIntegritySHA256Length},
		{n: 16, err: nil},
		{n: 17, err: ErrInvalidMessageIntegritySHA256Length},
		{n: 20, err: nil},
		{n: 32, err: nil},
		{n: 33, err: ErrInvalidMessageIntegritySHA256Length},
	}

	for _, tt := range tests {
		b := New(TypeBindingRequest, testTxID)
		b.AppendMessageIntegritySHA256Truncated(testKey, tt.n)
		m, err := b.Bytes()
		if err != tt.err {
			t.Fatalf("build: expected error %v, got %v", tt.err, err)
		}
		if err == nil {
			if _, err := Parse(m); err != nil {
				t.Fatalf("parse error: %v", err)
			}
		}
	}
}
