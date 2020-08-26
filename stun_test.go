package stun

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
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

	_, err := Parse(in)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

}

func TestRFC8489VectorB1(t *testing.T) {

	const (
		username = "\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9"
		nonce    = "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"
		realm    = "example.org"
	)

	txID := [12]byte{
		0x78, 0xAD, 0x34, 0x33,
		0xC6, 0xAD, 0x72, 0xC0,
		0x29, 0xDA, 0x41, 0x2E,
	}

	userHashX := []byte{
		0x4a, 0x3c, 0xf3, 0x8f,
		0xef, 0x69, 0x92, 0xbd,
		0xa9, 0x52, 0xc6, 0x78,
		0x04, 0x17, 0xda, 0x0f,
		0x24, 0x81, 0x94, 0x15,
		0x56, 0x9e, 0x60, 0xb2,
		0x05, 0xc4, 0x6e, 0x41,
		0x40, 0x7f, 0x17, 0x04,
	}

	userHash := UserHash(make([]byte, 0, sha256.Size), []byte(username), []byte(realm))
	if !bytes.Equal(userHash, userHashX) {
		t.Fatal("failed to create userhash")
	}

	key := md5.Sum([]byte(username + ":" + realm + ":" + "TheMatrIX"))

	b := New(TypeBindingRequest, txID)
	b.AppendUserHash(userHash)
	b.AppendNonce([]byte(nonce))
	b.AppendRealm(realm)
	b.AppendMessageIntegritySHA256(key[:])
	r, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	w := hex.Dumper(os.Stdout)
	w.Write(r)
	w.Close()

}

func TestFingerprint(t *testing.T) {

	b := New(TypeBindingRequest, txID)
	b.AppendFingerprint()
	m, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

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

	b := New(TypeBindingRequest, txID)
	b.AppendMessageIntegrity(key)
	m, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

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
	b := New(TypeBindingRequest, txID)
	b.AppendMessageIntegritySHA256(key)
	m, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

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
	b := New(TypeBindingRequest, txID)
	b.AppendMessageIntegritySHA256(key)
	b.AppendFingerprint()
	m, err := b.Bytes()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

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
	setAttrSize(m)

	if _, err := Parse(m); err != ErrMessageIntegrity {
		t.Fatal("expected ErrMessageIntegrity err")
	}
}

func TestMessageIntegritySHA256ShouldBeOnlyFollowedByFingerprint(t *testing.T) {
	// Only attribute allowed after a MessageIntegritySHA256 is Fingerprint
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendMessageIntegritySHA256(m, key)
	m = appendSoftware(m, "test")
	setAttrSize(m)

	if _, err := Parse(m); err != ErrMessageIntegritySHA256 {
		t.Fatal("expected ErrMessageIntegritySHA256 error")
	}
}

func TestFingerprintShouldBeLastAttribute(t *testing.T) {
	// Fingerprint should be last attribute
	m := newHeader(nil, TypeBindingRequest, txID)
	m = appendFingerprint(m)
	m = appendMessageIntegritySHA256(m, key)
	setAttrSize(m)

	if _, err := Parse(m); err == nil {
		t.Fatalf("expected failure")
	}
}

func BenchmarkMessageFingerprint(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AppendFingerprint()
	m, err := bb.Bytes()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(m)
	}
}

func BenchmarkMessageIntegrity(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AppendMessageIntegrity(key)
	m, err := bb.Bytes()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(m)
	}
}

func BenchmarkMessageIntegritySHA256(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AppendMessageIntegritySHA256(key)
	m, err := bb.Bytes()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(m)
	}
}
