package stun

import "testing"

func BenchmarkParseMessageFingerprint(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AddFingerprint()
	raw, err := bb.Build()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var m Message
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Unmarshal(raw, testKey)
	}
}

func BenchmarkParseMessageIntegrity(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AddMessageIntegrity(testKey)
	raw, err := bb.Build()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var m Message
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Unmarshal(raw, testKey)
	}
}

func BenchmarkParseMessageIntegritySHA256(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AddMessageIntegritySHA256(testKey)
	raw, err := bb.Build()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var m Message
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Unmarshal(raw, testKey)
	}
}
