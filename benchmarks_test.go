package stun

import (
	"testing"
)

func BenchmarkParseMessageFingerprint(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.AddFingerprint()
	raw, err := bb.Build()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var m Message
	var p Parser
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Parse(&m, raw)
	}
}

func BenchmarkParseMessageIntegrity(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.SetPassword(testPassword)
	bb.AddMessageIntegrity()
	raw, err := bb.Build()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var p Parser
	var m Message

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Parse(&m, raw)
	}
}

func BenchmarkParseMessageIntegritySHA256(b *testing.B) {
	bb := New(TypeBindingRequest, txID)
	bb.SetPassword(testPassword)
	bb.AddMessageIntegritySHA256()
	raw, err := bb.Build()
	if err != nil {
		b.Fatalf("build failed: %v", err)
	}
	var p Parser
	var m Message
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Parse(&m, raw)
	}
}
