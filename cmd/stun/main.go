package main

import (
	"context"
	"crypto/rand"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/renthraysk/stun"
)

func main() {
	cfg := struct {
		addr string
	}{
		addr: "127.0.0.1:3478",
	}
	key := make([]byte, 16)

	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.StringVar(&cfg.addr, "addr", cfg.addr, "addr")
	flags.Parse(os.Args[1:])

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addr, err := net.ResolveUDPAddr("udp", cfg.addr)
	if err != nil {
		log.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("DialUDP failed: %v", err)
	}
	defer conn.Close()

	errCh := make(chan error, 1)
	go func(conn *net.UDPConn) {
		errCh <- bindingRequest(ctx, conn, key)
	}(conn)

	select {
	case <-ctx.Done():
		log.Fatalf("cancelled")
	case <-errCh:
	}
}

func bindingRequest(ctx context.Context, conn *net.UDPConn, key []byte) error {
	var in [1280]byte
	var txID stun.TxID

	if _, err := rand.Read(txID[:]); err != nil {
		return err
	}
	b := stun.New(stun.TypeBindingRequest, txID)
	b.SetSoftware("test")
	r, err := b.Build()
	if err != nil {
		return err
	}
	if _, err := conn.Write(r); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	n, _, err := conn.ReadFrom(in[:])
	if err != nil {
		return err
	}
	var p stun.Parser
	var m stun.Message
	if err := p.Parse(&m, in[:n:n]); err == nil {
		_ = m
	}
	return err
}
