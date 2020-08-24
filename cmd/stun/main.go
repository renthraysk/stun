package main

import (
	"context"
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
		errCh <- bindingRequest(ctx, conn)
	}(conn)

	select {
	case <-ctx.Done():
		log.Fatalf("cancelled")
	case <-errCh:
	}
}

func bindingRequest(ctx context.Context, conn *net.UDPConn) error {
	var b [1280]byte

	r, err := stun.BindingRequest(b[:0], "test")
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
	n, _, err := conn.ReadFrom(b[:])
	if err != nil {
		return err
	}
	m, ok := stun.Parse(b[:n:n])
	if ok {
		_ = m
	}
	return nil
}
