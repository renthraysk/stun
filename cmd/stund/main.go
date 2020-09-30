package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/renthraysk/stun"
)

func main() {

	cfg := struct {
		addr string
	}{
		addr: "127.0.0.1:3478",
	}

	key := ""

	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.StringVar(&cfg.addr, "addr", cfg.addr, "addr")
	flags.Parse(os.Args[1:])

	pc, err := net.ListenPacket("udp", cfg.addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	fmt.Fprintf(os.Stdout, "Listening on %s\n", pc.LocalAddr().String())

	stun.Serve(pc, key)

}
