package stun

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
)

type errorString string

func (e errorString) Error() string { return string(e) }

const (
	headerSize = 20

	magicCookie     uint32 = 0x2112A442
	magicCookiePort uint16 = 0x2112
)

type Type uint16

const (
	TypeBindingRequest Type = 0x0001
	TypeBindingSuccess Type = 0x0101
)

type TxID [12]byte

func Serve(pc net.PacketConn) {
	buf := make([]byte, 4*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		m, err := Parse(buf[:n:n])
		if err != nil {
			continue
		}
		switch m.Type() {
		case TypeBindingRequest:
			b := New(TypeBindingSuccess, m.TxID())
			b.AppendXorMappingAddress(addr.(*net.UDPAddr))
			if err == nil {
				if b, err := b.Bytes(); err != nil {
					if _, err := pc.WriteTo(b, addr); err != nil {
						// @TODO?
					}
				}
			}
		}
	}
}

func BindingRequest(buf []byte, software string) ([]byte, error) {
	var txID TxID
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, err
	}
	b := New(TypeBindingRequest, txID)
	b.AppendSoftware(software)
	return b.Bytes()
}

func UserHash(b, name, realm []byte) []byte {
	h := sha256.New()
	h.Write(name)
	h.Write([]byte{':'})
	h.Write(realm)
	return h.Sum(b)
}
