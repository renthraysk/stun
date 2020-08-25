package stun

import (
	"crypto/rand"
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

func bindingSuccess(buf []byte, txID TxID, a *net.UDPAddr) []byte {
	p := newHeader(buf, TypeBindingSuccess, txID)
	return appendXorMappedAddress(p, a.IP, uint16(a.Port))
}

func bindingRequest(buf []byte, txID TxID, software string) []byte {
	p := newHeader(buf, TypeBindingRequest, txID)
	p = appendSoftware(p, software)
	return appendFingerprint(p)
}

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
			r := bindingSuccess(buf[:0], m.TxID(), addr.(*net.UDPAddr))
			if _, err := pc.WriteTo(r, addr); err != nil {
			}
		}
	}
}

func BindingRequest(buf []byte, software string) ([]byte, error) {
	var txID TxID
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, err
	}
	return bindingRequest(buf, txID, software), nil
}
