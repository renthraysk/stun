package stun

import (
	"net"
)

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

type Message struct {
	typ  Type
	txID TxID
}

func (m *Message) Type() Type        { return m.typ }
func (m *Message) TxID() (txID TxID) { copy(txID[:], m.txID[:]); return }
func (m *Message) Reset() {
	m.typ = 0
	for i := range m.txID[:] {
		m.txID[i] = 0
	}
}

func Serve(pc net.PacketConn, key []byte) {
	buf := make([]byte, 4*1024)

	var m Message

	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		if err := m.Unmarshal(buf[:n], key); err != nil {
			continue
		}
		switch m.Type() {
		case TypeBindingRequest:
			b := New(TypeBindingSuccess, m.TxID())
			b.SetXorMappingAddress(addr.(*net.UDPAddr))
			if raw, err := b.Build(); err == nil {
				if _, err := pc.WriteTo(raw, addr); err != nil {
					// @TODO?
				}
			}
		}
	}
}
