package stun

import (
	"encoding/binary"
	"net"
)

const ErrUnknownAddressAttribute = errorString("unknown address attribute")
const ErrUnknownIPFamily = errorString("unknown IP family")

const (
	iPv4Family = 0x01
	iPv6Family = 0x02
)

func family(n int) uint8 {
	switch n {
	case net.IPv4len:
		return iPv4Family
	case net.IPv6len:
		return iPv6Family
	default:
		return 0x00
	}
}

type Address struct {
	net.IP
	Port uint16

	buf [net.IPv6len]byte
}

func attrAddressFamily(attr []byte) byte { return attr[5] }

func (a *Address) Unmarshal(m Message, attr []byte) error {
	if len(attr) < 8+net.IPv4len {
		return ErrMalformedAttribute
	}
	n := net.IPv4len
	if f := attrAddressFamily(attr); f == iPv6Family {
		n = net.IPv6len
	} else if f != iPv4Family {
		return ErrUnknownIPFamily
	}
	if len(attr) != 8+n || attrSize(attr) != 4+n {
		return ErrMalformedAttribute
	}
	a.IP = a.buf[:n] // make([]byte, n)
	copy(a.IP, attr[8:])
	a.Port = binary.BigEndian.Uint16(attr[6:8])
	switch attrType(attr) {
	case attrXorMappedAddress:
		for i, x := range m[4 : 4+n] { // m[4:4+n] spans magiccookie and transactionid if needed
			a.IP[i] ^= x
		}
		a.Port ^= magicCookiePort
		return nil
	case attrMappedAddress:
		return nil
	}
	return ErrUnknownAddressAttribute
}

func appendMappedAddress(m Message, ip net.IP, port uint16) []byte {
	n := len(ip)
	m = append(m, byte(attrMappedAddress>>8), byte(attrMappedAddress),
		0, byte(4+n), 0, family(n), byte(port>>8), byte(port))
	return append(m, ip...)
}

func appendXorMappedAddress(m Message, ip net.IP, port uint16) []byte {
	port ^= magicCookiePort
	n := len(ip)
	m = append(m, byte(attrXorMappedAddress>>8), byte(attrXorMappedAddress),
		0, byte(4+n), 0, family(n), byte(port>>8), byte(port))
	m = append(m, m[4:4+n]...) // m[4:4+n] spans magiccookie and transactionid if needed
	s := m[len(m)-n:]
	for i, x := range ip {
		s[i] ^= x
	}
	return m
}
