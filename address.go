package stun

import (
	"encoding/binary"
	"net"
)

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

func attrAddressFamily(attr []byte) byte { return attr[1] }

func (a *Address) Unmarshal(raw []byte, attrType attr, attrValue []byte) error {
	if len(attrValue) < 4+net.IPv4len {
		return ErrUnexpectedEOF
	}
	n := net.IPv4len
	if f := attrAddressFamily(attrValue); f == iPv6Family {
		n = net.IPv6len
	} else if f != iPv4Family {
		return ErrUnknownIPFamily
	}
	if len(attrValue) != 4+n {
		return ErrUnexpectedEOF
	}
	if attributeSize(attrValue) != n {
		return ErrMalformedAttribute
	}
	a.IP = a.buf[:n] // make([]byte, n)
	copy(a.IP, attrValue[4:])
	a.Port = binary.BigEndian.Uint16(attrValue[2:4])
	switch attrType {
	case attrXorMappedAddress:
		for i, x := range raw[4 : 4+n] { // raw[4:4+n] spans magiccookie and transaction id if needed
			a.IP[i] ^= x
		}
		a.Port ^= magicCookiePort
		return nil
	case attrMappedAddress, attrAlternateServer:
		return nil
	}
	return ErrUnknownAddressAttribute
}

func appendAddress(m []byte, a attr, ip net.IP, port uint16) []byte {
	n := len(ip)
	m = append(m, byte(a>>8), byte(a),
		0, byte(4+n), 0, family(n), byte(port>>8), byte(port))
	return append(m, ip...)
}

func appendMappedAddress(m []byte, ip net.IP, port uint16) []byte {
	return appendAddress(m, attrMappedAddress, ip, port)
}

func appendXorMappedAddress(m []byte, ip net.IP, port uint16) []byte {
	port ^= magicCookiePort
	n := len(ip)
	m = append(m, byte(attrXorMappedAddress>>8), byte(attrXorMappedAddress),
		0, byte(4+n), 0, family(n), byte(port>>8), byte(port))
	m = append(m, m[4:4+n]...) // m[4:4+n] spans magiccookie and transaction id if needed
	s := m[len(m)-n:]
	for i, x := range ip {
		s[i] ^= x
	}
	return m
}

func appendAlternateServer(m []byte, ip net.IP, port uint16) []byte {
	return appendAddress(m, attrAlternateServer, ip, port)
}
