package socks5

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

var (
	ErrAddressTypeNotSupported = errors.New("socks5: address type not supported")
	ErrAddressLength           = errors.New("socks5: invalid address length")
)

type Atyp byte

const (
	AtypIPV4       Atyp = 1
	AtypDomainName Atyp = 3
	AtypIPV6       Atyp = 4
)

type Addr struct {
	ATYP Atyp
	Addr []byte
	Port uint16
}

func NewAddrFromBytes(b []byte) (*Addr, error) {
	if len(b) < 1 {
		return nil, ErrAddressLength
	}
	
	atyp := Atyp(b[0])
	
	switch atyp {
	case AtypIPV4, AtypIPV6:
		l := 0
		if atyp == AtypIPV4 {
			l = net.IPv4len
		} else {
			l = net.IPv6len
		}
		
		if len(b) < 1+l+2 {
			return nil, ErrAddressLength
		}
		
		addr := make([]byte, l)
		copy(addr, b[1:1+l])
		
		port := binary.BigEndian.Uint16(b[1+l:])
		
		return &Addr{
			ATYP: atyp,
			Addr: addr,
			Port: port,
		}, nil
	case AtypDomainName:
		if len(b) < 2 {
			return nil, ErrAddressLength
		}
		
		domainLen := int(b[1])
		if len(b) < 1+1+domainLen+2 {
			return nil, ErrAddressLength
		}
		
		addr := make([]byte, domainLen)
		copy(addr, b[2:2+domainLen])
		
		port := binary.BigEndian.Uint16(b[2+domainLen:])
		
		return &Addr{
			ATYP: atyp,
			Addr: addr,
			Port: port,
		}, nil
	
	default:
		return nil, ErrAddressTypeNotSupported
	}
}

func (a *Addr) Bytes() []byte {
	addrLen := len(a.Addr)
	if a.ATYP == AtypDomainName {
		addrLen += 1
	}
	
	buf := make([]byte, 1+addrLen+2)
	
	buf[0] = byte(a.ATYP)
	if a.ATYP == AtypDomainName {
		buf[1] = byte(len(a.Addr))
		copy(buf[2:], a.Addr)
	} else {
		copy(buf[1:], a.Addr)
	}
	
	binary.BigEndian.PutUint16(buf[1+addrLen:], a.Port)
	return buf
}

func (a *Addr) String() string {
	switch a.ATYP {
	case AtypIPV4:
		ip := net.IP(a.Addr).To4().String()
		port := strconv.Itoa(int(a.Port))
		return ip + ":" + port
	case AtypDomainName:
		domain := string(a.Addr)
		port := strconv.Itoa(int(a.Port))
		return domain + ":" + port
	case AtypIPV6:
		ip := net.IP(a.Addr).To16().String()
		port := strconv.Itoa(int(a.Port))
		return ip + ":" + port
	default:
		return "unknown"
	}
}

func EmptyAddr() *Addr {
	return &Addr{
		ATYP: AtypIPV4,
		Addr: net.IPv4(0, 0, 0, 0).To4(),
		Port: 0,
	}
}
