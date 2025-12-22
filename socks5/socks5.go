package socks5

import (
	"errors"
	"io"
	"net"
	"time"
	
	"github.com/withugetsu/kitsune/tool"
)

var (
	ErrCommandNotSupported = errors.New("socks5: command not supported")
)

type Command byte

const (
	CommandConnect      Command = 0x01
	CommandBind         Command = 0x02
	CommandUDPAssociate Command = 0x03
)

func (c Command) String() string {
	switch c {
	case CommandConnect:
		return "socks5_connect"
	case CommandBind:
		return "socks5_bind"
	case CommandUDPAssociate:
		return "socks5_udp_associate"
	default:
		return "socks5_unknow"
	}
}

type ReplyFiled byte

const (
	ReplyFiledSuccess             ReplyFiled = 0x00
	ReplyFiledCommandNotSupported ReplyFiled = 0x07
)

func Handshake(conn net.Conn) (cmd Command, addr []byte, err error) {
	buf, err := tool.ReadExact(conn, 2)
	if err != nil {
		return
	}
	
	buf, err = tool.ReadExact(conn, int(buf[1]))
	if err != nil {
		return
	}
	
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	
	buf, err = tool.ReadExact(conn, 4)
	if err != nil {
		return
	}
	
	cmd = Command(buf[1])
	atyp := buf[3]
	
	if cmd != CommandConnect && cmd != CommandUDPAssociate {
		_ = ReplyTo(conn, 0x07, EmptyAddr())
		return cmd, nil, ErrCommandNotSupported
	}
	
	switch Atyp(atyp) {
	case AtypIPV4:
		buf = make([]byte, 1+net.IPv4len+2)
		buf[0] = atyp
		if _, err = io.ReadFull(conn, buf[1:]); err != nil {
			return
		}
		return cmd, buf, nil
	case AtypDomainName:
		buf = make([]byte, 1)
		if _, err = io.ReadFull(conn, buf); err != nil {
			return
		}
		l := buf[0]
		buf = make([]byte, 1+1+l+2)
		buf[0] = atyp
		buf[1] = l
		if _, err = io.ReadFull(conn, buf[2:]); err != nil {
			return
		}
		return cmd, buf, nil
	case AtypIPV6:
		buf = make([]byte, 1+net.IPv6len+2)
		buf[0] = atyp
		if _, err = io.ReadFull(conn, buf[1:]); err != nil {
			return
		}
		return cmd, buf, nil
	default:
		return cmd, nil, ErrAddressTypeNotSupported
	}
}

func ReplyTo(conn net.Conn, rf ReplyFiled, addr *Addr) error {
	if addr == nil {
		addr = EmptyAddr()
	}
	_, err := conn.Write(append([]byte{0x05, byte(rf), 0x00}, addr.Bytes()...))
	return err
}

func WaitForInitialPayload(conn net.Conn, d time.Duration, maxPayloadLength int) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(d)); err != nil {
		return nil, err
	}
	
	buf := make([]byte, maxPayloadLength)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	
	if setErr := conn.SetDeadline(time.Time{}); setErr != nil {
		err = errors.Join(err, setErr)
	}
	
	return nil, err
}
