package shadowsocks

import (
	"errors"
	"io"
	"net"
	"sync"
	
	"github.com/withugetsu/kitsune/internal/sscipher"
)

var (
	ErrHeaderType = errors.New("shadowsocks: invalid header type")
)

type HeaderType byte

const (
	HeaderTypeClientStream HeaderType = 0x00
	HeaderTypeServerStream HeaderType = 0x01
	
	MaxPaddingLength        = 900
	MaxInitialPayloadLength = 0xFFFF
	MaxPayloadLength        = 0xFFFF
)

type Conn struct {
	Conn     net.Conn
	EnCipher *sscipher.Cipher
	DeCipher *sscipher.Cipher
	
	Pool sync.Pool
}

func NewConn(conn net.Conn, enCipher, deCipher *sscipher.Cipher) *Conn {
	bufSize := 2 + enCipher.Overhead() + MaxPayloadLength + enCipher.Overhead()
	return &Conn{
		Conn:     conn,
		EnCipher: enCipher,
		DeCipher: deCipher,
		Pool: sync.Pool{
			New: func() any {
				buf := make([]byte, bufSize)
				return &buf
			},
		},
	}
}

func NewClientConn(conn net.Conn, key []byte, cm sscipher.Method) (*Conn, error) {
	enSalt, err := sscipher.NewSalt(len(key))
	if err != nil {
		return nil, err
	}
	enCipher, err := sscipher.NewCipher(key, enSalt, cm)
	if err != nil {
		return nil, err
	}
	
	return NewConn(conn, enCipher, nil), nil
}

func NewServerConn(conn net.Conn, key []byte, cm sscipher.Method, clientSalt []byte) (*Conn, error) {
	deCipher, err := sscipher.NewCipher(key, clientSalt, cm)
	if err != nil {
		return nil, err
	}
	salt, err := sscipher.NewSalt(len(key))
	if err != nil {
		return nil, err
	}
	enCipher, err := deCipher.ReNew(salt)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, enCipher, deCipher), nil
}

func (c *Conn) Read(p []byte) (n int, err error) {
	bufPtr := c.Pool.Get().(*[]byte)
	defer c.Pool.Put(bufPtr)
	buf := *bufPtr
	
	overhead := c.Overhead()
	n, err = io.ReadFull(c.Conn, buf[:2+overhead])
	if err != nil {
		return n, err
	}
	
	lenChunk, err := c.Open(buf[:0], buf[:n])
	if err != nil {
		return 0, err
	}
	
	payloadSize := int(lenChunk[0])<<8 | int(lenChunk[1])
	if n, err = io.ReadFull(c.Conn, buf[:payloadSize+overhead]); err != nil {
		return n, err
	}
	
	plaintext, err := c.Open(buf[:0], buf[:n])
	if err != nil {
		return 0, err
	}
	
	n = copy(p, plaintext)
	return n, nil
}

func (c *Conn) Write(p []byte) (n int, err error) {
	bufPtr := c.Pool.Get().(*[]byte)
	defer c.Pool.Put(bufPtr)
	buf := *bufPtr
	
	buf = c.Seals(buf[:0],
		[]byte{byte(len(p) >> 8), byte(len(p))},
		p,
	)
	
	if _, err = c.Conn.Write(buf); err != nil {
		return 0, err
	}
	
	return len(p), nil
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) Seal(dst []byte, plaintext []byte) []byte {
	return c.EnCipher.Seal(dst, plaintext)
}

func (c *Conn) Seals(dst []byte, plaintexts ...[]byte) []byte {
	for _, plaintext := range plaintexts {
		dst = c.Seal(dst, plaintext)
	}
	return dst
}

func (c *Conn) Open(dst []byte, ciphertext []byte) ([]byte, error) {
	dst, err := c.DeCipher.Open(dst, ciphertext)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func (c *Conn) Overhead() int {
	return c.EnCipher.Overhead()
}

func Stream(conn *Conn, socks5Conn net.Conn, payload []byte) error {
	defer conn.Close()
	defer socks5Conn.Close()
	
	errChan := make(chan error, 2)
	bufSize := MaxPayloadLength
	
	go func() {
		buf := make([]byte, bufSize)
		_, err := io.CopyBuffer(conn, socks5Conn, buf)
		errChan <- err
	}()
	
	go func() {
		if len(payload) > 0 {
			if _, err := socks5Conn.Write(payload); err != nil {
				errChan <- err
				return
			}
		}
		
		buf := make([]byte, bufSize)
		_, err := io.CopyBuffer(socks5Conn, conn, buf)
		errChan <- err
	}()
	
	return <-errChan
}
