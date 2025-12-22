package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
	
	"github.com/withugetsu/kitsune/ciphers"
	"github.com/withugetsu/kitsune/tool"
)

var (
	ErrHeaderType = errors.New("shadowsocks: invalid header type")
	ErrVLHSize    = errors.New("shadowsocks: invalid variable length header size")
)

type HeaderType byte

const (
	HeaderTypeClientStream HeaderType = 0x00
	HeaderTypeServerStream HeaderType = 0x01
	
	MaxPaddingLength        = 900
	MaxInitialPayloadLength = 1200
	MaxPayloadLength        = 0xFFFF
)

type ShadowConn struct {
	Conn     net.Conn
	EnCipher *ciphers.Cipher
	DeCipher *ciphers.Cipher
	readBuf  []byte
	writeBuf []byte
	key      []byte
	ct       ciphers.Method
	
	doReadServerHandshake func() error
	serverHandshakeBuf    []byte
	
	doWriteServerHandshake func() error
	vlh                    []byte
}

func NewShadowConn(conn net.Conn, key []byte, ct ciphers.Method) (*ShadowConn, error) {
	enCipher, err := ciphers.NewCipher(ct, key)
	if err != nil {
		return nil, err
	}
	
	bufSize := 2 + enCipher.Overhead() + MaxPayloadLength + enCipher.Overhead()
	sc := &ShadowConn{
		Conn:     conn,
		EnCipher: enCipher,
		readBuf:  make([]byte, bufSize),
		writeBuf: make([]byte, bufSize),
		key:      key,
		ct:       ct,
	}
	
	sc.doReadServerHandshake = sync.OnceValue(sc.readServerHandshake)
	sc.doWriteServerHandshake = sync.OnceValue(sc.writeClientHandshake)
	
	return sc, nil
}

func (sc *ShadowConn) Write(p []byte) (n int, err error) {
	if err = sc.doWriteServerHandshake(); err != nil {
		return 0, err
	}
	
	buf := sc.writeBuf[:0]
	buf = sc.EnCipher.Seal(buf, []byte{byte(len(p) >> 8), byte(len(p))})
	buf = sc.EnCipher.Seal(buf, p)
	
	if _, err = sc.Conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (sc *ShadowConn) Read(p []byte) (n int, err error) {
	if err = sc.doReadServerHandshake(); err != nil {
		return 0, err
	}
	
	if len(sc.serverHandshakeBuf) > 0 {
		n = copy(p, sc.serverHandshakeBuf)
		sc.serverHandshakeBuf = sc.serverHandshakeBuf[n:]
		return n, nil
	}
	
	headSize := 2 + sc.DeCipher.Overhead()
	if _, err = io.ReadFull(sc.Conn, sc.readBuf[:headSize]); err != nil {
		return 0, err
	}
	
	plainLen, err := sc.DeCipher.Open(sc.readBuf[:0], sc.readBuf[:headSize])
	if err != nil {
		return 0, err
	}
	
	chunkLen := int(plainLen[0])<<8 | int(plainLen[1])
	payloadSize := chunkLen + sc.DeCipher.Overhead()
	
	if _, err = io.ReadFull(sc.Conn, sc.readBuf[:payloadSize]); err != nil {
		return 0, err
	}
	
	plaintext, err := sc.DeCipher.Open(sc.readBuf[:0], sc.readBuf[:payloadSize])
	if err != nil {
		return 0, err
	}
	
	n = copy(p, plaintext)
	
	if n < len(plaintext) {
		sc.serverHandshakeBuf = plaintext[n:]
	}
	
	return n, nil
}

func (sc *ShadowConn) writeClientHandshake() error {
	vlhLen := len(sc.vlh)
	if vlhLen <= 0 {
		return ErrVLHSize
	}
	
	flh := make([]byte, 1+8+2)
	flh[0] = byte(HeaderTypeClientStream)
	binary.BigEndian.PutUint64(flh[1:], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(flh[1+8:], uint16(vlhLen))
	
	encryptedFLH := sc.EnCipher.Seal(nil, flh)
	encryptedVLH := sc.EnCipher.Seal(nil, sc.vlh)
	
	if _, err := sc.Conn.Write(append(sc.EnCipher.Salt, append(encryptedFLH, encryptedVLH...)...)); err != nil {
		return err
	}
	
	return nil
}

func (sc *ShadowConn) readServerHandshake() error {
	respSaltLen := len(sc.EnCipher.Salt)
	respFLHLen := 1 + 8 + respSaltLen + 2 + sc.EnCipher.Overhead()
	
	respBuf := make([]byte, respSaltLen+respFLHLen)
	if _, err := io.ReadFull(sc.Conn, respBuf); err != nil {
		return err
	}
	
	respSalt := respBuf[:respSaltLen]
	deCipher, err := ciphers.NewCipherWithSalt(sc.ct, sc.key, respSalt)
	if err != nil {
		return err
	}
	
	sc.DeCipher = deCipher
	
	header, err := sc.DeCipher.Open(nil, respBuf[respSaltLen:])
	if err != nil {
		return err
	}
	
	ht := HeaderType(header[0])
	if ht != HeaderTypeServerStream {
		return ErrHeaderType
	}
	
	tsVal := binary.BigEndian.Uint64(header[1 : 1+8])
	ts := time.Unix(int64(tsVal), 0)
	if time.Since(ts).Abs() > 30*time.Second {
		return errors.New("timestamp skewed")
	}
	
	reqSalt := header[1+8 : 1+8+respSaltLen]
	if !bytes.Equal(reqSalt, sc.EnCipher.Salt) {
		return errors.New("request salt mismatch: potential mitm")
	}
	
	payloadLen := binary.BigEndian.Uint16(header[1+8+respSaltLen:])
	
	if payloadLen > 0 {
		payloadBuf := make([]byte, int(payloadLen)+sc.DeCipher.Overhead())
		if _, err = io.ReadFull(sc.Conn, payloadBuf); err != nil {
			return err
		}
		
		payload, err := sc.DeCipher.Open(nil, payloadBuf)
		if err != nil {
			return err
		}
		
		sc.serverHandshakeBuf = payload
	}
	
	return nil
}

func (sc *ShadowConn) SetVLH(targetAddr, initialPayload []byte) error {
	var minPaddingLength uint
	if len(initialPayload) == 0 {
		minPaddingLength = 1 // When making a request header, if payload is not available, add non-zero random length padding.
	}
	padding, err := tool.RandomPadding(minPaddingLength, MaxPaddingLength)
	if err != nil {
		return err
	}
	
	sc.vlh = append(targetAddr, append(padding, initialPayload...)...)
	return nil
}

func (sc *ShadowConn) Close() error {
	return sc.Conn.Close()
}

func (sc *ShadowConn) Stream(socks5Conn net.Conn) error {
	defer sc.Close()
	defer socks5Conn.Close()
	
	errChan := make(chan error, 1)
	bufSize := MaxPayloadLength
	
	go func() {
		buf := make([]byte, bufSize)
		_, err := io.CopyBuffer(sc, socks5Conn, buf)
		errChan <- err
	}()
	
	go func() {
		buf := make([]byte, bufSize)
		_, err := io.CopyBuffer(socks5Conn, sc, buf)
		errChan <- err
	}()
	
	return <-errChan
}
