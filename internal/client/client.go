package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"time"
	
	"github.com/withugetsu/kitsune/internal/shadowsocks"
	"github.com/withugetsu/kitsune/internal/socks5"
	"github.com/withugetsu/kitsune/internal/sscipher"
	"github.com/withugetsu/kitsune/internal/tool"
)

type Client struct {
	ctx          context.Context
	key          []byte
	cm           sscipher.Method
	RemoteSSAddr func(conn net.Conn) string
	logger       *slog.Logger
}

func New(ctx context.Context, key []byte, cm sscipher.Method) *Client {
	return &Client{
		ctx: ctx,
		key: key,
		cm:  cm,
		logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
	}
}

func (c *Client) SetLogger(logger *slog.Logger) {
	c.logger = logger
}

func (c *Client) Serve(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	
	c.logger.Info("shadowsocks socks TCP listening on", "address", addr)
	defer c.logger.Info("shadowsocks socks TCP closed")
	
	go func() {
		<-c.ctx.Done()
		_ = ln.Close()
	}()
	
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		
		go func(socks5Conn net.Conn) {
			if err := c.handleConnection(socks5Conn); err != nil {
				c.logger.Error("handle connection error", "error", err)
			}
		}(conn)
	}
}

func (c *Client) handleConnection(socks5Conn net.Conn) error {
	defer socks5Conn.Close()
	
	cmd, dstAddr, err := socks5.Handshake(socks5Conn)
	if err != nil {
		return err
	}
	
	ta, err := socks5.NewAddrFromBytes(dstAddr)
	if err != nil {
		return err
	}
	c.logger.Debug("socks5 handshake completed", "cmd", cmd.String(), "dstAddr", ta.String(), "srcAddr", socks5Conn.RemoteAddr().String())
	
	switch cmd {
	case socks5.CommandConnect:
		return c.handleTCP(socks5Conn, dstAddr)
	case socks5.CommandUDPAssociate:
		return c.handleUDP(socks5Conn, dstAddr)
	default:
		return socks5.ErrCommandNotSupported
	}
}

func (c *Client) handleTCP(socks5Conn net.Conn, targetAddr []byte) error {
	if err := socks5.ReplyTo(socks5Conn, socks5.ReplyFiledSuccess, socks5.EmptyAddr()); err != nil {
		return err
	}
	
	ssConn, err := net.Dial("tcp", c.RemoteSSAddr(socks5Conn))
	if err != nil {
		return err
	}
	
	initialPayload, err := socks5.WaitForInitialPayload(socks5Conn, shadowsocks.MaxInitialPayloadLength)
	if err != nil {
		return err
	}
	
	sc, err := shadowsocks.NewClientConn(ssConn, c.key, c.cm)
	if err != nil {
		_ = ssConn.Close()
		return err
	}
	
	payload, err := Handshake(sc, targetAddr, initialPayload)
	if err != nil {
		_ = ssConn.Close()
		return err
	}
	
	return shadowsocks.Stream(sc, socks5Conn, payload)
}

func (c *Client) handleUDP(conn net.Conn, targetAddr []byte) error {
	return socks5.ReplyTo(conn, socks5.ReplyFiledCommandNotSupported, nil)
}

func Handshake(sc *shadowsocks.Conn, targetAddr, initialPayload []byte) ([]byte, error) {
	if err := writeClientHandshake(sc, targetAddr, initialPayload); err != nil {
		return nil, err
	}
	
	payload, err := readServerHandshake(sc)
	if err != nil {
		return nil, err
	}
	
	return payload, nil
}

func readServerHandshake(sc *shadowsocks.Conn) ([]byte, error) {
	respSaltLen := len(sc.EnCipher.Salt())
	respFLHLen := 1 + 8 + respSaltLen + 2 + sc.EnCipher.Overhead()
	
	bufPtr := sc.Pool.Get().(*[]byte)
	defer sc.Pool.Put(bufPtr)
	buf := *bufPtr
	
	if _, err := io.ReadFull(sc.Conn, buf[:respSaltLen+respFLHLen]); err != nil {
		return nil, err
	}
	
	respSalt := buf[:respSaltLen]
	deCipher, err := sc.EnCipher.ReNew(respSalt)
	if err != nil {
		return nil, err
	}
	sc.DeCipher = deCipher
	
	header, err := sc.Open(buf[respSaltLen:respSaltLen], buf[respSaltLen:respSaltLen+respFLHLen])
	if err != nil {
		return nil, err
	}
	
	ht := shadowsocks.HeaderType(header[0])
	if ht != shadowsocks.HeaderTypeServerStream {
		return nil, shadowsocks.ErrHeaderType
	}
	
	ts := time.Unix(int64(binary.BigEndian.Uint64(header[1:1+8])), 0)
	if time.Since(ts) > 30*time.Second {
		return nil, errors.New("timestamp skewed")
	}
	
	reqSalt := header[1+8 : 1+8+respSaltLen]
	if !bytes.Equal(reqSalt, sc.EnCipher.Salt()) {
		return nil, errors.New("request salt mismatch: potential mitm")
	}
	
	payloadLen := binary.BigEndian.Uint16(header[1+8+respSaltLen : 1+8+respSaltLen+2])
	if payloadLen > 0 {
		buf = buf[:int(payloadLen)+sc.DeCipher.Overhead()]
		if _, err = io.ReadFull(sc.Conn, buf); err != nil {
			return nil, err
		}
		
		buf, err = sc.Open(buf[:0], buf)
		if err != nil {
			return nil, err
		}
		
		data := make([]byte, len(buf))
		copy(data, buf)
		
		return data, nil
	}
	
	return nil, nil
}

func writeClientHandshake(sc *shadowsocks.Conn, targetAddr, initialPayload []byte) error {
	padding, err := tool.Padding(1, shadowsocks.MaxPaddingLength)
	if err != nil {
		return err
	}
	
	vlh := append(targetAddr, append(padding, initialPayload...)...)
	
	flh := make([]byte, 1+8+2)
	flh[0] = byte(shadowsocks.HeaderTypeClientStream)
	binary.BigEndian.PutUint64(flh[1:], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(flh[1+8:], uint16(len(vlh)))
	
	salt := sc.EnCipher.Salt()
	header := sc.Seals(salt, flh, vlh)
	
	if _, err = sc.Conn.Write(header); err != nil {
		return err
	}
	return nil
}
