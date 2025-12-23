package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/withugetsu/kitsune/ciphers"
	"github.com/withugetsu/kitsune/shadowsocks"
	"github.com/withugetsu/kitsune/socks5"
)

var (
	ErrRemoteSSNil = errors.New("shadowsocks: remote SS address is nil")
)

type Client struct {
	ctx          context.Context
	key          []byte
	cm           ciphers.Method
	RemoteSSAddr func(conn net.Conn) string
	logger       *slog.Logger
}

func NewClient(ctx context.Context, key []byte, cm ciphers.Method) *Client {
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
		ln.Close()
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

	if c.RemoteSSAddr == nil {
		return ErrRemoteSSNil
	}
	ssAddr := c.RemoteSSAddr(socks5Conn)
	ssConn, err := net.Dial("tcp", ssAddr)
	if err != nil {
		return err
	}

	initialPayload, err := socks5.WaitForInitialPayload(socks5Conn, shadowsocks.MaxInitialPayloadLength)
	if err != nil {
		return err
	}

	sc, err := shadowsocks.NewShadowConn(ssConn, c.key, c.cm)
	if err != nil {
		_ = ssConn.Close()
		return err
	}

	if err = sc.WriteClientHandshake(targetAddr, initialPayload); err != nil {
		_ = ssConn.Close()
		return err
	}
	err = sc.Stream(socks5Conn)
	if err != nil {
		c.logger.Warn(fmt.Sprintf("shadow stream [%s <-> %s] quit with error", socks5Conn.RemoteAddr().String(), ssConn.RemoteAddr().String()), "error", err)
	} else {
		c.logger.Debug(fmt.Sprintf("shadow stream [%s <-> %s] quit without error", socks5Conn.RemoteAddr().String(), ssConn.RemoteAddr().String()))
	}

	return nil
}

func (c *Client) handleUDP(conn net.Conn, targetAddr []byte) error {
	return socks5.ReplyTo(conn, socks5.ReplyFiledCommandNotSupported, nil)
}
