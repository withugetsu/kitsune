package server

import "net"

type Server struct{}

func (server *Server) HandShake(conn net.Conn) error {
	return nil
}
