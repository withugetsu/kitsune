package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log"
	"net"
	"os"
	
	"github.com/withugetsu/kitsune/internal/client"
	"github.com/withugetsu/kitsune/internal/sscipher"
)

func main() {
	password := flag.String("password", "", "specify the password for the client")
	method := flag.String("method", "2022-blake3-aes-128-gcm", "specify the method for the client")
	remoteAddr := flag.String("remoteAddr", "", "specify the Shadowsocks server address")
	localAddr := flag.String("localAddr", "127.0.0.1:1080", "specify the TCP listening address for the client")
	
	flag.Parse()
	
	key, err := base64.StdEncoding.DecodeString(*password)
	if err != nil {
		log.Fatal(err)
	}
	
	if *remoteAddr == "" {
		flag.Usage()
		os.Exit(1)
	}
	
	m, err := sscipher.ParseMethod(*method)
	if err != nil {
		log.Fatal(err)
	}
	
	c := client.New(context.Background(), key, m)
	c.RemoteSSAddr = func(conn net.Conn) string {
		return *remoteAddr
	}
	
	if *localAddr == "" {
		flag.Usage()
		os.Exit(1)
	}
	
	if err = c.Serve(*localAddr); err != nil {
		log.Fatal(err)
	}
}
