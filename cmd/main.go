package main

import (
	"context"
	"encoding/base64"
	"log"
	"net"
	"os"
	
	"github.com/withugetsu/kitsune/ciphers"
	"github.com/withugetsu/kitsune/shadowsocks/client"
)

func main() {
	key, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	
	c := client.NewClient(context.Background(), key, ciphers.AEAD2022BLAKE3AES256GCM)
	c.RemoteSSAddr = func(conn net.Conn) string {
		return "127.0.0.1:9999"
	}
	
	if err = c.Serve("127.0.0.1:7777"); err != nil {
		log.Fatal(err)
	}
}
