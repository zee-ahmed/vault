package main

import (
	"golang.org/x/net/websocket"
	"io"
	"log"
	"net"
	"os"
)

func main() {

	l, err := net.ListenUnix("unix", &net.UnixAddr{"/tmp/unixdomain", "unix"})
	if err != nil {
		panic(err)
	}
	defer os.Remove("/tmp/unixdomain")

	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			panic(err)
		}

		client, err := websocket.Dial("ws://127.0.0.1:8080/ssh-agent", "", "http://127.0.0.1")
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			defer client.Close()
			defer conn.Close()
			io.Copy(client, conn)
		}()
		go func() {
			defer client.Close()
			defer conn.Close()
			io.Copy(conn, client)
		}()
	}
}
