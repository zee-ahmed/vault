package ssh

import (
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/net/websocket"
)

type AgentClient struct {
	Path         string
	Listener     net.Listener
	WebsocketURL string
}

func (ac *AgentClient) Close() error {
	if ac.Listener == nil {
		return nil
	}

	if err := os.Remove(ac.Path); err != nil {
		return err
	}

	ac.Listener = nil
	return nil
}

func (ac *AgentClient) Run(stopCh <-chan struct{}) error {
	var err error

	ac.Listener, err = net.ListenUnix("unix", &net.UnixAddr{ac.Path, "unix"})
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := ac.Listener.Accept()
			if err != nil {
				panic(err)
			}

			client, err := websocket.Dial(ac.WebsocketURL, "", "")
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
	}()

	return nil
}
