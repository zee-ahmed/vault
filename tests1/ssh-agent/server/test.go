package main

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/websocket"
	"io/ioutil"
	"log"
	"net/http"
)

type WebsocketAgent struct {
	agent.Agent
}

func NewWebsocketAgent() *WebsocketAgent {
	keyAgent := &WebsocketAgent{
		agent.NewKeyring(),
	}

	pemBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		log.Fatalf("parse key failed: %+v", err)
	}

	key := agent.AddedKey{
		PrivateKey: signer,
	}

	err = keyAgent.Add(key)
	if err != nil {
		log.Fatalf("parse key failed: %+v", err)
	}

	return keyAgent

}

func (wa *WebsocketAgent) Handle(ws *websocket.Conn) {
	err := agent.ServeAgent(wa, ws)
	if err != nil {
		log.Printf("server agent: %s", err)
	}
	ws.Close()
}

func main() {

	wsAgent := NewWebsocketAgent()

	http.Handle("/ssh-agent", websocket.Handler(wsAgent.Handle))
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
