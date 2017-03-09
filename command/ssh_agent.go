package command

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/vault/meta"
	"golang.org/x/net/websocket"
)

// SSHAgentCommand is a Command that establishes a SSH connection
// with target by using a SSH key agent
type SSHAgentCommand struct {
	meta.Meta
}

func (c *SSHAgentCommand) Run(args []string) int {
	var mountPoint string
	flags := c.Meta.FlagSet("ssh-agent", meta.FlagSetDefault)
	flags.StringVar(&mountPoint, "mount-point", "ssh", "")

	flags.Usage = func() { c.Ui.Error(c.Help()) }
	if err := flags.Parse(args); err != nil {
		return 1
	}

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

	sshCmd := exec.Command("ssh", args...)
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout

	err := sshCmd.Run()
	if err != nil {
		c.Ui.Error(fmt.Sprintf("Error while running ssh command: %q", err))
	}

	return 0
}

func (c *SSHAgentCommand) Synopsis() string {
	return "Initiate a SSH session with Agent auth"
}

func (c *SSHAgentCommand) Help() string {
	// TODO: Be a bit more bespoke
	helpText := `
Usage: vault ssh-agent [options] username@ip
`
	return strings.TrimSpace(helpText)
}
