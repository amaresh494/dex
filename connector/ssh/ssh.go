package ssh

import (
	"context"
	"errors"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"golang.org/x/crypto/ssh"
	"net/http"
)

// Config holds configuration options for SSH logins.
type Config struct {
	// The host of the SSH server.
	HostIP string `json:"hostIP"`
}

// Open returns an authentication strategy which prompts for a predefined username and password.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	if c.HostIP == "" {
		return nil, errors.New("no host ip supplied")
	}
	return &sshConnector{c.HostIP, logger}, nil
}

var (
	_ connector.PasswordConnector = sshConnector{}
)

type sshConnector struct {
	host   string
	logger log.Logger
}

func (sc sshConnector) Close() error { return nil }

func (sc sshConnector) Prompt() string {
	return ""
}

func (sc sshConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	client, err := ssh.Dial("tcp", sc.host, sshConfig)
	if err != nil {
		fmt.Print(err)
		return connector.Identity{}, false, err
	}

	return connector.Identity{
		UserID:            client.User(),
		Username:          username,
		PreferredUsername: username,
	}, true, nil
}

func (sc sshConnector) HandleClientCredentials(r *http.Request) (identity connector.Identity, err error) {
	clientID, _, _ := r.BasicAuth()
	return connector.Identity{
		UserID: clientID,
	}, nil
}
