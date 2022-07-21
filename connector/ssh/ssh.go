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
	return &sshConnector{c.HostIP, logger, c}, nil
}

var (
	_ connector.PasswordConnector = sshConnector{}
)

type sshConnector struct {
	host   string
	logger log.Logger
	config *Config
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

	defer func(client *ssh.Client) {
		err := client.Close()
		if err != nil {
			sc.logger.Error(err)
		}
	}(client)

	return connector.Identity{
		UserID:            client.User(),
		Username:          username,
		PreferredUsername: username,
	}, true, nil
}

// connectorData stores information for sessions authenticated by this connector
type connectorData struct {
	RefreshToken []byte
}

// Refresh is used to refresh a session with the refresh token provided by the IdP
func (sc sshConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	return identity, nil
}

func (sc sshConnector) HandleClientCredentials(r *http.Request) (identity connector.Identity, err error) {
	clientID, _, _ := r.BasicAuth()
	subject := r.Header.Get("subject")
	if subject == "" {
		subject = clientID
	}
	return connector.Identity{
		UserID: subject,
	}, nil
}
