package ssh

import (
	"context"
	"errors"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds configuration options for SSH logins.
type Config struct {
	// The host of the SSH server.
	HostIP string `json:"hostIP"`

	Username string `json:"username"`

	Password string `json:"password"`
}

// Open returns an authentication strategy which prompts for a predefined username and password.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	if c.Username == "" {
		return nil, errors.New("no username supplied")
	}
	if c.Password == "" {
		return nil, errors.New("no password supplied")
	}
	return &sshConnector{c.Username, c.Password, logger}, nil
}

var (
	_ connector.PasswordConnector = sshConnector{}
)

type sshConnector struct {
	username string
	password string
	logger   log.Logger
}

func (sc sshConnector) Close() error { return nil }

func (sc sshConnector) Prompt() string {
	return ""
}

func (sc sshConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	if username == sc.username && password == sc.password {
		return connector.Identity{
			UserID:        "9134",
			Username:      "Amaresh",
			Email:         "amarch@altair.com",
			EmailVerified: true,
			ConnectorData: []byte(`{"test": "true"}`),
		}, true, nil
	}
	return identity, false, nil
}
