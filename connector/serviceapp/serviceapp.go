package serviceapp

import (
	"encoding/json"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// serviceAppConnector is a connector that requires no user interaction to login.
type serviceAppConnector struct {
	config *Config
	Logger log.Logger
}

type OktaResponse struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
}

// LoginURL returns the URL to redirect the user to log in with.
func (sac *serviceAppConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

// HandleCallback parses the request and returns the user's identity
func (sac *serviceAppConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", sac.config.Scope)

	client := &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest(http.MethodPost, sac.config.AuthUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return identity, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("authorization", sac.config.AuthHeader)

	response, err := client.Do(req)
	if err != nil {
		return identity, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return identity, err
	}
	bodyString := string(bodyBytes)
	sac.Logger.Info(bodyString)

	if response.StatusCode == http.StatusOK {
		payload := OktaResponse{}
		err = json.Unmarshal(bodyBytes, &payload)
		if err != nil {
			return identity, err
		}

		return connector.Identity{
			UserID: sac.config.AuthHeader,
			//Username: payload.AccessToken,
		}, nil
	} else {
		return identity, errors.New(bodyString)
	}

}

// Config holds configuration options for Service App logins.
type Config struct {
	// Auth Provider
	Provider string `json:"provider"`
	// The Authorization URL.
	AuthUrl string `json:"authUrl"`
	// Authorization Header
	AuthHeader string `json:"authHeader"`

	Scope string `json:"scope"`
}

// Open returns an authentication strategy which requires no user interaction.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	return &serviceAppConnector{c, logger}, nil
}
