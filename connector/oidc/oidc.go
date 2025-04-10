// Package oidc implements logging in through OpenID Connect providers.
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config holds configuration options for OpenID Connect logins.
type Config struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`

	// Causes client_secret to be passed as POST parameters instead of basic
	// auth. This is specifically "NOT RECOMMENDED" by the OAuth2 RFC, but some
	// providers require it.
	//
	// https://tools.ietf.org/html/rfc6749#section-2.3.1
	BasicAuthUnsupported *bool `json:"basicAuthUnsupported"`

	Scopes []string `json:"scopes"` // defaults to "profile" and "email"

	// Override the value of email_verified to true in the returned claims
	InsecureSkipEmailVerified bool `json:"insecureSkipEmailVerified"`

	// InsecureEnableGroups enables groups claims. This is disabled by default until https://github.com/dexidp/dex/issues/1065 is resolved
	InsecureEnableGroups bool `json:"insecureEnableGroups"`

	// AcrValues (Authentication Context Class Reference Values) that specifies the Authentication Context Class Values
	// within the Authentication Request that the Authorization Server is being requested to use for
	// processing requests from this Client, with the values appearing in order of preference.
	AcrValues []string `json:"acrValues"`

	// GetUserInfo uses the userinfo endpoint to get additional claims for
	// the token. This is especially useful where upstreams return "thin"
	// id tokens
	GetUserInfo bool `json:"getUserInfo"`

	UserIDKey string `json:"userIDKey"`

	UserNameKey string `json:"userNameKey"`

	// PromptType will be used fot the prompt parameter (when offline_access, by default prompt=consent)
	PromptType string `json:"promptType"`

	// OverrideClaimMapping will be used to override the options defined in claimMappings.
	// i.e. if there are 'email' and `preferred_email` claims available, by default Dex will always use the `email` claim independent of the ClaimMapping.EmailKey.
	// This setting allows you to override the default behavior of Dex and enforce the mappings defined in `claimMapping`.
	OverrideClaimMapping bool `json:"overrideClaimMapping"` // defaults to false

	ClaimMapping struct {
		// Configurable key which contains the subject claims
		SubjectKey string `json:"sub"` // defaults to "sub"

		// Configurable key which contains the email claims
		EmailKey string `json:"email"` // defaults to "email"

		// Configurable key which contains the groups claims
		GroupsKey string `json:"groups"` // defaults to "groups"
	} `json:"claimMapping"`
}

// Domains that don't support basic auth. golang.org/x/oauth2 has an internal
// list, but it only matches specific URLs, not top level domains.
var brokenAuthHeaderDomains = []string{
	// See: https://github.com/dexidp/dex/issues/859
	"okta.com",
	"oktapreview.com",
}

// connectorData stores information for sessions authenticated by this connector
type connectorData struct {
	RefreshToken []byte
}

// Detect auth header provider issues for known providers. This lets users
// avoid having to explicitly set "basicAuthUnsupported" in their config.
//
// Setting the config field always overrides values returned by this function.
func knownBrokenAuthHeaderProvider(issuerURL string) bool {
	if u, err := url.Parse(issuerURL); err == nil {
		for _, host := range brokenAuthHeaderDomains {
			if u.Host == host || strings.HasSuffix(u.Host, "."+host) {
				return true
			}
		}
	}
	return false
}

// Open returns a connector which can be used to login users through an upstream
// OpenID Connect provider.
func (c *Config) Open(id string, logger log.Logger) (conn connector.Connector, err error) {
	ctx, cancel := context.WithCancel(context.Background())

	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	endpoint := provider.Endpoint()

	if c.BasicAuthUnsupported != nil {
		// Setting "basicAuthUnsupported" always overrides our detection.
		if *c.BasicAuthUnsupported {
			endpoint.AuthStyle = oauth2.AuthStyleInParams
		}
	} else if knownBrokenAuthHeaderProvider(c.Issuer) {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}

	// PromptType should be "consent" by default, if not set
	if c.PromptType == "" {
		c.PromptType = "consent"
	}

	providerUrls, err := GetProviderUrls(ctx, c.Issuer)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider urls: %v", err)
	}

	clientID := c.ClientID
	return &oidcConnector{
		provider:    provider,
		redirectURI: c.RedirectURI,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     endpoint,
			Scopes:       scopes,
			RedirectURL:  c.RedirectURI,
		},
		verifier: provider.Verifier(
			&oidc.Config{ClientID: clientID},
		),
		logger:                    logger,
		cancel:                    cancel,
		insecureSkipEmailVerified: c.InsecureSkipEmailVerified,
		insecureEnableGroups:      c.InsecureEnableGroups,
		acrValues:                 c.AcrValues,
		getUserInfo:               c.GetUserInfo,
		promptType:                c.PromptType,
		userIDKey:                 c.UserIDKey,
		userNameKey:               c.UserNameKey,
		overrideClaimMapping:      c.OverrideClaimMapping,
		subjectKey:                c.ClaimMapping.SubjectKey,
		emailKey:                  c.ClaimMapping.EmailKey,
		groupsKey:                 c.ClaimMapping.GroupsKey,
		providerUrls:              providerUrls,
	}, nil
}

var (
	_ connector.CallbackConnector = (*oidcConnector)(nil)
	_ connector.RefreshConnector  = (*oidcConnector)(nil)
)

type oidcConnector struct {
	provider                  *oidc.Provider
	redirectURI               string
	oauth2Config              *oauth2.Config
	verifier                  *oidc.IDTokenVerifier
	cancel                    context.CancelFunc
	logger                    log.Logger
	insecureSkipEmailVerified bool
	insecureEnableGroups      bool
	acrValues                 []string
	getUserInfo               bool
	promptType                string
	userIDKey                 string
	userNameKey               string
	overrideClaimMapping      bool
	subjectKey                string
	emailKey                  string
	groupsKey                 string
	providerUrls              *OidcProviderUrls
}

func (c *oidcConnector) Close() error {
	c.cancel()
	return nil
}

func (c *oidcConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	var opts []oauth2.AuthCodeOption

	if len(c.acrValues) > 0 {
		acrValues := strings.Join(c.acrValues, " ")
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", acrValues))
	}

	if s.OfflineAccess {
		opts = append(opts, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", c.promptType))
	}
	return c.oauth2Config.AuthCodeURL(state, opts...), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

type caller uint

const (
	createCaller caller = iota
	refreshCaller
)

func (c *oidcConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}
	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to get token: %v", err)
	}
	return c.createIdentity(r.Context(), identity, token, createCaller)
}

// Refresh is used to refresh a session with the refresh token provided by the IdP
func (c *oidcConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	cd := connectorData{}
	err := json.Unmarshal(identity.ConnectorData, &cd)
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to unmarshal connector data: %v", err)
	}

	t := &oauth2.Token{
		RefreshToken: string(cd.RefreshToken),
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.oauth2Config.TokenSource(ctx, t).Token()
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to get refresh token: %v", err)
	}
	return c.createIdentity(ctx, identity, token, refreshCaller)
}

func (c *oidcConnector) createIdentity(ctx context.Context, identity connector.Identity, token *oauth2.Token, caller caller) (connector.Identity, error) {
	var claims map[string]interface{}

	rawIDToken, ok := token.Extra("id_token").(string)
	if ok {
		idToken, err := c.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return identity, fmt.Errorf("oidc: failed to verify ID Token: %v", err)
		}

		if err := idToken.Claims(&claims); err != nil {
			return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
		}
	} else if caller != refreshCaller {
		// ID tokens aren't mandatory in the reply when using a refresh_token grant
		return identity, errors.New("oidc: no id_token in token response")
	}
	c.logger.Debugf("OIDC provider access token: %s", token.AccessToken)

	// We immediately want to run getUserInfo if configured before we validate the claims
	if c.getUserInfo {
		userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return identity, fmt.Errorf("oidc: error loading userinfo: %v", err)
		}
		if err := userInfo.Claims(&claims); err != nil {
			return identity, fmt.Errorf("oidc: failed to decode userinfo claims: %v", err)
		}
	}

	const subjectClaimKey = "sub"
	subject, found := claims[subjectClaimKey].(string)
	if (!found || c.overrideClaimMapping) && c.subjectKey != "" {
		subject, ok = claims[c.subjectKey].(string)
		if !ok {
			return identity, fmt.Errorf("missing \"%s\" claim", c.subjectKey)
		}
	}

	userNameKey := "name"
	if c.userNameKey != "" {
		userNameKey = c.userNameKey
	}
	name, found := claims[userNameKey].(string)
	if !found {
		return identity, fmt.Errorf("missing \"%s\" claim", userNameKey)
	}

	preferredUsername, found := claims["preferred_username"].(string)
	if !found {
		return identity, fmt.Errorf("missing preferred_username claim")
	}

	hasEmailScope := false
	for _, s := range c.oauth2Config.Scopes {
		if s == "email" {
			hasEmailScope = true
			break
		}
	}

	var email string
	emailKey := "email"
	email, found = claims[emailKey].(string)
	if (!found || c.overrideClaimMapping) && c.emailKey != "" {
		emailKey = c.emailKey
		email, found = claims[emailKey].(string)
	}

	if !found && hasEmailScope {
		return identity, fmt.Errorf("missing email claim, not found \"%s\" key", emailKey)
	}

	emailVerified, found := claims["email_verified"].(bool)
	if !found {
		if c.insecureSkipEmailVerified {
			emailVerified = true
		} else if hasEmailScope {
			return identity, errors.New("missing \"email_verified\" claim")
		}
	}

	var groups []string
	if c.insecureEnableGroups {
		groupsKey := "groups"
		vs, found := claims[groupsKey].([]interface{})
		if (!found || c.overrideClaimMapping) && c.groupsKey != "" {
			groupsKey = c.groupsKey
			vs, found = claims[groupsKey].([]interface{})
		}

		if found {
			for _, v := range vs {
				if s, ok := v.(string); ok {
					groups = append(groups, s)
				} else {
					return identity, fmt.Errorf("malformed \"%v\" claim", groupsKey)
				}
			}
		}
	}

	cd := connectorData{
		RefreshToken: []byte(token.RefreshToken),
	}

	connData, err := json.Marshal(&cd)
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to encode connector data: %v", err)
	}

	identity = connector.Identity{
		UserID:            subject,
		Username:          name,
		PreferredUsername: preferredUsername,
		Email:             email,
		EmailVerified:     emailVerified,
		Groups:            groups,
		ConnectorData:     connData,
	}

	if c.userIDKey != "" {
		userID, found := claims[c.userIDKey].(string)
		if !found {
			return identity, fmt.Errorf("oidc: not found %v claim", c.userIDKey)
		}
		identity.UserID = userID
	}

	return identity, nil
}

type ClientCredentialsResponse struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (c *oidcConnector) HandleClientCredentials(r *http.Request) (identity connector.Identity, err error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "client_credentials")

	authorizationHeader := "Basic " +
		base64.StdEncoding.EncodeToString([]byte(c.oauth2Config.ClientID+":"+c.oauth2Config.ClientSecret))

	subject := r.Header.Get("subject")

	endpoint := c.provider.Endpoint()
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest(http.MethodPost, endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return identity, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("authorization", authorizationHeader)

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

	if response.StatusCode == http.StatusOK {
		payload := ClientCredentialsResponse{}
		err = json.Unmarshal(bodyBytes, &payload)
		if err != nil {
			return identity, err
		}

		identity := connector.Identity{
			UserID: subject,
		}
		return identity, nil
	} else {
		return identity, errors.New(bodyString)
	}
}

func (c *oidcConnector) HandleOnBehalf(r *http.Request) (identity connector.Identity, err error) {
	authorizationHeader := "Bearer " + r.PostFormValue("access_token")

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest(http.MethodGet, c.providerUrls.UserInfoURL, nil)
	if err != nil {
		c.logger.Infof("HandleOnBehalf: %s", err)
		return identity, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("authorization", authorizationHeader)

	response, err := client.Do(req)
	if err != nil {
		return identity, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return identity, err
	}

	if response.StatusCode == http.StatusOK {
		var userInfo Json
		err = json.Unmarshal(bodyBytes, &userInfo)
		if err != nil {
			return identity, err
		}

		const subjectClaimKey = "sub"
		subject, found := userInfo.Get(subjectClaimKey)
		if (!found || c.overrideClaimMapping) && c.subjectKey != "" {
			subject, found = userInfo.Get(c.subjectKey)
			if !found {
				return identity, fmt.Errorf("missing \"%s\" claim", c.subjectKey)
			}
		}

		userNameKey := "name"
		if c.userNameKey != "" {
			userNameKey = c.userNameKey
		}
		name, found := userInfo.Get(userNameKey)
		if !found {
			return identity, fmt.Errorf("missing \"%s\" claim", userNameKey)
		}

		preferredUsername, found := userInfo.Get("preferred_username")
		if !found {
			return identity, fmt.Errorf("missing preferred_username claim")
		}

		hasEmailScope := false
		for _, s := range c.oauth2Config.Scopes {
			if s == "email" {
				hasEmailScope = true
				break
			}
		}

		var email string
		emailKey := "email"
		email, found = userInfo.Get(emailKey)
		if (!found || c.overrideClaimMapping) && c.emailKey != "" {
			emailKey = c.emailKey
			email, found = userInfo.Get(emailKey)
		}

		if !found && hasEmailScope {
			return identity, fmt.Errorf("missing email claim, not found \"%s\" key", emailKey)
		}

		identity = connector.Identity{
			UserID:            subject,
			Username:          name,
			PreferredUsername: preferredUsername,
			Email:             email,
		}

		if c.userIDKey != "" {
			userID, found := userInfo.Get(c.userIDKey)
			if !found {
				return identity, fmt.Errorf("oidc: not found %v claim", c.userIDKey)
			}
			identity.UserID = userID
		}

		return identity, nil
	} else {
		bodyString := string(bodyBytes)
		code := strconv.Itoa(response.StatusCode)
		return identity, errors.New("Failed with status code: " + code + ", message: " + bodyString)
	}
}
