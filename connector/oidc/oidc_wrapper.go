package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
)

type oidcProviderJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

// OidcProviderUrls represents an OpenID Connect server's urls.
type OidcProviderUrls struct {
	Issuer      string
	AuthURL     string
	TokenURL    string
	UserInfoURL string
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

func GetProviderUrls(ctx context.Context, issuer string) (*OidcProviderUrls, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p oidcProviderJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	return &OidcProviderUrls{
		Issuer:      p.Issuer,
		AuthURL:     p.AuthURL,
		TokenURL:    p.TokenURL,
		UserInfoURL: p.UserInfoURL,
	}, nil
}

type Json map[string]interface{}

func (j Json) Get(key string) (string, bool) {
	if j[key] != nil {
		return fmt.Sprintf("%v", j[key]), true
	} else {
		return "", false
	}

}

func (j Json) getSubtree(key string) Json {
	return j[key].(map[string]interface{})
}

type Array []interface{}

func (a Array) Get(key int) Json {
	return a[key].(map[string]interface{})
}

func (j Json) getSubtreeArray(key string) Array {
	var arr Array
	arr = j[key].([]interface{})
	/*fmt.Println(arr)
	fmt.Println(len(arr))
	if len(arr)>0{
		fmt.Printf("Type:%T",arr[0])
		fmt.Println("Arr:",arr.Get(0).Get("Control"))
	}*/
	return arr
}
