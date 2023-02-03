package CxSASTClientGo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func OauthCodeCallbackURL(base_url, client_id, redirect_uri, scope, state string) string {
	return fmt.Sprintf("%v/cxrestapi/auth/identity/connect/authorize?client_id=%v&redirect_uri=%v&response_type=code&scope=%v&state=%v", base_url, client_id, redirect_uri, scope, state)
}

func OauthCodeHTTPClient(client *http.Client, base_url, client_id, oauth_code, oauth_scope, oauth_redirect_uri string) (*http.Client, error) {
	// should auto-refresh afterwards
	//fmt.Println("SASTRefreshClient - GetAccessToken")
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	params := url.Values{
		"client_id":    {client_id},
		"code":         {oauth_code},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {oauth_redirect_uri},
	}
	resp, err := client.Post(fmt.Sprintf("%v/cxrestapi/auth/identity/connect/token", base_url), "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	returnval := map[string]interface{}{}
	err = json.Unmarshal(body, &returnval)
	if err != nil {
		return nil, err
	}

	if returnval["access_token"] == nil {
		return nil, errors.New(fmt.Sprintf("no access_token returned in response: %v", string(body)))
	}
	if returnval["refresh_token"] == nil {
		return nil, errors.New(fmt.Sprintf("no refresh_token returned in response: %v", string(body)))
	}

	conf := &oauth2.Config{
		ClientID: client_id,
		Endpoint: oauth2.Endpoint{
			TokenURL: fmt.Sprintf("%v/cxrestapi/auth/identity/connect/token", base_url),
		},
	}

	refreshToken := &oauth2.Token{
		AccessToken:  returnval["access_token"].(string),
		RefreshToken: returnval["refresh_token"].(string),
		Expiry:       time.Now().UTC().Add(time.Duration(returnval["expires_in"].(float64)) * time.Second),
	}

	//fmt.Printf("refresh token: %v\n", refreshToken.RefreshToken)
	return conf.Client(ctx, refreshToken), nil
}

func OauthCredentialClient(client *http.Client, base_url, client_id, client_secret, username, password string, scopes []string) *http.Client {
	ctx := context.Background()
	// client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	conf := &PasswordConfig{
		Config: oauth2.Config{
			ClientID:     client_id,
			ClientSecret: client_secret,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				TokenURL: fmt.Sprintf("%v/cxrestapi/auth/identity/connect/token", base_url),
			},
		},
		Username: username,
		Password: password,
	}

	return conf.Client(ctx)
}

type PasswordConfig struct {
	Config      oauth2.Config
	Username    string
	Password    string
	ReuseSource *PasswordTokenSource
}

func (c *PasswordConfig) Token(ctx context.Context) (*oauth2.Token, error) {
	//	fmt.Println("PasswordConfig.Token")
	return c.TokenSource(ctx).Token()
}

func (c *PasswordConfig) Client(ctx context.Context) *http.Client {
	//	fmt.Println("PasswordConfig.Client")
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

func (c *PasswordConfig) TokenSource(ctx context.Context) oauth2.TokenSource {
	//	fmt.Println("PasswordConfig.TokenSource")
	if c.ReuseSource == nil {
		c.ReuseSource = &PasswordTokenSource{
			ctx:  ctx,
			conf: c,
		}
	}
	return c.ReuseSource
}

type PasswordTokenSource struct {
	ctx       context.Context
	conf      *PasswordConfig
	LastToken *oauth2.Token
}

func (c *PasswordTokenSource) Token() (*oauth2.Token, error) {
	//	fmt.Println("PasswordTokenSource.Token")
	if c.LastToken.Valid() {
		//		fmt.Println("Last token is still valid")
		return c.LastToken, nil
	}
	var err error
	c.LastToken, err = c.conf.Config.PasswordCredentialsToken(c.ctx, c.conf.Username, c.conf.Password)
	return c.LastToken, err
}

/*
	OIDC client for refresh tokens, set up on SAST:

	{
		"updateAccessTokenClaimsOnRefresh": true,
		"accessTokenType": 0,
		"includeJwtId": true,
		"alwaysIncludeUserClaimsInIdToken": true,
		"clientId": "custom_client",
		"clientName": "custom_client",
		"allowOfflineAccess": true,
		"clientSecrets": [],
		"allowedGrantTypes": [
			"offline_access",
			"authorization_code"
		],
		"allowedScopes": [
			"sast_api",
			"access_control_api"
		],
		"enabled": true,
		"requireClientSecret": false,
		"redirectUris": [
			"http://custom_client:8000/oauth_redirect.html",
			"http://custom_client/oauth_redirect.html"
		],
		"postLogoutRedirectUris": [],
		"frontChannelLogoutUri": null,
		"frontChannelLogoutSessionRequired": false,
		"backChannelLogoutUri": null,
		"backChannelLogoutSessionRequired": false,
		"identityTokenLifetime": 3660,
		"accessTokenLifetime": 3660,
		"authorizationCodeLifetime": 3660,
		"absoluteRefreshTokenLifetime": 3660,
		"slidingRefreshTokenLifetime": 3660,
		"refreshTokenUsage": 3660,
		"refreshTokenExpiration": 3660,
		"allowedCorsOrigins": [],
		"allowAccessTokensViaBrowser": true,
		"claims": [],
		"clientClaimsPrefix": null,
		"requirePkce": false
	}

*/
