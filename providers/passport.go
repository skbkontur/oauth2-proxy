package providers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/golang-jwt/jwt"
	"gopkg.in/yaml.v2"

	"github.com/skbkontur/oauth2-proxy/pkg/apis/options"
	"github.com/skbkontur/oauth2-proxy/pkg/apis/sessions"
)

var (
	passportProviderName = "Passport"
	passportDefaultScope = "profile email"
	ErrKeyFileNotSet     = errors.New("key file not set")
)

// PassportProvider of auth
type PassportProvider struct {
	*ProviderData
	userGroups sync.Map
	auth       options.PassportAuthConfiguration
	publicKey  *rsa.PublicKey
}

// NewPassportProvider creates passport provider
func NewPassportProvider(p *ProviderData) (*PassportProvider, error) {
	var err error
	if p.LoginURL == nil {
		return nil, errors.New("login_url not set")
	}
	if p.RedeemURL == nil {
		return nil, errors.New("redeem_url not set")
	}
	if p.ProfileURL == nil {
		return nil, errors.New("profile_url not set")
	}
	p.setProviderDefaults(providerDefaults{
		name:  passportProviderName,
		scope: googleDefaultScope,
	})
	p.noValidate = true // no validate token
	provider := &PassportProvider{ProviderData: p}
	if err = provider.loadAllowed(); err != nil {
		return nil, err
	}
	if err = provider.loadKey(); err != nil {
		return nil, err
	}

	return provider, nil
}

func (p *PassportProvider) loadKey() error {
	passportKey := os.Getenv("PASSPORT_KEY")
	if passportKey == "" {
		return ErrKeyFileNotSet
	}
	b, err := os.ReadFile(passportKey)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return errors.New("public key decode error")
	}

	pubkeyinterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	p.publicKey = pubkeyinterface.(*rsa.PublicKey)

	return nil
}

func (p *PassportProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, "POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenStr := p.ClientID + ":" + p.ClientSecret
	token := []byte(tokenStr)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(token)))

	resp, err := p.apiRequest(req)
	if err != nil {
		return nil, err
	}
	accessToken, err := resp.Get("access_token").String()
	idToken, _ := resp.Get("id_token").String()
	s = &sessions.SessionState{
		AccessToken: accessToken,
		IDToken:     idToken,
	}

	return
}

func (p *PassportProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	email := ""
	token, err := jwt.Parse(s.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return p.publicKey, nil
	})
	if err == nil && token.Valid {
		login := strings.ToLower(token.Claims.(jwt.MapClaims)["sub"].(string))
		loginParts := strings.Split(login, "\\")
		if len(loginParts) > 1 {
			email = loginParts[1] + "@" + loginParts[0]
			groups, err := p.getUserGroups(token.Raw)
			if err != nil {
				log.Printf("Failed to get %s groups: %s", email, err.Error())
			}
			p.userGroups.Store(email, groups)
		} else {
			email = loginParts[0] + "@local"
			p.userGroups.Store(email, []string{"local"})
		}
	}
	return email, err
}

func (p *PassportProvider) apiRequest(req *http.Request) (*simplejson.Json, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return nil, err
	}
	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, err
	}
	return data, nil

}

func (p *PassportProvider) getUserGroups(token string) ([]string, error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	req, err := http.NewRequest("GET", p.ProfileURL.String(), bytes.NewBufferString(params.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	if err != nil {
		log.Printf("failed building request %s", err.Error())
		return nil, err
	}
	json, err := p.apiRequest(req)
	if err != nil {
		log.Printf("failed making request %s", err.Error())
		return nil, err
	}

	groupJson := json.Get("group")
	groups, err := groupJson.String()
	if err == nil {
		return strings.Split(groups, ","), nil
	}
	return groupJson.StringArray()
}

// ValidateRequest validates that the request fits configured provider
// authorization groups
func (p *PassportProvider) ValidateRequest(req *http.Request, s *sessions.SessionState) (bool, error) {
	if s == nil {
		return false, errors.New("session not established")
	}
	uri := strings.Split(req.Host, ":")[0] + req.URL.Path
	allowedGroups := p.getAllowedGroups(uri)
	_, exAll := allowedGroups["*"]
	if exAll {
		return true, nil
	}
	groups, isKnownUser := p.userGroups.Load(s.Email)
	if !isKnownUser {
		return false, errors.New("session need to be re-established")
	}
	for _, group := range groups.([]string) {
		val, ex := allowedGroups[group]
		if ex && val {
			return true, nil
		}
	}

	return false, nil
}

// GetLoginURL with typical oauth parameters
func (p *PassportProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

func (p *PassportProvider) loadAllowed() error {
	auth := os.Getenv("AUTH_FILE")
	if auth != "" {
		yamlFile, err := os.ReadFile(auth)
		if err != nil {
			return fmt.Errorf("auth file load err %v, %s ", err, auth)
		}
		err = yaml.Unmarshal(yamlFile, &p.auth)
		if err != nil {
			return fmt.Errorf("auth file unmarshall err %v, %s ", err, auth)
		}
	}
	return nil
}

func (p *PassportProvider) getAllowedGroups(uri string) map[string]bool {
	bestMatch := ""
	for key := range p.auth {
		if strings.HasPrefix(uri, key) {
			if len(bestMatch) < len(key) {
				bestMatch = key
			}
		}
	}
	groups, ex := p.auth[bestMatch]
	res := make(map[string]bool)
	if ex {
		for _, group := range groups {
			res[group] = true
		}
	}
	return res
}
