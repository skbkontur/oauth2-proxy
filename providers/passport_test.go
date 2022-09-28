package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/skbkontur/oauth2-proxy/pkg/apis/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPassportProviderIncomplete(t *testing.T) {
	// Test that defaults are failing
	os.Setenv("PASSPORT_KEY", "")
	os.Setenv("AUTH_FILE", "")
	p, err := NewPassportProvider(&ProviderData{})
	if err == nil {
		t.Fatalf("default must failed, %#v", p.auth)
	}

	loginUrl, _ := url.Parse("https://passport.test.com/connect/authorize")
	redeemUrl, _ := url.Parse("https://passport.test.com/connect/token")
	profileUrl, _ := url.Parse("https://passport.test.com/connect/userinfo")

	p, err = NewPassportProvider(
		&ProviderData{
			LoginURL:   loginUrl,
			RedeemURL:  redeemUrl,
			ProfileURL: profileUrl,
		},
	)
	if err == nil {
		t.Fatalf("default must failed, %#v", p.auth)
	}
}

func TestNewPassportProviderFromEnv(t *testing.T) {
	g := NewWithT(t)

	_, filename, _, _ := runtime.Caller(0)
	testDir := path.Join(path.Dir(filename), "../testdata/passport")
	pubKey := path.Join(testDir, "passport.pub")
	authFile := path.Join(testDir, "auth.yml")

	loginUrl, _ := url.Parse("https://passport.test.com/connect/authorize")
	redeemUrl, _ := url.Parse("https://passport.test.com/connect/token")
	profileUrl, _ := url.Parse("https://passport.test.com/connect/userinfo")

	// Test that defaults are failing
	os.Setenv("PASSPORT_KEY", pubKey)
	os.Setenv("AUTH_FILE", authFile)
	p, err := NewPassportProvider(
		&ProviderData{
			LoginURL:   loginUrl,
			RedeemURL:  redeemUrl,
			ProfileURL: profileUrl,
		},
	)
	if err != nil {
		t.Fatalf("must success, but err = '%v'", err)
	}
	if p.publicKey == nil {
		t.Errorf("public key not set")
	}
	g.Expect(p.auth).To(Equal(options.PassportAuthConfiguration{"test.com": []string{"*"}}))
}

func TestNewPassportProvider(t *testing.T) {
	g := NewWithT(t)

	_, filename, _, _ := runtime.Caller(0)
	testDir := path.Join(path.Dir(filename), "../testdata/passport")
	pubKey := path.Join(testDir, "passport.pub")
	os.Setenv("PASSPORT_KEY", pubKey)
	authFile := path.Join(testDir, "auth.yml")
	os.Setenv("AUTH_FILE", authFile)

	loginUrl, _ := url.Parse("https://passport.test.com/connect/authorize")
	redeemUrl, _ := url.Parse("https://passport.test.com/connect/token")
	profileUrl, _ := url.Parse("https://passport.test.com/connect/userinfo")

	// Test that defaults are set when calling for a new p with nothing set
	p, err := NewPassportProvider(
		&ProviderData{
			LoginURL:   loginUrl,
			RedeemURL:  redeemUrl,
			ProfileURL: profileUrl,
		},
	)
	g.Expect(err).ToNot(HaveOccurred())
	providerData := p.Data()

	g.Expect(providerData.ProviderName).To(Equal("Passport"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://passport.test.com/connect/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://passport.test.com/connect/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://passport.test.com/connect/userinfo"))
	g.Expect(providerData.ValidateURL.String()).To(Equal(""))
	g.Expect(providerData.Scope).To(Equal("profile email"))
}

func newTestPassportProvider(t *testing.T, serverURL *url.URL, skipNonce bool) *PassportProvider {
	_, filename, _, _ := runtime.Caller(0)
	testDir := path.Join(path.Dir(filename), "../testdata/passport")
	pubKey := path.Join(testDir, "passport.pub")
	os.Setenv("PASSPORT_KEY", pubKey)

	providerData := &ProviderData{
		ProviderName: passportProviderName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		LoginURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/authorize"},
		RedeemURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/access_token"},
		ProfileURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/profile"},
		Scope:       passportDefaultScope,
		EmailClaim:  "email",
		GroupsClaim: "groups",
		UserClaim:   "sub",
	}

	p, err := NewPassportProvider(providerData)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func newPassportServer(body []byte, clientID, clientSecret string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			if username != clientID || password != clientSecret {
				http.Error(rw, "Unauthorized", http.StatusForbidden)
				return
			}
			rw.Header().Add("content-type", "application/json")
			_, _ = rw.Write(body)
			return
		}
		http.Error(rw, "Unauthorized", http.StatusForbidden)
	}))
}

func newTestPassportSetup(t *testing.T, body []byte, clientID, clientSecret string) (*httptest.Server, *PassportProvider) {
	s := newPassportServer(body, clientID, clientSecret)
	u, _ := url.Parse(s.URL)
	provider := newTestPassportProvider(t, u, false)
	return s, provider
}

func TestPassportProviderUnauth(t *testing.T) {
	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   10,
		TokenType:   "Bearer",
		IDToken:     idToken,
	})

	server := newPassportServer(body, clientID, clientSecret+"1")
	u, _ := url.Parse(server.URL)
	provider := newTestPassportProvider(t, u, false)
	defer server.Close()

	_, err := provider.Redeem(context.Background(), provider.RedeemURL.String(), "code1234", "")
	if err == nil || !(strings.Contains(err.Error(), "got 403 ") && strings.Contains(err.Error(), "Unauzorized")) {
		require.Errorf(t, err, "want 403: Unauzorized")
	}
}

func TestPassportProviderRedeem(t *testing.T) {
	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   10,
		TokenType:   "Bearer",
		IDToken:     idToken,
	})

	server, provider := newTestPassportSetup(t, body, clientID, clientSecret)
	defer server.Close()

	session, err := provider.Redeem(context.Background(), provider.RedeemURL.String(), "code1234", "")
	require.NoError(t, err)
	assert.Equal(t, accessToken, session.AccessToken)
	assert.Equal(t, idToken, session.IDToken)
}
