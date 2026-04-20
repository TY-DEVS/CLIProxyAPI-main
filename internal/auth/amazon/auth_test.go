package amazon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestRegisterClientUsesConfiguredStartURLAndRegion(t *testing.T) {
	var seenPath string
	var seenBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		seenBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"clientId":"cid","clientSecret":"sec","clientSecretExpiresAt":1893456000}`))
	}))
	defer srv.Close()

	auth := NewAuth(&config.Config{}, "us-east-1", "https://view.awsapps.com/start")
	auth.httpClient = srv.Client()
	auth.baseURL = srv.URL
	auth.region = "unit-test"

	registration, err := auth.RegisterClient(context.Background(), "CLIProxyAPI-test")
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	if seenPath != "/client/register" {
		t.Fatalf("expected /client/register, got %q", seenPath)
	}
	if !strings.Contains(seenBody, `"startUrl":"https://view.awsapps.com/start"`) {
		t.Fatalf("expected request body to include configured startUrl, body = %s", seenBody)
	}
	if registration.Region != "unit-test" {
		t.Fatalf("expected region unit-test, got %q", registration.Region)
	}
	if registration.ConnectionType != "builderId" {
		t.Fatalf("expected connection type builderId, got %q", registration.ConnectionType)
	}
	if registration.RegistrationExpiresAt != "2030-01-01T00:00:00Z" {
		t.Fatalf("expected derived expiry, got %q", registration.RegistrationExpiresAt)
	}
}

func TestExchangeDeviceCodeSetsExpiryAndConnectionType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600}`))
	}))
	defer srv.Close()

	auth := NewAuth(&config.Config{}, "us-east-1", "https://view.awsapps.com/start")
	auth.httpClient = srv.Client()
	auth.baseURL = srv.URL

	before := time.Now().UTC()
	bundle, err := auth.ExchangeDeviceCode(context.Background(), "cid", "sec", "dc")
	if err != nil {
		t.Fatalf("ExchangeDeviceCode() error = %v", err)
	}

	if bundle.TokenData.AccessToken != "at" {
		t.Fatalf("expected access token at, got %q", bundle.TokenData.AccessToken)
	}
	if bundle.TokenData.ConnectionType != "builderId" {
		t.Fatalf("expected connection type builderId, got %q", bundle.TokenData.ConnectionType)
	}
	if bundle.TokenData.Region != "us-east-1" {
		t.Fatalf("expected region us-east-1, got %q", bundle.TokenData.Region)
	}
	if bundle.TokenData.StartURL != "https://view.awsapps.com/start" {
		t.Fatalf("expected start URL to be preserved, got %q", bundle.TokenData.StartURL)
	}
	if bundle.TokenData.Expired == "" {
		t.Fatal("expected expired timestamp to be set")
	}

	expiresAt, err := time.Parse(time.RFC3339, bundle.TokenData.Expired)
	if err != nil {
		t.Fatalf("time.Parse() error = %v", err)
	}
	if expiresAt.Before(before.Add(59 * time.Minute)) || expiresAt.After(before.Add(61*time.Minute)) {
		t.Fatalf("expected expiry about one hour ahead, got %s", expiresAt.Format(time.RFC3339))
	}
	if bundle.TokenData.LastRefresh == "" {
		t.Fatal("expected last refresh to be set")
	}
}

func TestGeneratePKCECodesProducesVerifierAndChallenge(t *testing.T) {
	codes, err := GeneratePKCECodes()
	if err != nil {
		t.Fatalf("GeneratePKCECodes() error = %v", err)
	}
	if codes == nil {
		t.Fatal("expected PKCE codes to be returned")
	}
	if codes.CodeVerifier == "" || codes.CodeChallenge == "" {
		t.Fatalf("expected verifier and challenge to be non-empty: %+v", codes)
	}
	if codes.CodeVerifier == codes.CodeChallenge {
		t.Fatalf("expected verifier and challenge to differ: %+v", codes)
	}
}

func TestGenerateAuthURLIncludesPKCEParameters(t *testing.T) {
	auth := NewAuth(&config.Config{}, "us-east-1", "https://view.awsapps.com/start")
	auth.baseURL = "https://example.com"

	codes := &PKCECodes{CodeVerifier: "verifier-123", CodeChallenge: "challenge-456"}
	urlString, err := auth.GenerateAuthURL("client-123", "http://127.0.0.1:54545/callback", "state-123", codes)
	if err != nil {
		t.Fatalf("GenerateAuthURL() error = %v", err)
	}
	if !strings.Contains(urlString, "https://example.com/authorize?") {
		t.Fatalf("expected authorize URL to use base URL, got %q", urlString)
	}
	if !strings.Contains(urlString, "response_type=code") {
		t.Fatalf("expected response_type=code in authorize URL: %s", urlString)
	}
	if !strings.Contains(urlString, "client_id=client-123") {
		t.Fatalf("expected client_id in authorize URL: %s", urlString)
	}
	if !strings.Contains(urlString, "redirect_uri=http%3A%2F%2F127.0.0.1%3A54545%2Fcallback") {
		t.Fatalf("expected redirect_uri in authorize URL: %s", urlString)
	}
	if !strings.Contains(urlString, "state=state-123") {
		t.Fatalf("expected state in authorize URL: %s", urlString)
	}
	if !strings.Contains(urlString, "code_challenge=challenge-456") {
		t.Fatalf("expected code_challenge in authorize URL: %s", urlString)
	}
	if !strings.Contains(urlString, "code_challenge_method=S256") {
		t.Fatalf("expected code_challenge_method in authorize URL: %s", urlString)
	}
}

func TestExchangeAuthorizationCodeSetsExpiryAndConnectionType(t *testing.T) {
	var seenPath string
	var seenBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		seenBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600}`))
	}))
	defer srv.Close()

	auth := NewAuth(&config.Config{}, "us-east-1", "https://view.awsapps.com/start")
	auth.httpClient = srv.Client()
	auth.baseURL = srv.URL

	before := time.Now().UTC()
	bundle, err := auth.ExchangeAuthorizationCode(context.Background(), "cid", "sec", "auth-code", "http://127.0.0.1:54545/callback", &PKCECodes{CodeVerifier: "verifier-123", CodeChallenge: "challenge-456"})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	if seenPath != "/token" {
		t.Fatalf("expected /token, got %q", seenPath)
	}
	if !strings.Contains(seenBody, `"grantType":"authorization_code"`) {
		t.Fatalf("expected authorization_code grant, body = %s", seenBody)
	}
	if !strings.Contains(seenBody, `"codeVerifier":"verifier-123"`) {
		t.Fatalf("expected code verifier in request body, body = %s", seenBody)
	}
	if bundle.TokenData.ConnectionType != "builderId" {
		t.Fatalf("expected connection type builderId, got %q", bundle.TokenData.ConnectionType)
	}
	if bundle.TokenData.Expired == "" {
		t.Fatal("expected expired timestamp to be set")
	}
	if bundle.TokenData.LastRefresh == "" {
		t.Fatal("expected last refresh to be set")
	}

	expiresAt, err := time.Parse(time.RFC3339, bundle.TokenData.Expired)
	if err != nil {
		t.Fatalf("time.Parse() error = %v", err)
	}
	if expiresAt.Before(before.Add(59 * time.Minute)) || expiresAt.After(before.Add(61*time.Minute)) {
		t.Fatalf("expected expiry about one hour ahead, got %s", expiresAt.Format(time.RFC3339))
	}
}
