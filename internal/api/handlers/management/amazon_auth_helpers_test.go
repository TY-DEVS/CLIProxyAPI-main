package management

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/amazon"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type stubAmazonAuthService struct {
	registerClientFn        func(context.Context, string, string) (*amazon.TokenData, error)
	generateAuthURLFn       func(string, string, string, *amazon.PKCECodes) (string, error)
	exchangeAuthorizationFn func(context.Context, string, string, string, string, *amazon.PKCECodes) (*amazon.AuthBundle, error)
	refreshTokensFn         func(context.Context, string, string, string) (*amazon.AuthBundle, error)
}

func (s *stubAmazonAuthService) RegisterClient(ctx context.Context, clientName, redirectURI string) (*amazon.TokenData, error) {
	return s.registerClientFn(ctx, clientName, redirectURI)
}

func (s *stubAmazonAuthService) GenerateAuthURL(clientID, redirectURI, state string, pkceCodes *amazon.PKCECodes) (string, error) {
	return s.generateAuthURLFn(clientID, redirectURI, state, pkceCodes)
}

func (s *stubAmazonAuthService) ExchangeAuthorizationCode(ctx context.Context, clientID, clientSecret, code, redirectURI string, pkceCodes *amazon.PKCECodes) (*amazon.AuthBundle, error) {
	return s.exchangeAuthorizationFn(ctx, clientID, clientSecret, code, redirectURI, pkceCodes)
}

func (s *stubAmazonAuthService) RefreshTokens(ctx context.Context, clientID, clientSecret, refreshToken string) (*amazon.AuthBundle, error) {
	return s.refreshTokensFn(ctx, clientID, clientSecret, refreshToken)
}

func TestBuildAmazonQuotaRequestContract(t *testing.T) {
	contract, err := buildAmazonQuotaRequestContract()
	if err != nil {
		t.Fatalf("buildAmazonQuotaRequestContract() error = %v", err)
	}
	if contract.URL != "https://codewhisperer.us-east-1.amazonaws.com/?origin=IDE" {
		t.Fatalf("unexpected URL: %q", contract.URL)
	}
	if got := contract.Headers["Content-Type"]; got != "application/x-amz-json-1.0" {
		t.Fatalf("unexpected content type: %q", got)
	}
	if got := contract.Headers["X-Amz-Target"]; got != "AmazonCodeWhispererService.GetUsageLimits" {
		t.Fatalf("unexpected x-amz-target: %q", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(contract.Body, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["origin"] != "IDE" {
		t.Fatalf("origin = %#v, want IDE", payload["origin"])
	}
	if payload["isEmailRequired"] != true {
		t.Fatalf("isEmailRequired = %#v, want true", payload["isEmailRequired"])
	}
}

func TestFetchAmazonModelsWithBaseURLParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.String() != "/?origin=CLI" {
			t.Fatalf("url = %s, want /?origin=CLI", r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("authorization = %q, want bearer token", got)
		}
		if got := r.Header.Get("X-Amz-Target"); got != "AmazonCodeWhispererService.ListAvailableModels" {
			t.Fatalf("x-amz-target = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if string(body) != "{\"maxResults\":50,\"origin\":\"CLI\"}" {
			t.Fatalf("unexpected request body: %s", string(body))
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"models":[{"modelId":"claude-sonnet-4.5","modelName":"claude-sonnet-4.5"}],"defaultModel":{"modelId":"claude-sonnet-4.5","modelName":"claude-sonnet-4.5"}}`))
	}))
	defer server.Close()

	h := &Handler{cfg: &config.Config{}}
	auth := &coreauth.Auth{
		Provider: "amazon",
		Metadata: map[string]any{
			"access_token": "token-123",
			"expired":      time.Now().Add(10 * time.Minute).Format(time.RFC3339),
		},
	}

	models := fetchAmazonModelsWithBaseURL(context.Background(), h, auth, server.URL+"/")
	if len(models) != 1 {
		t.Fatalf("len(models) = %d, want 1", len(models))
	}
	if models[0].ID != "claude-sonnet-4.5" {
		t.Fatalf("model id = %q, want claude-sonnet-4.5", models[0].ID)
	}
}

func TestFetchAmazonModelsWithBaseURLReturnsNilOnForbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer server.Close()

	h := &Handler{cfg: &config.Config{}}
	auth := &coreauth.Auth{
		Provider: "amazon",
		Metadata: map[string]any{
			"access_token": "token-123",
			"expired":      time.Now().Add(10 * time.Minute).Format(time.RFC3339),
		},
	}

	models := fetchAmazonModelsWithBaseURL(context.Background(), h, auth, server.URL+"/")
	if len(models) != 0 {
		t.Fatalf("len(models) = %d, want 0", len(models))
	}
}

func TestRefreshAmazonOAuthAccessTokenUsesCurrentTokenWhenNotExpired(t *testing.T) {
	h := &Handler{}
	auth := &coreauth.Auth{
		Provider: "amazon",
		Metadata: map[string]any{
			"access_token":  "current-token",
			"refresh_token": "refresh-token",
			"client_id":     "client-id",
			"client_secret": "client-secret",
			"region":        "us-east-1",
			"start_url":     "https://view.awsapps.com/start",
			"expired":       time.Now().Add(10 * time.Minute).Format(time.RFC3339),
		},
	}

	token, err := h.refreshAmazonOAuthAccessToken(context.Background(), auth)
	if err != nil {
		t.Fatalf("refreshAmazonOAuthAccessToken() error = %v", err)
	}
	if token != "current-token" {
		t.Fatalf("token = %q, want current-token", token)
	}
}

func TestRefreshAmazonOAuthAccessTokenRefreshesExpiredToken(t *testing.T) {
	originalFactory := newAmazonAuthService
	defer func() { newAmazonAuthService = originalFactory }()

	newAmazonAuthService = func(cfg *config.Config, region, startURL string) amazonAuthService {
		return &stubAmazonAuthService{
			refreshTokensFn: func(ctx context.Context, clientID, clientSecret, refreshToken string) (*amazon.AuthBundle, error) {
				return &amazon.AuthBundle{TokenData: amazon.TokenData{
					AccessToken:    "fresh-token",
					RefreshToken:   refreshToken,
					TokenType:      "Bearer",
					Expired:        time.Now().Add(time.Hour).Format(time.RFC3339),
					LastRefresh:    time.Now().Format(time.RFC3339),
					Region:         region,
					StartURL:       startURL,
					ConnectionType: "builderId",
				}}, nil
			},
		}
	}

	h := &Handler{cfg: &config.Config{}}
	auth := &coreauth.Auth{
		Provider: "amazon",
		Metadata: map[string]any{
			"access_token":  "stale-token",
			"refresh_token": "refresh-token",
			"client_id":     "client-id",
			"client_secret": "client-secret",
			"region":        "us-east-1",
			"start_url":     "https://view.awsapps.com/start",
			"expired":       time.Now().Add(-time.Minute).Format(time.RFC3339),
		},
	}

	token, err := h.refreshAmazonOAuthAccessToken(context.Background(), auth)
	if err != nil {
		t.Fatalf("refreshAmazonOAuthAccessToken() error = %v", err)
	}
	if token != "fresh-token" {
		t.Fatalf("token = %q, want fresh-token", token)
	}
	if got := auth.Metadata["access_token"]; got != "fresh-token" {
		t.Fatalf("metadata access_token = %#v, want fresh-token", got)
	}
}

func TestGetAuthFileModelsAmazonFallsBackToStaticDefinitions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "amazon-1.json",
		FileName: "amazon-1.json",
		Provider: "amazon",
		Metadata: map[string]any{},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	h := &Handler{authManager: manager}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/models?name=amazon-1.json", nil)

	h.GetAuthFileModels(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Models []registry.ModelInfo `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(payload.Models) == 0 {
		t.Fatal("expected fallback amazon models, got none")
	}
	if payload.Models[0].Type != "amazon" {
		t.Fatalf("first model type = %q, want amazon", payload.Models[0].Type)
	}
}
