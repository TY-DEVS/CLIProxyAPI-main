package amazon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
)

const (
	DefaultStartURL = "https://view.awsapps.com/start"
	DefaultRegion   = "us-east-1"
)

type Auth struct {
	httpClient *http.Client
	region     string
	startURL   string
	baseURL    string
}

func NewAuth(cfg *config.Config, region, startURL string) *Auth {
	resolvedRegion := strings.TrimSpace(region)
	if resolvedRegion == "" {
		resolvedRegion = DefaultRegion
	}
	resolvedStartURL := strings.TrimSpace(startURL)
	if resolvedStartURL == "" {
		resolvedStartURL = DefaultStartURL
	}

	return &Auth{
		httpClient: util.SetProxy(&cfg.SDKConfig, &http.Client{}),
		region:     resolvedRegion,
		startURL:   resolvedStartURL,
	}
}

func (a *Auth) oidcBaseURL() string {
	if strings.TrimSpace(a.baseURL) != "" {
		return a.baseURL
	}
	return fmt.Sprintf("https://oidc.%s.amazonaws.com", a.region)
}

func GeneratePKCECodes() (*PKCECodes, error) {
	bytes := make([]byte, 96)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	verifier := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
	return &PKCECodes{CodeVerifier: verifier, CodeChallenge: challenge}, nil
}

func (a *Auth) RegisterClient(ctx context.Context, clientName string) (*TokenData, error) {
	body, err := a.postJSON(ctx, "/client/register", map[string]any{
		"clientName":   clientName,
		"clientType":   "public",
		"startUrl":     a.startURL,
		"startURL":     a.startURL,
		"issuerUrl":    a.startURL,
		"grantTypes":   []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"scopes":       []string{"openid", "profile", "sso:account:access"},
		"redirectUris": []string{},
	})
	if err != nil {
		return nil, err
	}

	var out struct {
		ClientID                  string `json:"clientId"`
		ClientSecret              string `json:"clientSecret"`
		ClientSecretExpiresAt     int64  `json:"clientSecretExpiresAt"`
		RegistrationExpiresAtText string `json:"registrationExpiresAt"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to parse register client response: %w", err)
	}

	registrationExpiresAt := strings.TrimSpace(out.RegistrationExpiresAtText)
	if registrationExpiresAt == "" && out.ClientSecretExpiresAt > 0 {
		registrationExpiresAt = time.Unix(out.ClientSecretExpiresAt, 0).UTC().Format(time.RFC3339)
	}

	return &TokenData{
		ClientID:              out.ClientID,
		ClientSecret:          out.ClientSecret,
		RegistrationExpiresAt: registrationExpiresAt,
		Region:                a.region,
		StartURL:              a.startURL,
		ConnectionType:        "builderId",
	}, nil
}

func (a *Auth) GenerateAuthURL(clientID, redirectURI, state string, pkceCodes *PKCECodes) (string, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("client ID is required")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return "", fmt.Errorf("redirect URI is required")
	}
	if pkceCodes == nil {
		return "", fmt.Errorf("PKCE codes are required")
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scopes":                {"codewhisperer:completions,codewhisperer:analysis,codewhisperer:conversations,codewhisperer:transformations,codewhisperer:taskassist"},
		"state":                 {state},
		"code_challenge":        {pkceCodes.CodeChallenge},
		"code_challenge_method": {"S256"},
	}

	return fmt.Sprintf("%s/authorize?%s", a.oidcBaseURL(), params.Encode()), nil
}

func (a *Auth) StartDeviceAuthorization(ctx context.Context, clientID, clientSecret string) (*DeviceAuthorizationResponse, error) {
	body, err := a.postJSON(ctx, "/device_authorization", map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"startUrl":     a.startURL,
		"startURL":     a.startURL,
	})
	if err != nil {
		return nil, err
	}

	var wire deviceAuthorizationResponseWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse device authorization response: %w", err)
	}

	out := &DeviceAuthorizationResponse{
		DeviceCode:              firstNonEmpty(wire.DeviceCode, wire.DeviceCodeCamel),
		UserCode:                firstNonEmpty(wire.UserCode, wire.UserCodeCamel),
		VerificationURI:         firstNonEmpty(wire.VerificationURI, wire.VerificationURICamel),
		VerificationURIComplete: firstNonEmpty(wire.VerificationURIComplete, wire.VerificationURICompleteCam),
		ExpiresIn:               firstPositive(wire.ExpiresIn, wire.ExpiresInCamel),
		Interval:                wire.Interval,
	}

	if out.DeviceCode == "" && out.UserCode == "" && out.VerificationURI == "" && out.VerificationURIComplete == "" {
		return nil, fmt.Errorf("amazon device authorization returned no usable fields: %s", strings.TrimSpace(string(body)))
	}

	return out, nil
}

func (a *Auth) ExchangeDeviceCode(ctx context.Context, clientID, clientSecret, deviceCode string) (*AuthBundle, error) {
	body, err := a.postJSON(ctx, "/token", map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
		"deviceCode":   deviceCode,
	})
	if err != nil {
		return nil, err
	}

	var out TokenData
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	out.Region = a.region
	out.StartURL = a.startURL
	out.ConnectionType = "builderId"
	out.LastRefresh = time.Now().Format(time.RFC3339)
	if out.ExpiresIn > 0 {
		out.Expired = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second).Format(time.RFC3339)
	}

	return &AuthBundle{TokenData: out}, nil
}

func (a *Auth) ExchangeAuthorizationCode(ctx context.Context, clientID, clientSecret, code, redirectURI string, pkceCodes *PKCECodes) (*AuthBundle, error) {
	if pkceCodes == nil {
		return nil, fmt.Errorf("PKCE codes are required for token exchange")
	}
	body, err := a.postJSON(ctx, "/token", map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"grantType":    "authorization_code",
		"code":         code,
		"redirectUri":  redirectURI,
		"codeVerifier": pkceCodes.CodeVerifier,
	})
	if err != nil {
		return nil, err
	}

	var out TokenData
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to parse authorization code token response: %w", err)
	}
	out.Region = a.region
	out.StartURL = a.startURL
	out.ConnectionType = "builderId"
	out.LastRefresh = time.Now().Format(time.RFC3339)
	if out.ExpiresIn > 0 {
		out.Expired = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second).Format(time.RFC3339)
	}

	return &AuthBundle{TokenData: out}, nil
}

func (a *Auth) postJSON(ctx context.Context, path string, payload map[string]any) ([]byte, error) {
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.oidcBaseURL()+path, bytes.NewReader(rawBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}