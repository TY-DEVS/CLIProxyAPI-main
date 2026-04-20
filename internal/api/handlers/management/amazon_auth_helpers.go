package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/amazon"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type amazonListAvailableModelsResponse struct {
	Models []struct {
		ModelID   string `json:"modelId"`
		ModelName string `json:"modelName"`
	} `json:"models"`
	DefaultModel struct {
		ModelID   string `json:"modelId"`
		ModelName string `json:"modelName"`
	} `json:"defaultModel"`
}

func (h *Handler) RequestAmazonToken(c *gin.Context) {
	package management

	import (
		"bytes"
		"context"
		"encoding/json"
		"fmt"
		"io"
		"net/http"
		"os"
		"path/filepath"
		"strings"
		"time"

		"github.com/gin-gonic/gin"
		"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/amazon"
		"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
		"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
		"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
		coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	)

	const amazonCodeWhispererRuntimeURL = "https://codewhisperer.us-east-1.amazonaws.com/"

	type amazonAuthService interface {
		RegisterClient(ctx context.Context, clientName, redirectURI string) (*amazon.TokenData, error)
		GenerateAuthURL(clientID, redirectURI, state string, pkceCodes *amazon.PKCECodes) (string, error)
		ExchangeAuthorizationCode(ctx context.Context, clientID, clientSecret, code, redirectURI string, pkceCodes *amazon.PKCECodes) (*amazon.AuthBundle, error)
		RefreshTokens(ctx context.Context, clientID, clientSecret, refreshToken string) (*amazon.AuthBundle, error)
	}

	var newAmazonAuthService = func(cfg *config.Config, region, startURL string) amazonAuthService {
		return amazon.NewAuth(cfg, region, startURL)
	}

	type amazonListAvailableModelsResponse struct {
		Models []struct {
			ModelID   string `json:"modelId"`
			ModelName string `json:"modelName"`
		} `json:"models"`
		DefaultModel struct {
			ModelID   string `json:"modelId"`
			ModelName string `json:"modelName"`
		} `json:"defaultModel"`
	}

	type amazonQuotaRequestContract struct {
		URL     string
		Headers map[string]string
		Body    []byte
	}

	func (h *Handler) RequestAmazonToken(c *gin.Context) {
		ctx := context.Background()
		ctx = PopulateAuthContext(ctx, c)

		region := strings.TrimSpace(c.Query("region"))
		startURL := strings.TrimSpace(c.Query("start_url"))
		authSvc := newAmazonAuthService(h.cfg, region, startURL)
		pkceCodes, errPKCE := amazon.GeneratePKCECodes()
		if errPKCE != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate amazon pkce codes: %v", errPKCE)})
			return
		}

		redirectURI := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", amazonCallbackPort)
		clientName := fmt.Sprintf("CLIProxyAPI-%d", time.Now().Unix())
		registration, errRegister := authSvc.RegisterClient(ctx, clientName, redirectURI)
		if errRegister != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to register amazon oidc client: %v", errRegister)})
			return
		}

		state, errState := misc.GenerateRandomState()
		if errState != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate amazon state: %v", errState)})
			return
		}
		RegisterOAuthSession(state, "amazon")

		authURL, errURL := authSvc.GenerateAuthURL(registration.ClientID, redirectURI, state, pkceCodes)
		if errURL != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate amazon authorization url: %v", errURL)})
			return
		}

		isWebUI := isWebUIRequest(c)
		var forwarder *callbackForwarder
		if isWebUI {
			targetURL, errTarget := h.managementCallbackURL("/amazon/oauth/callback")
			if errTarget != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "callback server unavailable"})
				return
			}
			var errStart error
			if forwarder, errStart = startCallbackForwarder(amazonCallbackPort, "amazon", targetURL); errStart != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start callback server"})
				return
			}
		}

		go h.completeAmazonOAuthFlow(ctx, state, redirectURI, pkceCodes, registration, authSvc, isWebUI, forwarder)

		c.JSON(http.StatusOK, gin.H{"status": "ok", "url": authURL, "state": state})
	}

	func (h *Handler) completeAmazonOAuthFlow(
		ctx context.Context,
		state string,
		redirectURI string,
		pkceCodes *amazon.PKCECodes,
		registration *amazon.TokenData,
		authSvc amazonAuthService,
		isWebUI bool,
		forwarder *callbackForwarder,
	) {
		if isWebUI {
			defer stopCallbackForwarderInstance(amazonCallbackPort, forwarder)
		}

		deadline := time.Now().Add(10 * time.Minute)
		waitFile := filepath.Join(h.cfg.AuthDir, fmt.Sprintf(".oauth-amazon-%s.oauth", state))
		for {
			if !IsOAuthSessionPending(state, "amazon") {
				return
			}
			if time.Now().After(deadline) {
				SetOAuthSessionError(state, "Amazon OAuth flow timed out")
				return
			}

			data, errRead := os.ReadFile(waitFile)
			if errRead != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			var result map[string]string
			_ = json.Unmarshal(data, &result)
			_ = os.Remove(waitFile)
			if errStr := strings.TrimSpace(result["error"]); errStr != "" {
				SetOAuthSessionError(state, errStr)
				return
			}
			if strings.TrimSpace(result["state"]) != state {
				SetOAuthSessionError(state, "Amazon OAuth state mismatch")
				return
			}
			code := strings.TrimSpace(result["code"])
			if code == "" {
				SetOAuthSessionError(state, "Amazon OAuth code missing")
				return
			}

			bundle, errExchange := authSvc.ExchangeAuthorizationCode(ctx, registration.ClientID, registration.ClientSecret, code, redirectURI, pkceCodes)
			if errExchange != nil {
				SetOAuthSessionError(state, errExchange.Error())
				return
			}

			storage := &amazon.TokenStorage{
				AccessToken:           bundle.TokenData.AccessToken,
				RefreshToken:          bundle.TokenData.RefreshToken,
				IDToken:               bundle.TokenData.IDToken,
				TokenType:             bundle.TokenData.TokenType,
				Expired:               bundle.TokenData.Expired,
				Region:                bundle.TokenData.Region,
				StartURL:              bundle.TokenData.StartURL,
				ClientID:              registration.ClientID,
				ClientSecret:          registration.ClientSecret,
				RegistrationExpiresAt: registration.RegistrationExpiresAt,
				ConnectionType:        bundle.TokenData.ConnectionType,
				LastRefresh:           bundle.TokenData.LastRefresh,
			}

			record := &coreauth.Auth{
				ID:       fmt.Sprintf("amazon-%d.json", time.Now().UnixMilli()),
				Provider: "amazon",
				FileName: fmt.Sprintf("amazon-%d.json", time.Now().UnixMilli()),
				Label:    "Amazon Q",
				Storage:  storage,
				Metadata: map[string]any{
					"region":                  bundle.TokenData.Region,
					"start_url":               bundle.TokenData.StartURL,
					"connection_type":         bundle.TokenData.ConnectionType,
					"expired":                 bundle.TokenData.Expired,
					"last_refresh":            bundle.TokenData.LastRefresh,
					"client_id":               registration.ClientID,
					"client_secret":           registration.ClientSecret,
					"registration_expires_at": registration.RegistrationExpiresAt,
				},
			}

			if _, errSave := h.saveTokenRecord(ctx, record); errSave != nil {
				SetOAuthSessionError(state, fmt.Sprintf("failed to save amazon authentication tokens: %v", errSave))
				return
			}

			CompleteOAuthSession(state)
			CompleteOAuthSessionsByProvider("amazon")
			return
		}
	}

	func buildAmazonQuotaRequestContract() (amazonQuotaRequestContract, error) {
		body, err := json.Marshal(map[string]any{
			"origin":          "IDE",
			"isEmailRequired": true,
		})
		if err != nil {
			return amazonQuotaRequestContract{}, err
		}

		return amazonQuotaRequestContract{
			URL: amazonCodeWhispererRuntimeURL + "?origin=IDE",
			Headers: map[string]string{
				"Content-Type": "application/x-amz-json-1.0",
				"X-Amz-Target": "AmazonCodeWhispererService.GetUsageLimits",
			},
			Body: body,
		}, nil
	}

	func (h *Handler) fetchAmazonModels(ctx context.Context, auth *coreauth.Auth) []*registry.ModelInfo {
		return fetchAmazonModelsWithBaseURL(ctx, h, auth, amazonCodeWhispererRuntimeURL)
	}

	func fetchAmazonModelsWithBaseURL(ctx context.Context, h *Handler, auth *coreauth.Auth, baseURL string) []*registry.ModelInfo {
		if auth == nil {
			return nil
		}

		token, errToken := h.resolveTokenForAuth(ctx, auth)
		if errToken != nil || strings.TrimSpace(token) == "" {
			return nil
		}

		requestBody, errMarshal := json.Marshal(map[string]any{
			"origin":     "CLI",
			"maxResults": 50,
		})
		if errMarshal != nil {
			return nil
		}

		endpoint := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/?origin=CLI"
		req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
		if errReq != nil {
			return nil
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("X-Amz-Target", "AmazonCodeWhispererService.ListAvailableModels")

		httpClient := &http.Client{
			Timeout:   defaultAPICallTimeout,
			Transport: h.apiCallTransport(auth),
		}
		resp, errDo := httpClient.Do(req)
		if errDo != nil {
			return nil
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return nil
		}

		body, errRead := io.ReadAll(resp.Body)
		if errRead != nil {
			return nil
		}

		var payload amazonListAvailableModelsResponse
		if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
			return nil
		}

		models := make([]*registry.ModelInfo, 0, len(payload.Models))
		for _, model := range payload.Models {
			id := strings.TrimSpace(model.ModelID)
			if id == "" {
				continue
			}
			models = append(models, &registry.ModelInfo{
				ID:          id,
				Object:      "model",
				OwnedBy:     "amazon",
				Type:        "amazon",
				DisplayName: strings.TrimSpace(model.ModelName),
			})
		}

		return models
	}

	func (h *Handler) refreshAmazonOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		if auth == nil {
			return "", nil
		}

		metadata := auth.Metadata
		if len(metadata) == 0 {
			return "", fmt.Errorf("amazon oauth metadata missing")
		}

		current := strings.TrimSpace(tokenValueFromMetadata(metadata))
		if current != "" {
			if expStr, ok := metadata["expired"].(string); ok {
				if ts, errParse := time.Parse(time.RFC3339, strings.TrimSpace(expStr)); errParse == nil {
					if ts.After(time.Now().Add(30 * time.Second)) {
						return current, nil
					}
				}
			}
		}

		refreshToken := stringValue(metadata, "refresh_token")
		clientID := stringValue(metadata, "client_id")
		clientSecret := stringValue(metadata, "client_secret")
		region := stringValue(metadata, "region")
		startURL := stringValue(metadata, "start_url")
		if refreshToken == "" {
			return current, fmt.Errorf("amazon refresh token missing")
		}
		if clientID == "" || clientSecret == "" {
			return current, fmt.Errorf("amazon client registration missing")
		}

		authSvc := newAmazonAuthService(h.cfg, region, startURL)
		bundle, errRefresh := authSvc.RefreshTokens(ctx, clientID, clientSecret, refreshToken)
		if errRefresh != nil {
			return current, errRefresh
		}

		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata["access_token"] = strings.TrimSpace(bundle.TokenData.AccessToken)
		auth.Metadata["refresh_token"] = strings.TrimSpace(bundle.TokenData.RefreshToken)
		auth.Metadata["token_type"] = strings.TrimSpace(bundle.TokenData.TokenType)
		auth.Metadata["expired"] = strings.TrimSpace(bundle.TokenData.Expired)
		auth.Metadata["last_refresh"] = strings.TrimSpace(bundle.TokenData.LastRefresh)
		if bundle.TokenData.IDToken != "" {
			auth.Metadata["id_token"] = strings.TrimSpace(bundle.TokenData.IDToken)
		}
		if h != nil && h.authManager != nil {
			now := time.Now()
			auth.LastRefreshedAt = now
			auth.UpdatedAt = now
			_, _ = h.authManager.Update(ctx, auth)
		}

		return strings.TrimSpace(bundle.TokenData.AccessToken), nil
	}
