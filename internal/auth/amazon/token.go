package amazon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
)

type TokenStorage struct {
	AccessToken           string         `json:"access_token"`
	RefreshToken          string         `json:"refresh_token"`
	IDToken               string         `json:"id_token,omitempty"`
	TokenType             string         `json:"token_type,omitempty"`
	Expired               string         `json:"expired,omitempty"`
	Region                string         `json:"region,omitempty"`
	StartURL              string         `json:"start_url,omitempty"`
	ClientID              string         `json:"client_id,omitempty"`
	ClientSecret          string         `json:"client_secret,omitempty"`
	RegistrationExpiresAt string         `json:"registration_expires_at,omitempty"`
	ConnectionType        string         `json:"connection_type,omitempty"`
	LastRefresh           string         `json:"last_refresh,omitempty"`
	Type                  string         `json:"type"`
	Metadata              map[string]any `json:"-"`
}

func (ts *TokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

func (ts *TokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "amazon"

	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	if err = json.NewEncoder(f).Encode(data); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}

	return nil
}