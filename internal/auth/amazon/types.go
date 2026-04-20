package amazon

type PKCECodes struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type deviceAuthorizationResponseWire struct {
	DeviceCode                 string `json:"device_code"`
	DeviceCodeCamel            string `json:"deviceCode"`
	UserCode                   string `json:"user_code"`
	UserCodeCamel              string `json:"userCode"`
	VerificationURI            string `json:"verification_uri"`
	VerificationURICamel       string `json:"verificationUri"`
	VerificationURIComplete    string `json:"verification_uri_complete"`
	VerificationURICompleteCam string `json:"verificationUriComplete"`
	ExpiresIn                  int    `json:"expires_in"`
	ExpiresInCamel             int    `json:"expiresIn"`
	Interval                   int    `json:"interval"`
}

type TokenData struct {
	AccessToken           string `json:"access_token"`
	AccessTokenCamel      string `json:"accessToken,omitempty"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenCamel     string `json:"refreshToken,omitempty"`
	IDToken               string `json:"id_token,omitempty"`
	IDTokenCamel          string `json:"idToken,omitempty"`
	TokenType             string `json:"token_type,omitempty"`
	TokenTypeCamel        string `json:"tokenType,omitempty"`
	ExpiresIn             int    `json:"expires_in,omitempty"`
	ExpiresInCamel        int    `json:"expiresIn,omitempty"`
	Expired               string `json:"expired,omitempty"`
	Region                string `json:"region,omitempty"`
	StartURL              string `json:"start_url,omitempty"`
	ClientID              string `json:"client_id,omitempty"`
	ClientSecret          string `json:"client_secret,omitempty"`
	RegistrationExpiresAt string `json:"registration_expires_at,omitempty"`
	ConnectionType        string `json:"connection_type,omitempty"`
	LastRefresh           string `json:"last_refresh,omitempty"`
}

type AuthBundle struct {
	TokenData TokenData `json:"token_data"`
}
