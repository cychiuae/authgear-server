package accountmanagement

import (
	"crypto/subtle"
	"time"

	"github.com/authgear/authgear-server/pkg/util/crypto"
	"github.com/authgear/authgear-server/pkg/util/rand"
)

type Token struct {
	AppID     string     `json:"app_id,omitempty"`
	UserID    string     `json:"user_id,omitempty"`
	TokenHash string     `json:"token_hash,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	ExpireAt  *time.Time `json:"expire_at,omitempty"`

	// Adding OAuth
	Alias       string `json:"alias,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	State       string `json:"state,omitempty"`

	// Adding TOTP
	TOTPSecret string `json:"totp_secret,omitempty"`
	OTPAuthURI string `json:"otp_auth_uri,omitempty"`

	// Adding OOB
	OOBChannel string `json:"oob_channel,omitempty"`
	OOBTarget  string `json:"oob_target,omitempty"`
}

func (t *Token) CheckStateForOAuth(state string) error {
	return t.checkState(state, ErrOAuthStateNotBoundToToken)
}

func (t *Token) CheckUserForOAuth(userID string) error {
	return t.checkUser(userID, ErrOAuthTokenNotBoundToUser)
}

func (t *Token) CheckState(state string) error {
	return t.checkState(state, ErrAccountManagementTokenInvalid)
}

func (t *Token) CheckUser(userID string) error {
	return t.checkUser(userID, ErrAccountManagementTokenNotBoundToUser)
}

func (t *Token) checkState(state string, possibleError error) error {
	if t.State == "" {
		// token is not originally bound to state.
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(t.State), []byte(state)) == 1 {
		return nil
	}

	return possibleError
}

func (t *Token) checkUser(userID string, possibleError error) error {
	if subtle.ConstantTimeCompare([]byte(t.UserID), []byte(userID)) == 1 {
		return nil
	}

	return possibleError
}

const (
	tokenAlphabet string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func GenerateToken() string {
	token := rand.StringWithAlphabet(32, tokenAlphabet, rand.SecureRand)
	return token
}

func HashToken(token string) string {
	return crypto.SHA256String(token)
}
