package oauth

import (
	"context"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/util/clock"
)

type AccessGrantService struct {
	AppID config.AppID

	AccessGrants      AccessGrantStore
	AccessTokenIssuer AccessTokenEncoding
	Clock             clock.Clock
}

type IssueAccessGrantResult struct {
	Token     string
	TokenType string
	ExpiresIn int
}

func (s *AccessGrantService) IssueAccessGrant(
	ctx context.Context,
	client *config.OAuthClientConfig,
	scopes []string,
	authzID string,
	userID string,
	sessionID string,
	sessionKind GrantSessionKind,
	refreshTokenHash string,
) (*IssueAccessGrantResult, error) {
	token := GenerateToken()
	now := s.Clock.NowUTC()

	accessGrant := &AccessGrant{
		AppID:            string(s.AppID),
		AuthorizationID:  authzID,
		SessionID:        sessionID,
		SessionKind:      sessionKind,
		CreatedAt:        now,
		ExpireAt:         now.Add(client.AccessTokenLifetime.Duration()),
		Scopes:           scopes,
		TokenHash:        HashToken(token),
		RefreshTokenHash: refreshTokenHash,
	}
	err := s.AccessGrants.CreateAccessGrant(ctx, accessGrant)
	if err != nil {
		return nil, err
	}

	clientLike := ClientClientLike(client, scopes)
	at, err := s.AccessTokenIssuer.EncodeAccessToken(ctx, client, clientLike, accessGrant, userID, token)
	if err != nil {
		return nil, err
	}

	result := &IssueAccessGrantResult{
		Token:     at,
		TokenType: "Bearer",
		ExpiresIn: int(client.AccessTokenLifetime),
	}

	return result, nil
}
