package accountmanagement

import (
	"fmt"
	"time"

	"github.com/authgear/oauthrelyingparty/pkg/api/oauthrelyingparty"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/event"
	"github.com/authgear/authgear-server/pkg/api/event/nonblocking"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticationinfo"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/facade"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/uuid"
)

type StartAddingInput struct {
	UserID                                          string
	Alias                                           string
	RedirectURI                                     string
	IncludeStateAuthorizationURLAndBindStateToToken bool
}

type StartAddingOutput struct {
	Token            string `json:"token,omitempty"`
	AuthorizationURL string `json:"authorization_url,omitempty"`
}

type FinishAddingInput struct {
	UserID string
	Token  string
	Query  string
}

type FinishAddingOutput struct {
	// It is intentionally empty.
}

type ChangePrimaryPasswordInput struct {
	Session        session.ResolvedSession
	OAuthSessionID string
	RedirectURI    string
	OldPassword    string
	NewPassword    string
}

type ChangePrimaryPasswordOutput struct {
	RedirectURI string
}

type ChangeSecondaryPasswordInput struct {
	Session        session.ResolvedSession
	OAuthSessionID string
	RedirectURI    string
	OldPassword    string
	NewPassword    string
}

type ChangeSecondaryPasswordOutput struct {
	RedirectURI string
}

type ChangePasswordInput struct {
	Session        session.ResolvedSession
	OAuthSessionID string
	RedirectURI    string
	OldPassword    string
	NewPassword    string
	Kind           model.AuthenticatorKind
}

type ChangePasswordOutput struct {
	RedirectURI string
}

type CreateAdditionalPasswordInput struct {
	NewAuthenticatorID string
	UserID             string
	Password           string
}

type CreateTOTPAuthenticatorInput struct {
	NewAuthenticatorID string
	UserID             string
	DisplayName        string
	Code               string
}

type RemoveSecondaryPasswordInput struct {
	UserID          string
	AuthenticatorID string
}

type RemoveSecondaryPasswordOutput struct {
	// It is intentionally empty.
}

type RemoveTOTPAuthenticatorInput struct {
	UserID          string
	AuthenticatorID string
}

type RemoveTOTPAuthenticatorOutput struct {
	// It is intentionally empty.
}

func NewCreateAdditionalPasswordInput(userID string, password string) CreateAdditionalPasswordInput {
	return CreateAdditionalPasswordInput{
		NewAuthenticatorID: uuid.New(),
		UserID:             userID,
		Password:           password,
	}
}

type Store interface {
	GenerateToken(options GenerateTokenOptions) (string, error)
	ConsumeToken(tokenStr string) (*Token, error)
}

type OAuthProvider interface {
	GetProviderConfig(alias string) (oauthrelyingparty.ProviderConfig, error)
	GetAuthorizationURL(alias string, options oauthrelyingparty.GetAuthorizationURLOptions) (string, error)
	GetUserProfile(alias string, options oauthrelyingparty.GetUserProfileOptions) (oauthrelyingparty.UserProfile, error)
}

type IdentityService interface {
	New(userID string, spec *identity.Spec, options identity.NewIdentityOptions) (*identity.Info, error)
	CheckDuplicated(info *identity.Info) (dupe *identity.Info, err error)
	Create(info *identity.Info) error
	ListByUser(userID string) ([]*identity.Info, error)
}

type EventService interface {
	DispatchEventOnCommit(payload event.Payload) error
}

type AuthenticatorService interface {
	Get(id string) (*authenticator.Info, error)
	NewWithAuthenticatorID(authenticatorID string, spec *authenticator.Spec) (*authenticator.Info, error)
	List(userID string, filters ...authenticator.Filter) ([]*authenticator.Info, error)
	Create(authenticatorInfo *authenticator.Info, markVerified bool) error
	Update(authenticatorInfo *authenticator.Info) error
	UpdatePassword(authenticatorInfo *authenticator.Info, options *service.UpdatePasswordOptions) (changed bool, info *authenticator.Info, err error)
	Delete(authenticatorInfo *authenticator.Info) error
	VerifyWithSpec(info *authenticator.Info, spec *authenticator.Spec, options *facade.VerifyOptions) (verifyResult *service.VerifyResult, err error)
}

type AuthenticationInfoService interface {
	Save(entry *authenticationinfo.Entry) error
}

type SettingsDeleteAccountSuccessUIInfoResolver interface {
	SetAuthenticationInfoInQuery(redirectURI string, e *authenticationinfo.Entry) string
}

type UserService interface {
	UpdateMFAEnrollment(userID string, t *time.Time) error
}

type Service struct {
	Database                  *appdb.Handle
	Store                     Store
	OAuthProvider             OAuthProvider
	Identities                IdentityService
	Events                    EventService
	Authenticators            AuthenticatorService
	AuthenticationInfoService AuthenticationInfoService
	UIInfoResolver            SettingsDeleteAccountSuccessUIInfoResolver
	Users                     UserService

	Config *config.AppConfig
}

func (s *Service) StartAdding(input *StartAddingInput) (*StartAddingOutput, error) {
	state := ""
	if input.IncludeStateAuthorizationURLAndBindStateToToken {
		state = GenerateRandomState()
	}

	param := oauthrelyingparty.GetAuthorizationURLOptions{
		RedirectURI: input.RedirectURI,
		State:       state,
	}

	authorizationURL, err := s.OAuthProvider.GetAuthorizationURL(input.Alias, param)
	if err != nil {
		return nil, err
	}

	token, err := s.Store.GenerateToken(GenerateTokenOptions{
		UserID:      input.UserID,
		Alias:       input.Alias,
		RedirectURI: input.RedirectURI,
		MaybeState:  state,
	})
	if err != nil {
		return nil, err
	}

	return &StartAddingOutput{
		Token:            token,
		AuthorizationURL: authorizationURL,
	}, nil
}

func (s *Service) FinishAdding(input *FinishAddingInput) (*FinishAddingOutput, error) {
	token, err := s.Store.ConsumeToken(input.Token)
	if err != nil {
		return nil, err
	}

	err = token.CheckUser(input.UserID)
	if err != nil {
		return nil, err
	}

	state, err := ExtractStateFromQuery(input.Query)
	if err != nil {
		return nil, err
	}

	err = token.CheckState(state)
	if err != nil {
		return nil, err
	}

	providerConfig, err := s.OAuthProvider.GetProviderConfig(token.Alias)
	if err != nil {
		return nil, err
	}

	emptyNonce := ""
	userProfile, err := s.OAuthProvider.GetUserProfile(token.Alias, oauthrelyingparty.GetUserProfileOptions{
		Query:       input.Query,
		RedirectURI: token.RedirectURI,
		Nonce:       emptyNonce,
	})
	if err != nil {
		return nil, err
	}

	providerID := providerConfig.ProviderID()
	spec := &identity.Spec{
		Type: model.IdentityTypeOAuth,
		OAuth: &identity.OAuthSpec{
			ProviderID:     providerID,
			SubjectID:      userProfile.ProviderUserID,
			RawProfile:     userProfile.ProviderRawProfile,
			StandardClaims: userProfile.StandardAttributes,
		},
	}

	info, err := s.Identities.New(
		token.UserID,
		spec,
		// We are not adding Login ID here so the options is irrelevant.
		identity.NewIdentityOptions{},
	)
	if err != nil {
		return nil, err
	}

	err = s.Database.WithTx(func() error {
		_, err = s.Identities.CheckDuplicated(info)
		if err != nil {
			return err
		}

		err = s.Identities.Create(info)
		if err != nil {
			return err
		}

		evt := &nonblocking.IdentityOAuthConnectedEventPayload{
			UserRef: model.UserRef{
				Meta: model.Meta{
					ID: info.UserID,
				},
			},
			Identity: info.ToModel(),
			AdminAPI: false,
		}

		err = s.Events.DispatchEventOnCommit(evt)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &FinishAddingOutput{}, nil
}

func (s *Service) ChangePrimaryPassword(input *ChangePrimaryPasswordInput) (*ChangePrimaryPasswordOutput, error) {
	output, err := s.ChangePassword(&ChangePasswordInput{
		Session:        input.Session,
		OAuthSessionID: input.OAuthSessionID,
		RedirectURI:    input.RedirectURI,
		OldPassword:    input.OldPassword,
		NewPassword:    input.NewPassword,
		Kind:           model.AuthenticatorKindPrimary,
	})
	if err != nil {
		return nil, err
	}

	return &ChangePrimaryPasswordOutput{
		RedirectURI: output.RedirectURI,
	}, nil
}

func (s *Service) ChangeSecondaryPassword(input *ChangeSecondaryPasswordInput) (*ChangeSecondaryPasswordOutput, error) {
	output, err := s.ChangePassword(&ChangePasswordInput{
		Session:        input.Session,
		OAuthSessionID: input.OAuthSessionID,
		RedirectURI:    input.RedirectURI,
		OldPassword:    input.OldPassword,
		NewPassword:    input.NewPassword,
		Kind:           model.AuthenticatorKindSecondary,
	})
	if err != nil {
		return nil, err
	}

	return &ChangeSecondaryPasswordOutput{
		RedirectURI: output.RedirectURI,
	}, nil
}

// If have OAuthSessionID, it means the user is changing password after login with SDK.
// Then do special handling such as authenticationInfo
func (s *Service) ChangePassword(input *ChangePasswordInput) (*ChangePasswordOutput, error) {
	userID := input.Session.GetAuthenticationInfo().UserID
	redirectURI := input.RedirectURI

	err := s.Database.WithTx(func() error {
		ais, err := s.Authenticators.List(
			userID,
			authenticator.KeepType(model.AuthenticatorTypePassword),
			authenticator.KeepKind(input.Kind),
		)
		if err != nil {
			return err
		}

		if len(ais) == 0 {
			return api.ErrNoPassword
		}

		oldInfo := ais[0]

		_, err = s.Authenticators.VerifyWithSpec(oldInfo, &authenticator.Spec{
			Password: &authenticator.PasswordSpec{
				PlainPassword: input.OldPassword,
			},
		}, nil)
		if err != nil {
			return api.ErrInvalidCredentials
		}

		changed, newInfo, err := s.Authenticators.UpdatePassword(oldInfo, &service.UpdatePasswordOptions{
			SetPassword:    true,
			PlainPassword:  input.NewPassword,
			SetExpireAfter: true,
		})
		if err != nil {
			return err
		}

		if changed {
			err = s.Authenticators.Update(newInfo)
			if err != nil {
				return err
			}
		}

		// If is changing password with SDK.
		if input.OAuthSessionID != "" {
			authInfo := input.Session.GetAuthenticationInfo()
			authenticationInfoEntry := authenticationinfo.NewEntry(authInfo, input.OAuthSessionID, "")

			err = s.AuthenticationInfoService.Save(authenticationInfoEntry)

			if err != nil {
				return err
			}

			redirectURI = s.UIInfoResolver.SetAuthenticationInfoInQuery(input.RedirectURI, authenticationInfoEntry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &ChangePasswordOutput{RedirectURI: redirectURI}, nil
}

func (s *Service) CreateAdditionalPassword(input CreateAdditionalPasswordInput) error {
	spec := &authenticator.Spec{
		UserID:    input.UserID,
		IsDefault: false,
		Kind:      model.AuthenticatorKindSecondary,
		Type:      model.AuthenticatorTypePassword,
		Password: &authenticator.PasswordSpec{
			PlainPassword: input.Password,
		},
	}
	info, err := s.Authenticators.NewWithAuthenticatorID(input.NewAuthenticatorID, spec)
	if err != nil {
		return err
	}
	return s.CreateAuthenticator(info)
}

func (s *Service) CreateTOTPAuthenticator(input *CreateTOTPAuthenticatorInput) error {
	spec := &authenticator.Spec{
		UserID:    input.UserID,
		IsDefault: false,
		Kind:      model.AuthenticatorKindSecondary,
		Type:      model.AuthenticatorTypeTOTP,
		TOTP: &authenticator.TOTPSpec{
			DisplayName: input.DisplayName,
		},
	}
	info, err := s.Authenticators.NewWithAuthenticatorID(input.NewAuthenticatorID, spec)
	if err != nil {
		return err
	}

	// 	// Generate and store a token
	// 	return nil
	// }

	// func (s *Service) FinishCreateTOTPAuthenticator(input struct{  }) error {
	_, err = s.Authenticators.VerifyWithSpec(info, &authenticator.Spec{
		TOTP: &authenticator.TOTPSpec{
			Code: input.Code,
		},
	}, nil)
	if err != nil {
		return err
	}

	err = s.CreateAuthenticator(info)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) CreateAuthenticator(authenticatorInfo *authenticator.Info) error {
	err := s.Database.WithTx(func() error {
		err := s.Authenticators.Create(authenticatorInfo, false)
		if err != nil {
			return err
		}
		if authenticatorInfo.Kind == authenticator.KindSecondary {
			err = s.Users.UpdateMFAEnrollment(authenticatorInfo.UserID, nil)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RemoveSecondaryPassword(input *RemoveSecondaryPasswordInput) (*RemoveSecondaryPasswordOutput, error) {
	authenticatorInfo, err := s.Authenticators.Get(input.AuthenticatorID)
	if err != nil {
		return nil, err
	}

	if authenticatorInfo.Type != model.AuthenticatorTypePassword {
		return nil, fmt.Errorf("authenticator with given ID does not have Type Password")
	}

	if authenticatorInfo.Kind != model.AuthenticatorKindSecondary {
		return nil, fmt.Errorf("authenticator with given ID does not have Kind Secondary")
	}

	err = s.Database.WithTx(func() error {
		/* RemoveAuthenticator: Instantiate */
		if authenticatorInfo.UserID != input.UserID {
			return api.NewInvariantViolated(
				"AuthenticatorNotBelongToUser",
				"authenticator does not belong to the user",
				nil,
			)
		}

		/* RemoveAuthenticator: Prepare */
		/* RemoveAuthenticator: GetEffects */

		/* DoRemoveAuthenticator: Instantiate */
		/* DoRemoveAuthenticator: Prepare */
		/* DoRemoveAuthenticator: GetEffects */

		// Effect 1: EffectRun
		as, err := s.Authenticators.List(input.UserID)
		if err != nil {
			return err
		}

		// Ensure authenticators conform to MFA requirement configuration
		primaries := authenticator.ApplyFilters(as, authenticator.KeepPrimaryAuthenticatorCanHaveMFA)
		secondaries := authenticator.ApplyFilters(as, authenticator.KeepKind(authenticator.KindSecondary))
		var mode config.SecondaryAuthenticationMode = config.SecondaryAuthenticationModeDefault
		if s.Config != nil && s.Config.Authentication != nil {
			mode = s.Config.Authentication.SecondaryAuthenticationMode
		}

		cannotRemove := mode == config.SecondaryAuthenticationModeRequired &&
			len(primaries) > 0 &&
			len(secondaries) == 1 && secondaries[0].ID == authenticatorInfo.ID

		if cannotRemove {
			return api.NewInvariantViolated(
				"RemoveLastSecondaryAuthenticator",
				"cannot remove last secondary authenticator",
				nil,
			)
		}

		err = s.Authenticators.Delete(authenticatorInfo)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &RemoveSecondaryPasswordOutput{}, nil
}

func (s *Service) RemoveTOTPAuthenticator(input *RemoveTOTPAuthenticatorInput) (*RemoveTOTPAuthenticatorOutput, error) {
	authenticatorInfo, err := s.Authenticators.Get(input.AuthenticatorID)
	if err != nil {
		return nil, err
	}

	if authenticatorInfo.Type != model.AuthenticatorTypeTOTP {
		return nil, fmt.Errorf("authenticator with given ID does not have Type Password")
	}

	if authenticatorInfo.Kind != model.AuthenticatorKindSecondary {
		return nil, fmt.Errorf("authenticator with given ID does not have Kind Secondary")
	}

	err = s.Database.WithTx(func() error {
		/* RemoveAuthenticator: Instantiate */
		if authenticatorInfo.UserID != input.UserID {
			return api.NewInvariantViolated(
				"AuthenticatorNotBelongToUser",
				"authenticator does not belong to the user",
				nil,
			)
		}

		/* RemoveAuthenticator: Prepare */
		/* RemoveAuthenticator: GetEffects */

		/* DoRemoveAuthenticator: Instantiate */
		/* DoRemoveAuthenticator: Prepare */
		/* DoRemoveAuthenticator: GetEffects */

		// Effect 1: EffectRun
		as, err := s.Authenticators.List(input.UserID)
		if err != nil {
			return err
		}

		// Ensure authenticators conform to MFA requirement configuration
		primaries := authenticator.ApplyFilters(as, authenticator.KeepPrimaryAuthenticatorCanHaveMFA)
		secondaries := authenticator.ApplyFilters(as, authenticator.KeepKind(authenticator.KindSecondary))
		var mode config.SecondaryAuthenticationMode = config.SecondaryAuthenticationModeDefault
		if s.Config != nil && s.Config.Authentication != nil {
			mode = s.Config.Authentication.SecondaryAuthenticationMode
		}

		cannotRemove := mode == config.SecondaryAuthenticationModeRequired &&
			len(primaries) > 0 &&
			len(secondaries) == 1 && secondaries[0].ID == authenticatorInfo.ID

		if cannotRemove {
			return api.NewInvariantViolated(
				"RemoveLastSecondaryAuthenticator",
				"cannot remove last secondary authenticator",
				nil,
			)
		}

		err = s.Authenticators.Delete(authenticatorInfo)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &RemoveTOTPAuthenticatorOutput{}, nil
}
