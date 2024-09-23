package accountmanagement

import (
	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticationinfo"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	authenticatorservice "github.com/authgear/authgear-server/pkg/lib/authn/authenticator/service"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/secretcode"
)

type ChangePrimaryPasswordInput struct {
	OAuthSessionID string
	RedirectURI    string
	OldPassword    string
	NewPassword    string
}

type ChangePrimaryPasswordOutput struct {
	RedirectURI string
	OldInfo     *authenticator.Info
	NewInfo     *authenticator.Info
}

// If have OAuthSessionID, it means the user is changing password after login with SDK.
// Then do special handling such as authenticationInfo
func (s *Service) ChangePrimaryPassword(resolvedSession session.ResolvedSession, input *ChangePrimaryPasswordInput) (*ChangePrimaryPasswordOutput, error) {
	redirectURI := input.RedirectURI

	var output *changePasswordOutput
	var err error
	err = s.Database.WithTx(func() error {
		output, err = s.changePassword(resolvedSession, &changePasswordInput{
			Kind:        authenticator.KindPrimary,
			OldPassword: input.OldPassword,
			NewPassword: input.NewPassword,
		})
		return err
	})

	if err != nil {
		return nil, err
	}

	// If is changing password with SDK.
	if input.OAuthSessionID != "" {
		authInfo := resolvedSession.GetAuthenticationInfo()
		authenticationInfoEntry := authenticationinfo.NewEntry(authInfo, input.OAuthSessionID, "")

		err = s.AuthenticationInfoService.Save(authenticationInfoEntry)
		if err != nil {
			return nil, err
		}
		redirectURI = s.UIInfoResolver.SetAuthenticationInfoInQuery(input.RedirectURI, authenticationInfoEntry)
	}

	return &ChangePrimaryPasswordOutput{
		RedirectURI: redirectURI,
		OldInfo:     output.OldInfo,
		NewInfo:     output.NewInfo,
	}, nil
}

type CreateSecondaryPasswordInput struct {
	PlainPassword string
}

type CreateSecondaryPasswordOutput struct {
}

func (s *Service) CreateSecondaryPassword(resolvedSession session.ResolvedSession, input CreateSecondaryPasswordInput) (*CreateSecondaryPasswordOutput, error) {
	userID := resolvedSession.GetAuthenticationInfo().UserID
	spec := &authenticator.Spec{
		UserID:    userID,
		IsDefault: false,
		Kind:      model.AuthenticatorKindSecondary,
		Type:      model.AuthenticatorTypePassword,
		Password: &authenticator.PasswordSpec{
			PlainPassword: input.PlainPassword,
		},
	}
	info, err := s.Authenticators.New(spec)
	if err != nil {
		return nil, err
	}
	err = s.Database.WithTx(func() error {
		return s.createAuthenticator(info)
	})
	if err != nil {
		return nil, err
	}
	return &CreateSecondaryPasswordOutput{}, nil
}

type ChangeSecondaryPasswordInput struct {
	OldPassword string
	NewPassword string
}

type ChangeSecondaryPasswordOutput struct {
}

func (s *Service) ChangeSecondaryPassword(resolvedSession session.ResolvedSession, input *ChangeSecondaryPasswordInput) (*ChangeSecondaryPasswordOutput, error) {
	err := s.Database.WithTx(func() error {
		_, err := s.changePassword(resolvedSession, &changePasswordInput{
			Kind:        authenticator.KindSecondary,
			OldPassword: input.OldPassword,
			NewPassword: input.NewPassword,
		})
		return err
	})

	if err != nil {
		return nil, err
	}

	return &ChangeSecondaryPasswordOutput{}, nil
}

type StartAddTOTPAuthenticatorInput struct{}
type StartAddTOTPAuthenticatorOutput struct {
	Token string
}

func (s *Service) StartAddTOTPAuthenticator(resolvedSession session.ResolvedSession, input *StartAddTOTPAuthenticatorInput) (*StartAddTOTPAuthenticatorOutput, error) {
	userID := resolvedSession.GetAuthenticationInfo().UserID

	totp, err := secretcode.NewTOTPFromRNG()
	if err != nil {
		return nil, err
	}
	token, err := s.Store.GenerateToken(GenerateTokenOptions{
		UserID:                  userID,
		AuthenticatorTOTPSecret: totp.Secret,
	})
	if err != nil {
		return nil, err
	}

	return &StartAddTOTPAuthenticatorOutput{
		Token: token,
	}, nil
}

type ResumeAddTOTPAuthenticatorInput struct {
	Code string
}
type ResumeAddTOTPAuthenticatorOutput struct {
	Token string
}

func (s *Service) ResumeAddTOTPAuthenticator(resolvedSession session.ResolvedSession, tokenString string, input *ResumeAddTOTPAuthenticatorInput) (output *ResumeAddTOTPAuthenticatorOutput, err error) {
	userID := resolvedSession.GetAuthenticationInfo().UserID
	token, err := s.Store.GetToken(tokenString)
	defer func() {
		if err == nil {
			_, err = s.Store.ConsumeToken(tokenString)
		}
	}()

	if err != nil {
		return
	}

	err = token.CheckUser(userID)
	if err != nil {
		return
	}

	info, err := s.Authenticators.New(
		&authenticator.Spec{
			UserID:    userID,
			IsDefault: false,
			Kind:      model.AuthenticatorKindSecondary,
			Type:      model.AuthenticatorTypeTOTP,
			TOTP: &authenticator.TOTPSpec{
				Secret: token.Authenticator.TOTPSecret,
			},
		},
	)
	if err != nil {
		return
	}
	_, err = s.Authenticators.VerifyWithSpec(
		info,
		&authenticator.Spec{
			UserID:    userID,
			IsDefault: false,
			Kind:      model.AuthenticatorKindSecondary,
			Type:      model.AuthenticatorTypeTOTP,
			TOTP: &authenticator.TOTPSpec{
				Code: input.Code,
			},
		},
		nil,
	)

	if err != nil {
		return
	}

	recoveryCodes := s.MFA.GenerateRecoveryCodes()

	newToken, err := s.Store.GenerateToken(GenerateTokenOptions{
		UserID:                     userID,
		AuthenticatorTOTPSecret:    token.Authenticator.TOTPSecret,
		AuthenticatorTOTPVerified:  true,
		AuthenticatorRecoveryCodes: recoveryCodes,
	})
	if err != nil {
		return
	}

	output = &ResumeAddTOTPAuthenticatorOutput{
		Token: newToken,
	}
	return
}

type FinishAddTOTPAuthenticatorInput struct {
}

type FinishAddTOTPAuthenticatorOutput struct {
	Info *authenticator.Info
}

func (s *Service) FinishAddTOTPAuthenticator(resolvedSession session.ResolvedSession, tokenString string, input *FinishAddTOTPAuthenticatorInput) (output *FinishAddTOTPAuthenticatorOutput, err error) {
	userID := resolvedSession.GetAuthenticationInfo().UserID
	token, err := s.Store.GetToken(tokenString)
	defer func() {
		if err == nil {
			_, err = s.Store.ConsumeToken(tokenString)
		}
	}()

	if err != nil {
		return
	}

	err = token.CheckUser(userID)
	if err != nil {
		return
	}

	info, err := s.Authenticators.New(
		&authenticator.Spec{
			UserID:    userID,
			IsDefault: false,
			Kind:      model.AuthenticatorKindSecondary,
			Type:      model.AuthenticatorTypeTOTP,
			TOTP: &authenticator.TOTPSpec{
				Secret: token.Authenticator.TOTPSecret,
			},
		},
	)
	if err != nil {
		return
	}
	err = s.Database.WithTx(func() error {
		err = s.createAuthenticator(info)
		if err != nil {
			return err
		}

		_, err = s.MFA.ReplaceRecoveryCodes(userID, token.Authenticator.RecoveryCodes)
		if err != nil {
			return err
		}

		return nil
	})

	output = &FinishAddTOTPAuthenticatorOutput{
		Info: info,
	}
	return
}

type changePasswordInput struct {
	Kind        authenticator.Kind
	OldPassword string
	NewPassword string
}

type changePasswordOutput struct {
	OldInfo *authenticator.Info
	NewInfo *authenticator.Info
}

func (s *Service) changePassword(resolvedSession session.ResolvedSession, input *changePasswordInput) (*changePasswordOutput, error) {
	userID := resolvedSession.GetAuthenticationInfo().UserID

	ais, err := s.Authenticators.List(
		userID,
		authenticator.KeepType(model.AuthenticatorTypePassword),
		authenticator.KeepKind(input.Kind),
	)
	if err != nil {
		return nil, err
	}
	if len(ais) == 0 {
		return nil, api.ErrNoPassword
	}
	oldInfo := ais[0]
	_, err = s.Authenticators.VerifyWithSpec(oldInfo, &authenticator.Spec{
		Password: &authenticator.PasswordSpec{
			PlainPassword: input.OldPassword,
		},
	}, nil)
	if err != nil {
		err = api.ErrInvalidCredentials
		return nil, err
	}
	changed, newInfo, err := s.Authenticators.UpdatePassword(oldInfo, &authenticatorservice.UpdatePasswordOptions{
		SetPassword:    true,
		PlainPassword:  input.NewPassword,
		SetExpireAfter: true,
	})
	if err != nil {
		return nil, err
	}
	if changed {
		err = s.Authenticators.Update(newInfo)
		if err != nil {
			return nil, err
		}
	}
	return &changePasswordOutput{
		OldInfo: oldInfo,
		NewInfo: newInfo,
	}, nil

}

func (s *Service) createAuthenticator(authenticatorInfo *authenticator.Info) error {
	err := s.Authenticators.Create(authenticatorInfo, true)
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
}
