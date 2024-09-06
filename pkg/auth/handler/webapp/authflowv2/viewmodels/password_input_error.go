package viewmodels

import (
	"github.com/authgear/authgear-server/pkg/api/apierrors"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
)

type InputError struct {
	HasError        bool
	HasErrorMessage bool
}

type PasswordInputErrorViewModel struct {
	PasswordInputError        *InputError
	NewPasswordInputError     *InputError
	ConfirmPasswordInputError *InputError
	HasUnknownError           bool
}

// nolint: gocognit
func NewPasswordInputErrorViewModel(apiError *apierrors.APIError) PasswordInputErrorViewModel {
	viewModel := PasswordInputErrorViewModel{
		PasswordInputError: &InputError{
			HasError:        false,
			HasErrorMessage: false,
		},
		NewPasswordInputError: &InputError{
			HasError:        false,
			HasErrorMessage: false,
		},
		ConfirmPasswordInputError: &InputError{
			HasError:        false,
			HasErrorMessage: false,
		},
	}
	if apiError != nil {
		switch apiError.Reason {
		case "InvalidCredentials":
			viewModel.PasswordInputError.HasError = true
			viewModel.PasswordInputError.HasErrorMessage = true
		case "PasswordPolicyViolated":
			viewModel.NewPasswordInputError.HasError = true
			viewModel.NewPasswordInputError.HasErrorMessage = true
			viewModel.ConfirmPasswordInputError.HasError = true
		case "NewPasswordTypo":
			viewModel.ConfirmPasswordInputError.HasError = true
			viewModel.ConfirmPasswordInputError.HasErrorMessage = true
		case "ValidationFailed":
			for _, causes := range apiError.Info["causes"].([]interface{}) {
				if cause, ok := causes.(map[string]interface{}); ok {
					if kind, ok := cause["kind"].(string); ok {
						if kind == "required" {
							if details, ok := cause["details"].(map[string]interface{}); ok {
								if missing, ok := details["missing"].([]interface{}); ok {
									if viewmodels.SliceContains(missing, "x_password") {
										viewModel.PasswordInputError.HasError = true
										viewModel.PasswordInputError.HasErrorMessage = true
									} else if viewmodels.SliceContains(missing, "x_old_password") {
										viewModel.PasswordInputError.HasError = true
										viewModel.PasswordInputError.HasErrorMessage = true
									} else if viewmodels.SliceContains(missing, "x_new_password") {
										viewModel.NewPasswordInputError.HasError = true
										viewModel.NewPasswordInputError.HasErrorMessage = true
									} else if viewmodels.SliceContains(missing, "x_confirm_password") {
										viewModel.ConfirmPasswordInputError.HasError = true
										viewModel.ConfirmPasswordInputError.HasErrorMessage = true
									}
								}
							}
						}
					}
				}
			}
		}

		if !viewModel.PasswordInputError.HasError && !viewModel.NewPasswordInputError.HasError && !viewModel.ConfirmPasswordInputError.HasError {
			// If it is not an error shown in inputs, it is an unknown error
			viewModel.HasUnknownError = true
		}
	}

	return viewModel
}
