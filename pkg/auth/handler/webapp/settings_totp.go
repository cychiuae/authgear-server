package webapp

import (
	"fmt"
	"net/http"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/accountmanagement"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/template"
)

var TemplateWebSettingsTOTPHTML = template.RegisterHTML(
	"web/settings_totp.html",
	Components...,
)

func ConfigureSettingsTOTPRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern("/settings/mfa/totp")
}

type SettingsTOTPViewModel struct {
	Authenticators []*authenticator.Info
}

type SettingsTOTPHandler struct {
	ControllerFactory ControllerFactory
	BaseViewModel     *viewmodels.BaseViewModeler
	Renderer          Renderer
	Authenticators    SettingsAuthenticatorService
	AccountManagement accountmanagement.Service
}

func (h *SettingsTOTPHandler) GetData(r *http.Request, rw http.ResponseWriter) (map[string]interface{}, error) {
	data := map[string]interface{}{}
	baseViewModel := h.BaseViewModel.ViewModel(r, rw)
	userID := session.GetUserID(r.Context())
	viewModel := SettingsTOTPViewModel{}
	authenticators, err := h.Authenticators.List(*userID,
		authenticator.KeepKind(authenticator.KindSecondary),
		authenticator.KeepType(model.AuthenticatorTypeTOTP),
	)
	if err != nil {
		return nil, err
	}
	viewModel.Authenticators = authenticators

	viewmodels.Embed(data, baseViewModel)
	viewmodels.Embed(data, viewModel)

	return data, nil
}

func (h *SettingsTOTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.ServeWithDBTx()

	ctrl.Get(func() error {
		data, err := h.GetData(r, w)
		if err != nil {
			return err
		}

		h.Renderer.RenderHTML(w, r, TemplateWebSettingsTOTPHTML, data)
		return nil
	})

	ctrl.PostAction("remove", func() error {
		userID := session.GetUserID(r.Context())
		authenticatorID := r.Form.Get("x_authenticator_id")

		_, err := h.AccountManagement.RemoveTOTPAuthenticator(&accountmanagement.RemoveTOTPAuthenticatorInput{
			UserID:          *userID,
			AuthenticatorID: authenticatorID,
		})
		if err != nil {
			return err
		}

		result := webapp.Result{RedirectURI: "/settings/mfa/totp"}
		result.WriteResponse(w, r)
		return nil
	})

	ctrl.PostAction("add", func() error {
		userID := session.GetUserID(r.Context())

		output, err := h.AccountManagement.StartAddingTOTP(&accountmanagement.StartAddingTOTPInput{
			UserID: *userID,
		})
		if err != nil {
			return err
		}

		result := webapp.Result{RedirectURI: fmt.Sprintf("/settings/mfa/totp/new?q_token=%s", output.Token)}
		result.WriteResponse(w, r)
		return nil
	})
}
