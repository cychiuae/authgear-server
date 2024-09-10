package authflowv2

import (
	"fmt"
	htmltemplate "html/template"
	"net/http"

	"github.com/authgear/authgear-server/pkg/api"
	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/accountmanagement"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	coreimage "github.com/authgear/authgear-server/pkg/util/image"
	"github.com/authgear/authgear-server/pkg/util/secretcode"
	"github.com/authgear/authgear-server/pkg/util/template"
)

var TemplateWebAuthflowCreateTOTPHTML = template.RegisterHTML(
	"web/authflowv2/create_totp.html",
	handlerwebapp.Components...,
)

var TemplateWebAuthflowCreateTOTPVerifyHTML = template.RegisterHTML(
	"web/authflowv2/create_totp_verify.html",
	handlerwebapp.Components...,
)

func ConfigureAuthflowV2CreateTOTPRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern("/settings/mfa/totp/new")
}

type AuthflowCreateTOTPViewModel struct {
	Secret   string
	ImageURI htmltemplate.URL
	Token    string
}

type AuthflowV2CreateTOTPHandler struct {
	ControllerFactory handlerwebapp.ControllerFactory
	BaseViewModel     *viewmodels.BaseViewModeler
	Renderer          handlerwebapp.Renderer

	AccountManagement accountmanagement.Service
}

func (h *AuthflowV2CreateTOTPHandler) GetData(w http.ResponseWriter, r *http.Request, token string) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	userID := session.GetUserID(r.Context())

	baseViewModel := h.BaseViewModel.ViewModelForAuthFlow(r, w)
	viewmodels.Embed(data, baseViewModel)

	output, err := h.AccountManagement.ResumeAddingTOTP(&accountmanagement.ResumeAddingTOTPInput{
		UserID: *userID,
		Token:  token,
	})
	if err != nil {
		return nil, err
	}

	// viewmodels.Embed(data, output)

	img, err := secretcode.QRCodeImageFromURI(output.OTPAuthURI, 512, 512)
	if err != nil {
		return nil, err
	}
	dataURI, err := coreimage.DataURIFromImage(coreimage.CodecPNG, img)
	if err != nil {
		return nil, err
	}

	screenViewModel := AuthflowCreateTOTPViewModel{
		Secret: output.TOTPSecret,
		// nolint: gosec
		ImageURI: htmltemplate.URL(dataURI),
		Token:    token,
	}
	viewmodels.Embed(data, screenViewModel)

	// branchViewModel := viewmodels.NewAuthflowBranchViewModel(screen)
	branchViewModel := viewmodels.AuthflowBranchViewModel{
		FlowType:           "",
		ActionType:         "",
		DeviceTokenEnabled: false,
		Branches:           []viewmodels.AuthflowBranch{},
	}
	viewmodels.Embed(data, branchViewModel)

	return data, nil
}

func (h *AuthflowV2CreateTOTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// var handlers handlerwebapp.AuthflowControllerHandlers
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.Serve()

	ctrl.Get(func() error {
		userID := session.GetUserID(r.Context())

		token := r.URL.Query().Get("q_token")
		if r.URL.Query().Get("q_token") == "" {
			output, err := h.AccountManagement.StartAddingTOTP(&accountmanagement.StartAddingTOTPInput{
				UserID: *userID,
			})
			if err != nil {
				return err
			}
			result := webapp.Result{RedirectURI: fmt.Sprintf("/settings/mfa/totp/new?q_token=%s", output.Token)}
			result.WriteResponse(w, r)
			return nil
		}

		data, err := h.GetData(w, r, token)
		if err != nil {
			return err
		}

		if r.URL.Query().Get("q_setup_totp_step") == "verify" {
			h.Renderer.RenderHTML(w, r, TemplateWebAuthflowCreateTOTPVerifyHTML, data)
			return nil
		}

		h.Renderer.RenderHTML(w, r, TemplateWebAuthflowCreateTOTPHTML, data)
		return nil
	})

	ctrl.PostAction("submit", func() error {
		userID := session.GetUserID(r.Context())

		err := AuthflowSetupTOTPSchema.Validator().ValidateValue(handlerwebapp.FormToJSON(r.Form))
		if err != nil {
			return err
		}

		token := r.Form.Get("q_token")
		if token == "" {
			return api.ErrInvalidCredentials
		}

		err = h.AccountManagement.FinishAddingTOTP(&accountmanagement.FinishAddingTOTPInput{
			UserID:      *userID,
			Token:       token,
			DisplayName: "put a proper name here",
			Code:        r.Form.Get("x_code"),
		})
		if err != nil {
			return err
		}

		result := webapp.Result{RedirectURI: "/settings/mfa/totp"}
		// result := webapp.Result{RedirectURI: fmt.Sprintf("/settings/mfa/totp/new?q_setup_totp_step=recovery&_token=%s", token)}
		result.WriteResponse(w, r)
		return nil
	})
	// h.Controller.HandleStep(w, r, &handlers)
}
