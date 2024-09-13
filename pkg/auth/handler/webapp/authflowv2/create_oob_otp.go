package authflowv2

import (
	"fmt"
	"net/http"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/accountmanagement"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/template"
)

var TemplateWebAuthflowCreateOOBOTPHTML = template.RegisterHTML(
	"web/authflowv2/create_oob_otp.html",
	handlerwebapp.Components...,
)

var TemplateWebAuthflowCreateOOBOTPVerifyHTML = template.RegisterHTML(
	"web/authflowv2/create_oob_otp_verify.html",
	handlerwebapp.Components...,
)

func ConfigureAuthflowV2CreateOOBOTPRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern(AuthflowV2RouteCreateOOBOTP)
}

type AuthflowCreateOOBOTPViewModel struct {
	OOBAuthenticatorType    model.AuthenticatorType
	CodeLength              int
	Channel                 model.AuthenticatorOOBChannel
	MaskedClaimValue        string
	IsBotProtectionRequired bool
}

type AuthflowV2CreateOOBOTPHandler struct {
	ControllerFactory handlerwebapp.ControllerFactory
	BaseViewModel     *viewmodels.BaseViewModeler
	Renderer          handlerwebapp.Renderer

	AccountManagement accountmanagement.Service
}

// func NewAuthflowCreateOOBOTPViewModel(s *webapp.Session, screen *webapp.AuthflowScreenWithFlowResponse) AuthflowCreateOOBOTPViewModel {
//
// 	// Ignore error, bpRequired would be false
// 	bpRequired, _ := webapp.IsCreateAuthenticatorStepBotProtectionRequired(option.Authentication, screen.StateTokenFlowResponse)
// 	return AuthflowCreateOOBOTPViewModel{
// 		OOBAuthenticatorType:    oobAuthenticatorType,
// 		Channel:                 channel,
// 		IsBotProtectionRequired: bpRequired,
// 	}
// }

func (h *AuthflowV2CreateOOBOTPHandler) GetData(w http.ResponseWriter, r *http.Request, qtoken string, qtype string) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	baseViewModel := h.BaseViewModel.ViewModelForAuthFlow(r, w)
	viewmodels.Embed(data, baseViewModel)

	target := ""
	channel := model.AuthenticatorOOBChannel(qtype)
	if qtoken != "" {
		token, err := h.AccountManagement.CreateOOBStatus(session.GetSession(r.Context()), qtoken)
		if err != nil {
			return nil, err
		}

		target = token.Target
		channel = token.Channel
	}

	switch channel {
	case model.AuthenticatorOOBChannelEmail:
		screenViewModel := AuthflowCreateOOBOTPViewModel{
			OOBAuthenticatorType: model.AuthenticatorTypeOOBEmail,
			CodeLength:           6,
			Channel:              model.AuthenticatorOOBChannelEmail,
			MaskedClaimValue:     target,
			// IsBotProtectionRequired: bpRequired,
		}
		viewmodels.Embed(data, screenViewModel)
	case model.AuthenticatorOOBChannelSMS:
		screenViewModel := AuthflowCreateOOBOTPViewModel{
			OOBAuthenticatorType: model.AuthenticatorTypeOOBSMS,
			CodeLength:           6,
			Channel:              model.AuthenticatorOOBChannelSMS,
			MaskedClaimValue:     target,
			// IsBotProtectionRequired: bpRequired,
		}
		viewmodels.Embed(data, screenViewModel)
	}

	// screenViewModel := NewAuthflowSetupOOBOTPViewModel(s, screen)

	// authentication := getTakenBranchCreateAuthenticatorAuthentication(screen)

	// branchFilter := func(branches []viewmodels.AuthflowBranch) []viewmodels.AuthflowBranch {
	// 	filtered := []viewmodels.AuthflowBranch{}
	// 	for _, branch := range branches {
	// 		if branch.Authentication == authentication {
	// 			// Hide oob otp branches of same type
	// 			continue
	// 		}
	// 		filtered = append(filtered, branch)
	// 	}
	// 	return filtered
	// }

	// branchViewModel := viewmodels.NewAuthflowBranchViewModel(screen, branchFilter)
	// viewmodels.Embed(data, branchViewModel)

	return data, nil
}

func (h *AuthflowV2CreateOOBOTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.Serve()

	ctrl.Get(func() error {
		qtoken := r.Form.Get("q_token")
		qtype := r.Form.Get("q_type")

		if qtoken == "" && qtype != "email" && qtype != "sms" {
			result := webapp.Result{RedirectURI: fmt.Sprintf("%s?q_type=sms", AuthflowV2RouteCreateOOBOTP)}
			result.WriteResponse(w, r)
			return nil
		}

		data, err := h.GetData(w, r, qtoken, qtype)
		if err != nil {
			return err
		}

		if qtoken != "" {
			h.Renderer.RenderHTML(w, r, TemplateWebAuthflowCreateOOBOTPVerifyHTML, data)
			return nil
		}

		h.Renderer.RenderHTML(w, r, TemplateWebAuthflowCreateOOBOTPHTML, data)
		return nil
	})
	ctrl.PostAction("", func() error {
		// err = handlerwebapp.HandleCreateAuthenticatorBotProtection(option.Authentication, screen.StateTokenFlowResponse, r.Form, input)
		// if err != nil {
		// 	return err
		// }
		var channel model.AuthenticatorOOBChannel

		qtype := r.Form.Get("q_type")
		switch qtype {
		case "email":
			channel = model.AuthenticatorOOBChannelEmail
		case "sms":
			channel = model.AuthenticatorOOBChannelSMS
		default:
			return api.ErrGetUsersInvalidArgument.Errorf("q_type: %s", qtype)
		}

		output, err := h.AccountManagement.CreateOOBAdvance(session.GetSession(r.Context()), &accountmanagement.CreateOOBInput{
			Target:  r.Form.Get("x_target"),
			Channel: channel,
		})
		if err != nil {
			return err
		}

		switch output.State {
		case accountmanagement.CreateOOBVerify:
			result := webapp.Result{RedirectURI: fmt.Sprintf("%s?&q_token=%s", AuthflowV2RouteCreateOOBOTP, output.Token)}
			result.WriteResponse(w, r)
			return nil
		case accountmanagement.CreateOOBRecovery:
			result := webapp.Result{RedirectURI: "settings/mfa/oob-otp"}
			result.WriteResponse(w, r)
			return nil
		case accountmanagement.CreateOOBComplete:
			result := webapp.Result{RedirectURI: "settings/mfa/oob-otp"}
			result.WriteResponse(w, r)
			return nil
		default:
			result := webapp.Result{RedirectURI: "errors/error"}
			result.WriteResponse(w, r)
			return nil
		}
	})
	ctrl.PostAction("resend", func() error {
		var channel model.AuthenticatorOOBChannel

		qtype := r.Form.Get("q_type")
		switch qtype {
		case "email":
			channel = model.AuthenticatorOOBChannelEmail
		case "sms":
			channel = model.AuthenticatorOOBChannelSMS
		default:
			return api.ErrGetUsersInvalidArgument.Errorf("q_type: %s", qtype)
		}

		_, err := h.AccountManagement.CreateOOBAdvance(session.GetSession(r.Context()), &accountmanagement.CreateOOBInput{
			Target:  r.Form.Get("x_target"),
			Channel: channel,
		})
		if err != nil {
			return err
		}

		result := webapp.Result{}
		result.WriteResponse(w, r)
		return nil
	})
	// h.Controller.HandleStep(w, r, &handlers)
}
