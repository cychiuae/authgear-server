package authflowv2

import (
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/authgear/authgear-server/pkg/api/model"
	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/accountmanagement"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/template"
)

var TemplateSettingsV2PasskeyHTML = template.RegisterHTML(
	"web/authflowv2/settings_passkey.html",
	handlerwebapp.SettingsComponents...,
)

type AuthflowV2SettingsPasskeyViewModel struct {
	PasskeyIdentities   []*identity.Info
	CreationOptionsJSON string
}

type PasskeyCreationOptionsService interface {
	MakeCreationOptions(userID string) (*model.WebAuthnCreationOptions, error)
}

type AuthflowV2SettingsChangePasskeyHandler struct {
	ControllerFactory        handlerwebapp.ControllerFactory
	BaseViewModel            *viewmodels.BaseViewModeler
	Renderer                 handlerwebapp.Renderer
	Identities               handlerwebapp.SettingsIdentityService
	AccountmanagementService *accountmanagement.Service
	Passkey                  PasskeyCreationOptionsService
}

func (h *AuthflowV2SettingsChangePasskeyHandler) GetData(r *http.Request, rw http.ResponseWriter) (map[string]interface{}, error) {
	data := map[string]interface{}{}
	userID := session.GetUserID(r.Context())

	// BaseViewModel
	baseViewModel := h.BaseViewModel.ViewModel(r, rw)
	viewmodels.Embed(data, baseViewModel)

	// PasskeyViewModel
	identities, err := h.Identities.ListByUser(*userID)
	if err != nil {
		return nil, err
	}
	var passkeyIdentities []*identity.Info
	for _, i := range identities {
		if i.Type == model.IdentityTypePasskey {
			ii := i
			passkeyIdentities = append(passkeyIdentities, ii)
		}
	}
	var creationOptionsJSON string
	creationOptions, err := h.Passkey.MakeCreationOptions(*userID)
	if err != nil {
		return nil, err
	}
	creationOptionsJSONBytes, err := json.Marshal(creationOptions)
	if err != nil {
		return nil, err
	}
	creationOptionsJSON = string(creationOptionsJSONBytes)

	passkeyViewModel := AuthflowV2SettingsPasskeyViewModel{
		PasskeyIdentities:   passkeyIdentities,
		CreationOptionsJSON: creationOptionsJSON,
	}
	viewmodels.Embed(data, passkeyViewModel)

	return data, nil
}

func (h *AuthflowV2SettingsChangePasskeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.Serve()

	ctrl.Get(func() error {
		data, err := h.GetData(r, w)
		if err != nil {
			return err
		}
		h.Renderer.RenderHTML(w, r, TemplateSettingsV2PasskeyHTML, data)

		return nil
	})

	ctrl.PostAction("add", func() error {
		attestationResponseStr := r.Form.Get("x_attestation_response")

		var creationResponse protocol.CredentialCreationResponse
		err := json.Unmarshal([]byte(attestationResponseStr), &creationResponse)
		if err != nil {
			return err
		}

		s := session.GetSession(r.Context())

		input := &accountmanagement.AddPasskeyInput{
			Session:          s,
			CreationResponse: &creationResponse,
		}

		_, err = h.AccountmanagementService.AddPasskey(input)
		if err != nil {
			return err
		}

		redirectURI := httputil.HostRelative(r.URL).String()
		result := webapp.Result{RedirectURI: redirectURI}
		result.WriteResponse(w, r)

		return nil

	})
}
