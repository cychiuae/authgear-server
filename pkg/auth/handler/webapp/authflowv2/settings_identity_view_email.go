package authflowv2

import (
	"net/http"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	identityservice "github.com/authgear/authgear-server/pkg/lib/authn/identity/service"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/template"
)

var TemplateWebSettingsIdentityViewEmailHTML = template.RegisterHTML(
	"web/authflowv2/settings_identity_view_email.html",
	handlerwebapp.SettingsComponents...,
)

func ConfigureAuthflowV2SettingsIdentityViewEmailRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern(AuthflowV2RouteSettingsIdentityViewEmail)
}

type AuthflowV2SettingsIdentityViewEmailViewModel struct {
	EmailIdentity  identity.LoginID
	Verifications  map[string][]verification.ClaimStatus
	UpdateDisabled bool
	DeleteDisabled bool
}

type AuthflowV2SettingsIdentityViewEmailHandler struct {
	Database          *appdb.Handle
	LoginIDConfig     *config.LoginIDConfig
	Identities        *identityservice.Service
	ControllerFactory handlerwebapp.ControllerFactory
	BaseViewModel     *viewmodels.BaseViewModeler
	Verification      handlerwebapp.SettingsVerificationService
	Renderer          handlerwebapp.Renderer
}

func (h *AuthflowV2SettingsIdentityViewEmailHandler) GetData(r *http.Request, rw http.ResponseWriter) (map[string]interface{}, error) {
	loginID := r.Form.Get("q_login_id")
	data := map[string]interface{}{}

	baseViewModel := h.BaseViewModel.ViewModel(r, rw)
	viewmodels.Embed(data, baseViewModel)

	userID := session.GetUserID(r.Context())

	identities, err := h.Identities.LoginID.List(*userID)
	if err != nil {
		return nil, err
	}

	var emailIdentity *identity.LoginID
	for _, id := range identities {
		if id.ID == loginID {
			emailIdentity = id
		}
	}
	if emailIdentity == nil {
		return nil, api.ErrIdentityNotFound // Probably the wrong error
	}
	if emailIdentity.LoginIDType != model.LoginIDKeyTypeEmail {
		return nil, api.ErrIdentityNotFound // Probably the wrong error
	}

	verifications, err := h.Verification.GetVerificationStatuses([]*identity.Info{emailIdentity.ToInfo()})
	if err != nil {
		return nil, err
	}

	updateDisabled := true
	deleteDisabled := len(identities) < 2 // Do not let user remove their last identity
	if loginIDConfig, ok := h.LoginIDConfig.GetKeyConfig(loginID); ok {
		updateDisabled = *loginIDConfig.UpdateDisabled
		deleteDisabled = deleteDisabled || *loginIDConfig.DeleteDisabled
	}

	vm := AuthflowV2SettingsIdentityViewEmailViewModel{
		EmailIdentity:  *emailIdentity,
		Verifications:  verifications,
		UpdateDisabled: updateDisabled,
		DeleteDisabled: deleteDisabled,
	}
	viewmodels.Embed(data, vm)

	return data, nil
}

func (h *AuthflowV2SettingsIdentityViewEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctrl, err := h.ControllerFactory.New(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ctrl.ServeWithoutDBTx()

	ctrl.Get(func() error {
		var data map[string]interface{}
		err := h.Database.WithTx(func() error {
			data, err = h.GetData(r, w)
			return err
		})
		if err != nil {
			return err
		}

		h.Renderer.RenderHTML(w, r, TemplateWebSettingsIdentityViewEmailHTML, data)
		return nil
	})
}
