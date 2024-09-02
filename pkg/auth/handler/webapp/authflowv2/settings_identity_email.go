package authflowv2

import (
	"net/http"
	"sort"
	"time"

	handlerwebapp "github.com/authgear/authgear-server/pkg/auth/handler/webapp"
	"github.com/authgear/authgear-server/pkg/auth/handler/webapp/viewmodels"
	"github.com/authgear/authgear-server/pkg/auth/webapp"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/template"
)

var TemplateWebSettingsIdentityEmailHTML = template.RegisterHTML(
	"web/authflowv2/settings_identity_email.html",
	handlerwebapp.SettingsComponents...,
)

func ConfigureSettingsIdentityEmailRoute(route httproute.Route) httproute.Route {
	return route.
		WithMethods("OPTIONS", "POST", "GET").
		WithPathPattern(AuthflowV2RouteSettingsIdentityEmail)
}

type CheckedEmail struct {
	Email      string
	Verified   bool
	Verifiable bool
	UpdatedAt  time.Time
}

type AuthflowV2SettingsIdentityEmailHandler struct {
	ControllerFactory        handlerwebapp.ControllerFactory
	BaseViewModel            *viewmodels.BaseViewModeler
	SettingsProfileViewModel *viewmodels.SettingsProfileViewModeler
	Identities               viewmodels.SettingsProfileIdentityService
	Renderer                 handlerwebapp.Renderer
	Verification             handlerwebapp.SettingsVerificationService
}

func (h *AuthflowV2SettingsIdentityEmailHandler) GetData(r *http.Request, rw http.ResponseWriter) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	baseViewModel := h.BaseViewModel.ViewModel(r, rw)
	viewmodels.Embed(data, baseViewModel)

	userID := session.GetUserID(r.Context())

	settingsProfileViewModel, err := h.SettingsProfileViewModel.ViewModel(*userID)
	if err != nil {
		return nil, err
	}
	viewmodels.Embed(data, *settingsProfileViewModel)

	identities, err := h.Identities.ListByUser(*userID)
	if err != nil {
		return nil, err
	}

	verifications, err := h.Verification.GetVerificationStatuses(identities)
	if err != nil {
		return nil, err
	}

	emails := []CheckedEmail{}
	for _, id := range identities {
		claims, ok := verifications[id.ID]
		if !ok || len(claims) == 0 {
			continue
		}

		claim := claims[0]

		if claim.Name == "email" {
			emails = append(emails, CheckedEmail{
				Email:      claim.Value,
				Verified:   claim.Verified,
				Verifiable: claim.EndUserTriggerable,
				UpdatedAt:  id.UpdatedAt,
			})
		}
	}
	sort.Slice(emails, func(i, j int) bool {
		return emails[i].UpdatedAt.Before(emails[j].UpdatedAt)
	})
	viewModel := struct{ CheckedEmails []CheckedEmail }{
		CheckedEmails: emails,
	}
	viewmodels.Embed(data, viewModel)

	return data, nil
}

func (h *AuthflowV2SettingsIdentityEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

		h.Renderer.RenderHTML(w, r, TemplateWebSettingsIdentityEmailHTML, data)
		return nil
	})

	ctrl.PostAction("verify", func() error {
		result := webapp.Result{RedirectURI: "/settings/identity"}

		result.WriteResponse(w, r)
		return nil
	})
}
