package latte

import (
	"context"
	"fmt"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
	"github.com/authgear/authgear-server/pkg/util/uuid"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func init() {
	workflow.RegisterPrivateIntent(&IntentSignup{})
}

var IntentSignupSchema = validation.NewSimpleSchema(`
	{
		"type": "object",
		"additionalProperties": false
	}
`)

type IntentSignup struct{}

func (*IntentSignup) Kind() string {
	return "latte.IntentSignup"
}

func (*IntentSignup) JSONSchema() *validation.SimpleSchema {
	return IntentSignupSchema
}

func (*IntentSignup) CanReactTo(ctx context.Context, deps *workflow.Dependencies, w *workflow.Workflow) ([]workflow.Input, error) {
	switch len(w.Nodes) {
	case 0:
		// Generate a new user ID.
		return nil, nil
	case 1:
		// Create a phone login ID.
		return nil, nil
	case 2:
		// Create a email login ID.
		// We assume the project is set to skip verify email on sign up.
		return nil, nil
	case 3:
		// Create a primary password.
		return nil, nil
	case 4:
		// Create a session, if needed.
		return nil, nil
	default:
		return nil, workflow.ErrEOF
	}
}

func (i *IntentSignup) ReactTo(ctx context.Context, deps *workflow.Dependencies, w *workflow.Workflow, input workflow.Input) (*workflow.Node, error) {
	switch len(w.Nodes) {
	case 0:
		// The token will be taken in on-commit effect.
		bucket := AntiSpamSignupBucket(string(deps.RemoteIP))
		pass, _, err := deps.RateLimiter.CheckToken(bucket)
		if err != nil {
			return nil, err
		}
		if !pass {
			return nil, bucket.BucketError()
		}
		return workflow.NewNodeSimple(&NodeDoCreateUser{
			UserID: uuid.New(),
		}), nil
	case 1:
		return workflow.NewSubWorkflow(&IntentCreateLoginID{
			// LoginID key and LoginID type are fixed here.
			UserID:      i.userID(w),
			LoginIDType: model.LoginIDKeyTypePhone,
			LoginIDKey:  string(model.LoginIDKeyTypePhone),
		}), nil
	case 2:
		return workflow.NewSubWorkflow(&IntentCreateLoginID{
			// LoginID key and LoginID type are fixed here.
			UserID:      i.userID(w),
			LoginIDType: model.LoginIDKeyTypeEmail,
			LoginIDKey:  string(model.LoginIDKeyTypeEmail),
		}), nil
	case 3:
		// The type, kind is fixed here.
		return workflow.NewSubWorkflow(&IntentCreatePassword{
			UserID:                 i.userID(w),
			AuthenticatorKind:      authenticator.KindPrimary,
			AuthenticatorIsDefault: false,
		}), nil
	case 4:
		return workflow.NewSubWorkflow(&IntentCreateSession{
			UserID:       i.userID(w),
			CreateReason: session.CreateReasonSignup,
			// AMR is NOT populated because
			// 1. Strictly speaking this is NOT an authentication. It is a sign up.
			// 2. 3 authenticators were created. Should we report all 3?
			AMR:        nil,
			SkipCreate: workflow.GetSuppressIDPSessionCookie(ctx),
		}), nil
	}

	return nil, workflow.ErrIncompatibleInput
}

func (i *IntentSignup) GetEffects(ctx context.Context, deps *workflow.Dependencies, w *workflow.Workflow) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			// Apply ratelimit on sign up.
			bucket := AntiSpamSignupBucket(string(deps.RemoteIP))
			err := deps.RateLimiter.TakeToken(bucket)
			if err != nil {
				return err
			}
			return nil
		}),
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			var identities []*identity.Info
			identityWorkflows := workflow.FindSubWorkflows[NewIdentityGetter](w)
			for _, subWorkflow := range identityWorkflows {
				if iden, ok := subWorkflow.Intent.(NewIdentityGetter).GetNewIdentity(subWorkflow); ok {
					identities = append(identities, iden)
				}
			}

			var authenticators []*authenticator.Info
			authenticatorWorkflows := workflow.FindSubWorkflows[NewAuthenticatorGetter](w)
			for _, subWorkflow := range authenticatorWorkflows {
				if a, ok := subWorkflow.Intent.(NewAuthenticatorGetter).GetNewAuthenticator(subWorkflow); ok {
					authenticators = append(authenticators, a)
				}
			}

			userID := i.userID(w)
			isAdminAPI := false
			state := workflow.GetState(ctx)

			u, err := deps.Users.GetRaw(userID)
			if err != nil {
				return err
			}

			err = deps.Users.AfterCreate(
				u,
				identities,
				authenticators,
				isAdminAPI,
				state,
			)
			if err != nil {
				return err
			}

			return nil
		}),
	}, nil
}

func (*IntentSignup) OutputData(ctx context.Context, deps *workflow.Dependencies, w *workflow.Workflow) (interface{}, error) {
	return nil, nil
}

func (i *IntentSignup) userID(w *workflow.Workflow) string {
	node, ok := workflow.FindSingleNode[*NodeDoCreateUser](w)
	if !ok {
		panic(fmt.Errorf("expected userID"))
	}
	return node.UserID
}

type NewIdentityGetter interface {
	workflow.Intent
	GetNewIdentity(w *workflow.Workflow) (*identity.Info, bool)
}

type NewAuthenticatorGetter interface {
	workflow.Intent
	GetNewAuthenticator(w *workflow.Workflow) (*authenticator.Info, bool)
}