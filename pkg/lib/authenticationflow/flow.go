package authenticationflow

import (
	"fmt"
	"reflect"

	"github.com/authgear/authgear-server/pkg/lib/config"
)

// PublicFlow is a instantiable intent by the public.
type PublicFlow interface {
	Intent
	FlowType() FlowType
	FlowInit(r FlowReference)
	FlowFlowReference() FlowReference
	FlowRootObject(deps *Dependencies) (config.AuthenticationFlowObject, error)
}

// FlowType denotes the type of the intents.
type FlowType string

const (
	FlowTypeSignup      FlowType = "signup"
	FlowTypeLogin       FlowType = "login"
	FlowTypeSignupLogin FlowType = "signup_login"
)

var AllFlowTypes []FlowType = []FlowType{
	FlowTypeSignup,
	FlowTypeLogin,
	FlowTypeSignupLogin,
}

// FlowReference is an API object.
type FlowReference struct {
	Type FlowType `json:"type"`
	Name string   `json:"name"`
}

// FlowStep is an API object.
type FlowStep struct {
	Type           string                                  `json:"type"`
	Identification config.AuthenticationFlowIdentification `json:"identification,omitempty"`
	Authentication config.AuthenticationFlowAuthentication `json:"authentication,omitempty"`
}

// FlowResponse is an API object.
// When the flow finished, `json_schema` is absent and `finished` is true.
// When data contains "redirect_uri", the driver of the flow must perform redirect.
type FlowResponse struct {
	// StateID is the StateID.
	StateID string `json:"state_id"`
	// ID is the flow ID.
	ID string `json:"id"`

	Finished bool `json:"finished,omitempty"`

	Type FlowType `json:"type,omitempty"`
	Name string   `json:"name,omitempty"`

	Step *FlowStep `json:"step,omitempty"`

	Data Data `json:"data"`
}

type flowFactory func() PublicFlow

var flowRegistry = map[FlowType]flowFactory{}

// RegisterFlow is for registering a flow.
func RegisterFlow(flow PublicFlow) {
	flowGoType := reflect.TypeOf(flow).Elem()

	flowType := flow.FlowType()
	factory := flowFactory(func() PublicFlow {
		return reflect.New(flowGoType).Interface().(PublicFlow)
	})

	if _, registered := flowRegistry[flowType]; registered {
		panic(fmt.Errorf("duplicated flow type: %v", flowType))
	}

	flowRegistry[flowType] = factory

	RegisterIntent(flow)
}

// InstantiateFlow is used by the HTTP layer to instantiate a Flow.
func InstantiateFlow(f FlowReference) (PublicFlow, error) {
	factory, ok := flowRegistry[f.Type]
	if !ok {
		return nil, ErrUnknownFlow
	}

	flow := factory()
	flow.FlowInit(f)
	return flow, nil
}