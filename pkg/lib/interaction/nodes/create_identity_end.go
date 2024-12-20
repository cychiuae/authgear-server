package nodes

import (
	"context"

	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/interaction"
)

func init() {
	interaction.RegisterNode(&NodeCreateIdentityEnd{})
}

type EdgeCreateIdentityEnd struct {
	IdentitySpec *identity.Spec
}

func (e *EdgeCreateIdentityEnd) Instantiate(goCtx context.Context, ctx *interaction.Context, graph *interaction.Graph, rawInput interface{}) (interaction.Node, error) {
	byPassBlocklistAllowlist := false
	var bypassInput interface{ BypassLoginIDEmailBlocklistAllowlist() bool }
	if interaction.Input(rawInput, &bypassInput) {
		byPassBlocklistAllowlist = bypassInput.BypassLoginIDEmailBlocklistAllowlist()
	}

	info, err := ctx.Identities.New(goCtx, graph.MustGetUserID(), e.IdentitySpec, identity.NewIdentityOptions{
		LoginIDEmailByPassBlocklistAllowlist: byPassBlocklistAllowlist,
	})
	if err != nil {
		return nil, err
	}

	return &NodeCreateIdentityEnd{
		IdentitySpec: e.IdentitySpec,
		IdentityInfo: info,
	}, nil
}

type NodeCreateIdentityEnd struct {
	IdentitySpec *identity.Spec `json:"identity_spec"`
	IdentityInfo *identity.Info `json:"identity_info"`
}

func (n *NodeCreateIdentityEnd) Prepare(goCtx context.Context, ctx *interaction.Context, graph *interaction.Graph) error {
	return nil
}

func (n *NodeCreateIdentityEnd) GetEffects(goCtx context.Context) ([]interaction.Effect, error) {
	return nil, nil
}

func (n *NodeCreateIdentityEnd) DeriveEdges(goCtx context.Context, graph *interaction.Graph) ([]interaction.Edge, error) {
	return graph.Intent.DeriveEdgesForNode(goCtx, graph, n)
}
