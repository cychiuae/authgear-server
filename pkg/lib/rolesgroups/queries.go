package rolesgroups

import (
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/util/graphqlutil"
	"github.com/authgear/authgear-server/pkg/util/slice"
)

type Queries struct {
	Store *Store
}

func (q *Queries) GetRole(id string) (*model.Role, error) {
	role, err := q.Store.GetRoleByID(id)
	if err != nil {
		return nil, err
	}
	return role.ToModel(), nil
}

func (q *Queries) GetGroup(id string) (*model.Group, error) {
	group, err := q.Store.GetGroupByID(id)
	if err != nil {
		return nil, err
	}
	return group.ToModel(), nil
}

func (q *Queries) GetManyRoles(ids []string) ([]*model.Role, error) {
	roles, err := q.Store.GetManyRoles(ids)
	if err != nil {
		return nil, err
	}

	roleModels := make([]*model.Role, len(roles))
	for i, r := range roles {
		roleModels[i] = r.ToModel()
	}

	return roleModels, nil
}

func (q *Queries) GetManyGroups(ids []string) ([]*model.Group, error) {
	groups, err := q.Store.GetManyGroups(ids)
	if err != nil {
		return nil, err
	}

	groupModels := make([]*model.Group, len(groups))
	for i, r := range groups {
		groupModels[i] = r.ToModel()
	}

	return groupModels, nil
}

func (q *Queries) ListGroupsByRoleID(roleID string) ([]*model.Group, error) {
	groups, err := q.Store.ListGroupsByRoleID(roleID)
	if err != nil {
		return nil, err
	}

	groupModels := make([]*model.Group, len(groups))
	for i, r := range groups {
		groupModels[i] = r.ToModel()
	}

	return groupModels, nil
}

func (q *Queries) ListRolesByGroupID(groupID string) ([]*model.Role, error) {
	roles, err := q.Store.ListRolesByGroupID(groupID)
	if err != nil {
		return nil, err
	}

	roleModels := make([]*model.Role, len(roles))
	for i, r := range roles {
		roleModels[i] = r.ToModel()
	}

	return roleModels, nil
}

type ListRolesOptions struct {
	SearchKeyword string
	ExcludedIDs   []string
}

func (q *Queries) ListRoles(options *ListRolesOptions, pageArgs graphqlutil.PageArgs) ([]model.PageItemRef, error) {
	roles, offset, err := q.Store.ListRoles(options, pageArgs)
	if err != nil {
		return nil, err
	}

	models := make([]model.PageItemRef, len(roles))
	for i, r := range roles {
		pageKey := db.PageKey{Offset: offset + uint64(i)}
		cursor, err := pageKey.ToPageCursor()
		if err != nil {
			return nil, err
		}

		models[i] = model.PageItemRef{ID: r.ID, Cursor: cursor}
	}
	return models, nil
}

type ListGroupsOptions struct {
	SearchKeyword string
	ExcludedIDs   []string
}

func (q *Queries) ListGroups(options *ListGroupsOptions, pageArgs graphqlutil.PageArgs) ([]model.PageItemRef, error) {
	groups, offset, err := q.Store.ListGroups(options, pageArgs)
	if err != nil {
		return nil, err
	}

	models := make([]model.PageItemRef, len(groups))
	for i, r := range groups {
		pageKey := db.PageKey{Offset: offset + uint64(i)}
		cursor, err := pageKey.ToPageCursor()
		if err != nil {
			return nil, err
		}

		models[i] = model.PageItemRef{ID: r.ID, Cursor: cursor}
	}
	return models, nil
}

func (q *Queries) ListRolesByUserID(userID string) ([]*model.Role, error) {
	roles, err := q.Store.ListRolesByUserID(userID)
	if err != nil {
		return nil, err
	}

	roleModels := make([]*model.Role, len(roles))
	for i, r := range roles {
		roleModels[i] = r.ToModel()
	}

	return roleModels, nil
}

func (q *Queries) ListRolesByUserIDs(userIDs []string) (map[string][]*model.Role, error) {
	rolesByUserID, err := q.Store.ListRolesByUserIDs(userIDs)
	if err != nil {
		return nil, err
	}

	roleModelsByUserID := make(map[string][]*model.Role)
	for k, v := range rolesByUserID {
		for _, r := range v {
			roleModelsByUserID[k] = append(roleModelsByUserID[k], r.ToModel())
		}
	}

	return roleModelsByUserID, nil
}

func (q *Queries) ListGroupsByUserID(userID string) ([]*model.Group, error) {
	groups, err := q.Store.ListGroupsByUserID(userID)
	if err != nil {
		return nil, err
	}

	groupModels := make([]*model.Group, len(groups))
	for i, r := range groups {
		groupModels[i] = r.ToModel()
	}

	return groupModels, nil
}

func (q *Queries) ListGroupsByUserIDs(userIDs []string) (map[string][]*model.Group, error) {
	groupsByUserID, err := q.Store.ListGroupsByUserIDs(userIDs)
	if err != nil {
		return nil, err
	}

	groupModelsByUserID := make(map[string][]*model.Group)
	for k, v := range groupsByUserID {
		for _, g := range v {
			groupModelsByUserID[k] = append(groupModelsByUserID[k], g.ToModel())
		}
	}

	return groupModelsByUserID, nil
}

func (q *Queries) ListUserIDsByRoleID(roleID string, pageArgs graphqlutil.PageArgs) ([]model.PageItemRef, error) {
	userIDs, offset, err := q.Store.ListUserIDsByRoleID(roleID, pageArgs)
	if err != nil {
		return nil, err
	}

	models := make([]model.PageItemRef, len(userIDs))
	for i, r := range userIDs {
		pageKey := db.PageKey{Offset: offset + uint64(i)}
		cursor, err := pageKey.ToPageCursor()
		if err != nil {
			return nil, err
		}

		models[i] = model.PageItemRef{ID: r, Cursor: cursor}
	}
	return models, nil
}

func (q *Queries) ListAllUserIDsByRoleIDs(roleIDs []string) ([]string, error) {
	return q.Store.ListAllUserIDsByRoleID(roleIDs)
}

func (q *Queries) ListAllUserIDsByGroupKeys(groupKeys []string) ([]string, error) {
	groups, err := q.Store.GetManyGroupsByKeys(groupKeys)
	if err != nil {
		return nil, err
	}
	groupIDs := slice.Map(groups, func(group *Group) string { return group.ID })
	return q.Store.ListAllUserIDsByGroupIDs(groupIDs)
}

func (q *Queries) ListAllUserIDsByGroupIDs(groupIDs []string) ([]string, error) {
	return q.Store.ListAllUserIDsByGroupIDs(groupIDs)
}

func (q *Queries) ListUserIDsByGroupID(groupID string, pageArgs graphqlutil.PageArgs) ([]model.PageItemRef, error) {
	userIDs, offset, err := q.Store.ListUserIDsByGroupID(groupID, pageArgs)
	if err != nil {
		return nil, err
	}

	models := make([]model.PageItemRef, len(userIDs))
	for i, r := range userIDs {
		pageKey := db.PageKey{Offset: offset + uint64(i)}
		cursor, err := pageKey.ToPageCursor()
		if err != nil {
			return nil, err
		}

		models[i] = model.PageItemRef{ID: r, Cursor: cursor}
	}
	return models, nil
}

func (q *Queries) ListEffectiveRolesByUserID(userID string) ([]*model.Role, error) {
	roles, err := q.Store.ListEffectiveRolesByUserID(userID)
	if err != nil {
		return nil, err
	}

	roleModels := make([]*model.Role, len(roles))
	for i, r := range roles {
		roleModels[i] = r.ToModel()
	}

	return roleModels, nil
}

func (q *Queries) ListAllUserIDsByEffectiveRoleIDs(roleIDs []string) ([]string, error) {
	return q.Store.ListAllUserIDsByEffectiveRoleIDs(roleIDs)
}

func (f *Queries) ListAllRolesByKeys(keys []string) ([]*model.Role, error) {
	roles, err := f.Store.GetManyRolesByKeys(keys)
	if err != nil {
		return nil, err
	}
	return slice.Map(roles, func(r *Role) *model.Role { return r.ToModel() }), nil
}

func (f *Queries) ListAllGroupsByKeys(keys []string) ([]*model.Group, error) {
	groups, err := f.Store.GetManyGroupsByKeys(keys)
	if err != nil {
		return nil, err
	}
	return slice.Map(groups, func(g *Group) *model.Group { return g.ToModel() }), nil
}

func (q *Queries) CountRoles() (uint64, error) {
	return q.Store.CountRoles()
}

func (q *Queries) CountGroups() (uint64, error) {
	return q.Store.CountGroups()
}
