package ldap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
)

const (
	tableNameAuthIdentityLDAP = "_auth_identity_ldap"
)

type Store struct {
	SQLBuilder  *appdb.SQLBuilderApp
	SQLExecutor *appdb.SQLExecutor
}

func (s *Store) selectQuery() db.SelectBuilder {
	return s.SQLBuilder.
		Select(
			"p.id",
			"p.user_id",
			"p.created_at",
			"p.updated_at",

			"l.server_name",
			"l.user_id_attribute_name",
			"l.user_id_attribute_value",
			"l.claims",
			"l.raw_entry_json",
			"l.last_login_username",
		).
		From(s.SQLBuilder.TableName("_auth_identity"), "p").
		Join(s.SQLBuilder.TableName(tableNameAuthIdentityLDAP), "l", "p.id = l.id")
}

func (s *Store) scan(scn db.Scanner) (*identity.LDAP, error) {
	i := &identity.LDAP{}
	var claims []byte
	var rawEntryJSON []byte

	err := scn.Scan(
		&i.ID,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ServerName,
		&i.UserIDAttributeName,
		&i.UserIDAttributeValue,
		&claims,
		&rawEntryJSON,
		&i.LastLoginUserName,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, api.ErrIdentityNotFound
	} else if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(claims, &i.Claims); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(rawEntryJSON, &i.RawEntryJSON); err != nil {
		return nil, err
	}

	return i, nil
}

func (s *Store) Get(ctx context.Context, userID string, id string) (*identity.LDAP, error) {
	q := s.selectQuery().Where("p.user_id = ? AND p.id = ?", userID, id)
	rows, err := s.SQLExecutor.QueryRowWith(ctx, q)
	if err != nil {
		return nil, err
	}
	return s.scan(rows)
}

func (s *Store) GetMany(ctx context.Context, ids []string) ([]*identity.LDAP, error) {
	builder := s.selectQuery().Where("p.id = ANY (?)", pq.Array(ids))

	rows, err := s.SQLExecutor.QueryWith(ctx, builder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var is []*identity.LDAP
	for rows.Next() {
		i, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		is = append(is, i)
	}

	return is, nil
}

func (s *Store) List(ctx context.Context, userID string) ([]*identity.LDAP, error) {
	builder := s.selectQuery().Where("p.user_id = ?", userID)

	rows, err := s.SQLExecutor.QueryWith(ctx, builder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var is []*identity.LDAP
	for rows.Next() {
		i, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		is = append(is, i)
	}

	return is, nil
}

func (s *Store) ListByClaim(ctx context.Context, name string, value string) ([]*identity.LDAP, error) {
	q := s.selectQuery().
		Where("(l.claims ->> ?) = ?", name, value)

	rows, err := s.SQLExecutor.QueryWith(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var is []*identity.LDAP
	for rows.Next() {
		i, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		is = append(is, i)
	}

	return is, nil
}

func (s *Store) GetByServerUserID(ctx context.Context, serverName string, userIDAttributeName string, userIDAttributeValue []byte) (*identity.LDAP, error) {
	q := s.selectQuery().
		Where(
			"l.server_name = ? AND l.user_id_attribute_name = ? AND l.user_id_attribute_value = ?",
			serverName,
			userIDAttributeName,
			userIDAttributeValue,
		)
	rows, err := s.SQLExecutor.QueryRowWith(ctx, q)
	if err != nil {
		return nil, err
	}
	return s.scan(rows)
}

func (s *Store) Create(ctx context.Context, i *identity.LDAP) (err error) {
	builder := s.SQLBuilder.
		Insert(s.SQLBuilder.TableName("_auth_identity")).
		Columns(
			"id",
			"type",
			"user_id",
			"created_at",
			"updated_at",
		).
		Values(
			i.ID,
			model.IdentityTypeLDAP,
			i.UserID,
			i.CreatedAt,
			i.UpdatedAt,
		)

	_, err = s.SQLExecutor.ExecWith(ctx, builder)
	if err != nil {
		return err
	}

	claims, err := json.Marshal(i.Claims)
	if err != nil {
		return err
	}
	rawEntryJSON, err := json.Marshal(i.RawEntryJSON)
	if err != nil {
		return err
	}

	q := s.SQLBuilder.
		Insert(s.SQLBuilder.TableName(tableNameAuthIdentityLDAP)).
		Columns(
			"id",
			"server_name",
			"user_id_attribute_name",
			"user_id_attribute_value",
			"claims",
			"raw_entry_json",
			"last_login_username",
		).
		Values(
			i.ID,
			i.ServerName,
			i.UserIDAttributeName,
			i.UserIDAttributeValue,
			claims,
			rawEntryJSON,
			i.LastLoginUserName,
		)

	_, err = s.SQLExecutor.ExecWith(ctx, q)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) Update(ctx context.Context, i *identity.LDAP) error {
	claims, err := json.Marshal(i.Claims)
	if err != nil {
		return err
	}
	rawEntryJSON, err := json.Marshal(i.RawEntryJSON)
	if err != nil {
		return err
	}

	q := s.SQLBuilder.
		Update(s.SQLBuilder.TableName(tableNameAuthIdentityLDAP)).
		Set("claims", claims).
		Set("raw_entry_json", rawEntryJSON).
		Set("last_login_username", i.LastLoginUserName).
		Where("id = ?", i.ID)

	result, err := s.SQLExecutor.ExecWith(ctx, q)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return api.ErrIdentityNotFound
	} else if rowsAffected > 1 {
		panic(fmt.Sprintf("identity_ldap: want 1 row updated, got %v", rowsAffected))
	}

	q = s.SQLBuilder.
		Update(s.SQLBuilder.TableName("_auth_identity")).
		Set("updated_at", i.UpdatedAt).
		Where("id = ?", i.ID)

	_, err = s.SQLExecutor.ExecWith(ctx, q)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) Delete(ctx context.Context, i *identity.LDAP) error {
	q := s.SQLBuilder.
		Delete(s.SQLBuilder.TableName(tableNameAuthIdentityLDAP)).
		Where("id = ?", i.ID)

	_, err := s.SQLExecutor.ExecWith(ctx, q)
	if err != nil {
		return err
	}

	q = s.SQLBuilder.
		Delete(s.SQLBuilder.TableName("_auth_identity")).
		Where("id = ?", i.ID)

	_, err = s.SQLExecutor.ExecWith(ctx, q)
	if err != nil {
		return err
	}

	return nil
}
