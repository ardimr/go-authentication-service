package query

import (
	"context"
	"database/sql"

	"github.com/ardimr/go-authentication-service.git/configs/db"
	"github.com/ardimr/go-authentication-service.git/internal/model"
)

type Querier interface {
	GetUsers(ctx context.Context) ([]model.User, error)
	GetUserById(ctx context.Context, id int64) (*model.User, error)
	AddNewUser(ctx context.Context, newUser model.User) (int64, error)
	UpdateUser(ctx context.Context, user model.User) (int64, error)
	DeleteUser(ctx context.Context, id int64) error
	GetUserPasswordByUsername(ctx context.Context, username string) (string, error)
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	GetUserInfoByUsername(ctx context.Context, username string) (*model.UserInfo, error)
}

type PostgresQuerier struct {
	db db.DBInterface
}

func NewPostgresQuerier(db db.DBInterface) *PostgresQuerier {
	return &PostgresQuerier{
		db: db,
	}
}

// Query Implementation
func (q *PostgresQuerier) GetUserPasswordByUsername(ctx context.Context, username string) (string, error) {
	var password string

	queryStatement := `
	SELECT
		password
	FROM public.users
	WHERE username=$1
	`

	err := q.db.QueryRowContext(ctx, queryStatement, username).Scan(&password)

	if err != nil {
		return "", err
	}

	return password, nil

}
func (q *PostgresQuerier) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User

	queryStatement := `
	SELECT
		username,
		password,
		name,
		email,
		role
	FROM public.users
	WHERE username=$1
	`
	err := q.db.QueryRowContext(ctx, queryStatement, username).Scan(
		&user.Username,
		&user.Password,
		&user.Name,
		&user.Email,
		&user.Role,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (q *PostgresQuerier) GetUserInfoByUsername(ctx context.Context, username string) (*model.UserInfo, error) {
	var user model.UserInfo

	tx, err := q.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelDefault})

	if err != nil {
		return nil, err
	}

	queryStatement := `
	SELECT
		username,
		name,
		password,
		email
	FROM public.users
	WHERE username=$1
	`
	err = tx.QueryRowContext(ctx, queryStatement, username).Scan(
		&user.Username,
		&user.Name,
		&user.Password,
		&user.Email,
	)

	if err != nil {
		tx.Rollback()
		return nil, err
	}

	queryStatement = `
	SELECT
		roles.name
	FROM users
	INNER JOIN user_roles
	ON users.id = user_roles.user_id
	INNER JOIN roles
	ON user_roles.role_id = roles.id
	WHERE users.username=$1
	`
	err = tx.QueryRowContext(ctx, queryStatement, username).Scan(
		&user.Role,
	)

	if err != nil {
		tx.Rollback()
		return nil, err
	}

	queryStatement = `
	SELECT
		permissions.action
	FROM users
	INNER JOIN user_roles
	ON users.id = user_roles.user_id
	INNER JOIN role_permissions
	ON user_roles.role_id = role_permissions.role_id
	INNER JOIN permissions
	ON role_permissions.permission_id = permissions.id
	WHERE users.username=$1
	`
	rows, err := tx.QueryContext(ctx, queryStatement, username)

	if err != nil {
		tx.Rollback()
		return nil, err
	}

	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)

		if err != nil {
			tx.Rollback()
			return nil, err
		}

		user.Permissions = append(user.Permissions, permission)
	}

	tx.Commit()
	return &user, nil
}

func (q *PostgresQuerier) GetUsers(ctx context.Context) ([]model.User, error) {
	var users []model.User

	sqlStatement := `
	SELECT 
		id,
		username,
		name,
		email,
		created_at,
		updated_at
	FROM public.users
	`

	// Querying
	rows, err := q.db.QueryContext(ctx, sqlStatement)

	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var user model.User

		// read data
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Name,
			&user.Email,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (q *PostgresQuerier) GetUserById(ctx context.Context, id int64) (*model.User, error) {
	var user model.User

	queryStatement := `
	SELECT
		*
	FROM public.users
	WHERE id=$1
	`
	err := q.db.QueryRowContext(ctx, queryStatement, id).Scan(
		&user.ID,
		&user.Name,
	)

	if err != nil {
		return nil, sql.ErrNoRows
	}

	return &user, nil
}

func (q *PostgresQuerier) AddNewUser(ctx context.Context, newUser model.User) (int64, error) {

	var newId int64

	sqlStatement := `
	INSERT INTO public.users 
		(name, username, password, email) VALUES ($1,$2,$3,$4) RETURNING id
	`

	err := q.db.QueryRowContext(ctx,
		sqlStatement,
		newUser.Name,
		newUser.Username,
		newUser.Password,
		newUser.Email).Scan(&newId)

	if err != nil {
		return 0, err
	}

	return newId, nil
}

func (q *PostgresQuerier) UpdateUser(ctx context.Context, user model.User) (int64, error) {

	sqlStatement := `
	UPDATE public.users SET name=$2 WHERE id=$1
	`

	res, err := q.db.ExecContext(ctx, sqlStatement, user.ID, user.Name)

	if err != nil {
		return 0, err
	}

	rowsAffeced, err := res.RowsAffected()

	if err != nil {
		return 0, err
	}
	return rowsAffeced, nil
}

func (q *PostgresQuerier) DeleteUser(ctx context.Context, id int64) error {

	// create sql statement to delete user from database
	sqlStatement := `DELETE FROM public.users WHERE id=$1`

	// execute sql statement
	res, err := q.db.ExecContext(ctx, sqlStatement, id)

	if err != nil {
		return err
	}

	rowsAffected, _ := res.RowsAffected()

	if rowsAffected < 1 {
		return sql.ErrNoRows
	}
	return nil
}
