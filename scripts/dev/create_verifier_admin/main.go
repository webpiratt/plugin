package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pass "github.com/vultisig/plugin/internal/password"
)

var username string
var password string

// Usage:
// `go run ./scripts/dev/create_verifier_admin/main.go -username=admin -password=s3cre7`
func main() {
	flag.StringVar(&username, "username", "", "user name")
	flag.StringVar(&password, "password", "", "user password")
	flag.Parse()

	ctx := context.Background()

	passwordHash, err := pass.HashPassword(password)
	if err != nil {
		panic(fmt.Errorf("failed to hash password: %w", err))
	}

	pool, err := pgxpool.New(ctx, "postgres://myuser:mypassword@localhost:5432/vultisig-plugin?sslmode=disable")
	if err != nil {
		panic(fmt.Errorf("failed to create connection pool: %w", err))
	}

	query := fmt.Sprintf(`INSERT INTO %s (
		username,
		password
	) VALUES (
		@Username,
		@Password
	) RETURNING id;`, "users")
	args := pgx.NamedArgs{
		"Username": username,
		"Password": passwordHash,
	}

	var createdId string
	err = pool.QueryRow(ctx, query, args).Scan(&createdId)
	if err != nil {
		panic(fmt.Errorf("failed to create user: %w", err))
	}

	fmt.Println("User created successfully")
}
