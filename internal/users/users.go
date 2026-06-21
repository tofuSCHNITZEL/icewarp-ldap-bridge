// Package users defines the bridge's domain model and the repository interface
// its backends implement. This is the persistence seam: a Repository stores and
// retrieves users and validates passwords, in domain terms only. All LDAP
// concerns — DNs, object classes, filters, scopes — live in the ldapserver
// layer, so a repository never sees them.
package users

import (
	"context"
	"errors"
)

// Repository errors. Backends return these; the LDAP layer maps them to result
// codes.
var (
	ErrNotFound           = errors.New("users: not found")
	ErrAlreadyExists      = errors.New("users: already exists")
	ErrInvalidCredentials = errors.New("users: invalid credentials")
)

// User is the domain object the bridge serves. The bridge exists only to project
// IceWarp into Keycloak, so the domain is IceWarp: the name fields follow
// IceWarp's a_vcard card (Firstname, Lastname, Fileas, …). The LDAP attribute
// names Keycloak speaks (givenName, cn, sn, …) are confined to the ldapserver
// layer; fields without a card equivalent keep a plain conceptual name.
type User struct {
	// Username is the unique key (the mailbox local part).
	Username   string
	Fileas     string // "Display as" — the human-readable display name
	Firstname  string
	Lastname   string
	Middlename string
	Nickname   string
	Suffix     string // name suffix, e.g. Jr / III
	Title      string // honorific, e.g. Herr / Dr
	Email      string
	Disabled   bool

	// Password is write-only: set it on Create; reads never populate it.
	Password string
}

// Query narrows a List. The fields are pushdown hints — a backend uses them to
// fetch less, but callers must not assume the result is already exact (the LDAP
// layer applies the full filter afterward). An empty Query lists everyone.
type Query struct {
	Username       string // exact username
	UsernamePrefix string // username prefix
}

// Repository is the persistence backend for users.
type Repository interface {
	// Authenticate validates a username/password, returning
	// ErrInvalidCredentials on any failure (wrong password, unknown, disabled).
	Authenticate(ctx context.Context, username, password string) error
	// Get returns one user by username, or ErrNotFound.
	Get(ctx context.Context, username string) (User, error)
	// List returns users matching the query (empty query = all).
	List(ctx context.Context, q Query) ([]User, error)
	// Create adds a new user, or ErrAlreadyExists.
	Create(ctx context.Context, u User) error
	// Update writes a user's profile fields (not the password), or ErrNotFound.
	Update(ctx context.Context, u User) error
	// SetPassword sets a user's password, or ErrNotFound.
	SetPassword(ctx context.Context, username, password string) error
	// Delete removes a user, or ErrNotFound.
	Delete(ctx context.Context, username string) error
}
