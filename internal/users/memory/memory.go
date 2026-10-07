// Package memory is an in-memory users.Repository for development and tests.
package memory

import (
	"context"
	"strings"
	"sync"

	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
)

// Repository is a concurrency-safe in-memory user store.
type Repository struct {
	mu     sync.RWMutex
	users  map[string]users.User  // keyed by lower-cased username
	groups map[string]users.Group // keyed by lower-cased group name
}

var _ users.Repository = (*Repository)(nil)

// New returns an empty repository.
func New() *Repository {
	return &Repository{users: make(map[string]users.User), groups: make(map[string]users.Group)}
}

// Seed inserts a user directly, bypassing the duplicate check — for fixtures.
func (r *Repository) Seed(u users.User) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[key(u.Username)] = u
}

// SeedGroup inserts a group with the given member usernames — for fixtures.
func (r *Repository) SeedGroup(name string, members ...string) {
	r.SeedGroupDescription(name, "", members...)
}

// SeedGroupDescription inserts a group with an LDAP description — for fixtures.
func (r *Repository) SeedGroupDescription(name, description string, members ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groups[key(name)] = users.Group{Name: name, Description: description, Members: members}
}

func (r *Repository) Authenticate(_ context.Context, username, password string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[key(username)]
	if !ok || u.Disabled || u.Password != password {
		return users.ErrInvalidCredentials
	}
	return nil
}

func (r *Repository) Get(_ context.Context, username string) (users.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[key(username)]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return public(u), nil
}

func (r *Repository) List(_ context.Context, q users.Query) ([]users.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []users.User
	for _, u := range r.users {
		if q.Username != "" && !strings.EqualFold(u.Username, q.Username) {
			continue
		}
		if q.UsernamePrefix != "" && !strings.HasPrefix(key(u.Username), key(q.UsernamePrefix)) {
			continue
		}
		out = append(out, lightweight(u))
	}
	return out, nil
}

func (r *Repository) Create(_ context.Context, u users.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[key(u.Username)]; ok {
		return users.ErrAlreadyExists
	}
	r.users[key(u.Username)] = u
	return nil
}

func (r *Repository) Update(_ context.Context, u users.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.users[key(u.Username)]
	if !ok {
		return users.ErrNotFound
	}
	// Mirror exactly the profile fields the LDAP modify path maps (see
	// ldapserver.Server.modify). Email is intentionally not updated: a primary
	// address change is an account rename the bridge rejects upstream.
	existing.Fileas = u.Fileas
	existing.Firstname = u.Firstname
	existing.Lastname = u.Lastname
	existing.Middlename = u.Middlename
	existing.Nickname = u.Nickname
	existing.Suffix = u.Suffix
	existing.Title = u.Title
	existing.Disabled = u.Disabled
	r.users[key(u.Username)] = existing
	return nil
}

func (r *Repository) SetPassword(_ context.Context, username, password string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[key(username)]
	if !ok {
		return users.ErrNotFound
	}
	u.Password = password
	r.users[key(username)] = u
	return nil
}

func (r *Repository) Delete(_ context.Context, username string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[key(username)]; !ok {
		return users.ErrNotFound
	}
	delete(r.users, key(username))
	return nil
}

func (r *Repository) ListGroups(_ context.Context) ([]users.Group, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]users.Group, 0, len(r.groups))
	for _, group := range r.groups {
		group.Members = nil
		out = append(out, group)
	}
	return out, nil
}

func (r *Repository) GroupMembers(_ context.Context, name string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	group, ok := r.groups[key(name)]
	if !ok {
		return nil, users.ErrNotFound
	}
	return append([]string(nil), group.Members...), nil
}

func key(username string) string { return strings.ToLower(username) }

// public returns a copy with the password cleared (reads never leak it).
func public(u users.User) users.User {
	u.Password = ""
	return u
}

// lightweight returns the candidate form List yields: like public but with the
// group memberships dropped, mirroring the IceWarp backend whose listing call is
// cheap and resolves Groups (u_groups) only on a per-user Get. The ldapserver
// prefilter must not assume memberOf is known at this stage.
func lightweight(u users.User) users.User {
	u = public(u)
	u.Groups = nil
	return u
}
