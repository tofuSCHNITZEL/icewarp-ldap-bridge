package cache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
	"github.com/verdigado/icewarp-ldap-bridge/internal/users/memory"
)

// countingBackend is a memory repository that counts the calls the cache makes
// and can be made to fail, so tests can assert what reaches the backend.
type countingBackend struct {
	*memory.Repository

	mu       sync.Mutex
	calls    map[string]int
	readErr  error // returned by the read calls a sweep uses
	authUser string
}

func newBackend() *countingBackend {
	return &countingBackend{Repository: memory.New(), calls: make(map[string]int)}
}

func (b *countingBackend) count(name string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls[name]++
	return b.calls[name]
}

func (b *countingBackend) calledTimes(name string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls[name]
}

func (b *countingBackend) fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readErr = err
}

func (b *countingBackend) err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.readErr
}

func (b *countingBackend) Get(ctx context.Context, username string) (users.User, error) {
	b.count("Get")
	if err := b.err(); err != nil {
		return users.User{}, err
	}
	return b.Repository.Get(ctx, username)
}

func (b *countingBackend) List(ctx context.Context, q users.Query) ([]users.User, error) {
	b.count("List")
	if err := b.err(); err != nil {
		return nil, err
	}
	return b.Repository.List(ctx, q)
}

func (b *countingBackend) ListGroups(ctx context.Context) ([]users.Group, error) {
	b.count("ListGroups")
	if err := b.err(); err != nil {
		return nil, err
	}
	return b.Repository.ListGroups(ctx)
}

func (b *countingBackend) GroupMembers(ctx context.Context, name string) ([]string, error) {
	b.count("GroupMembers")
	if err := b.err(); err != nil {
		return nil, err
	}
	return b.Repository.GroupMembers(ctx, name)
}

func (b *countingBackend) Authenticate(ctx context.Context, username, password string) error {
	b.count("Authenticate")
	b.mu.Lock()
	b.authUser = username
	b.mu.Unlock()
	return b.Repository.Authenticate(ctx, username, password)
}

func seeded(t *testing.T) (*countingBackend, *Repository) {
	t.Helper()
	b := newBackend()
	b.Seed(users.User{Username: "alice", Fileas: "Alice A", Firstname: "Alice", Email: "alice@example.org", Password: "pw"})
	b.Seed(users.User{Username: "bob", Fileas: "Bob B", Email: "bob@example.org"})
	b.SeedGroup("staff", "alice", "bob")
	// A long ttl keeps the background stale-refresh out of the tests.
	return b, New(b, time.Hour, nil)
}

func TestReadsAreServedFromOneSweep(t *testing.T) {
	b, c := seeded(t)
	ctx := context.Background()

	for range 3 {
		list, err := c.List(ctx, users.Query{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("List returned %d users, want 2", len(list))
		}
		u, err := c.Get(ctx, "alice")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if u.Firstname != "Alice" {
			t.Fatalf("Get returned firstname %q, want Alice", u.Firstname)
		}
		members, err := c.GroupMembers(ctx, "staff")
		if err != nil {
			t.Fatalf("GroupMembers: %v", err)
		}
		if len(members) != 2 {
			t.Fatalf("GroupMembers returned %v, want 2 members", members)
		}
	}

	if got := b.calledTimes("List"); got != 1 {
		t.Errorf("backend List called %d times, want 1", got)
	}
	if got := b.calledTimes("Get"); got != 2 { // one per user during the sweep
		t.Errorf("backend Get called %d times, want 2", got)
	}
	if got := b.calledTimes("GroupMembers"); got != 1 {
		t.Errorf("backend GroupMembers called %d times, want 1", got)
	}
}

func TestGetFallsThroughOnMiss(t *testing.T) {
	b, c := seeded(t)
	ctx := context.Background()
	if err := c.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// An account added behind the cache's back is still found.
	b.Seed(users.User{Username: "carol", Email: "carol@example.org"})
	if _, err := c.Get(ctx, "carol"); err != nil {
		t.Fatalf("Get(carol): %v", err)
	}
	if _, err := c.Get(ctx, "nobody"); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("Get(nobody) = %v, want ErrNotFound", err)
	}
}

func TestWritesPatchTheSnapshot(t *testing.T) {
	_, c := seeded(t)
	ctx := context.Background()

	if err := c.Update(ctx, users.User{Username: "alice", Fileas: "Alice Updated", Firstname: "Alice"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	u, err := c.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if u.Fileas != "Alice Updated" {
		t.Errorf("Get returned fileas %q, want the updated value", u.Fileas)
	}

	if err := c.Create(ctx, users.User{Username: "dave", Email: "dave@example.org"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := c.Delete(ctx, "bob"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	list, err := c.List(ctx, users.Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	names := map[string]bool{}
	for _, u := range list {
		names[u.Username] = true
	}
	if !names["dave"] || names["bob"] {
		t.Errorf("List returned %v, want dave present and bob gone", names)
	}
}

func TestAuthenticateAlwaysHitsTheBackend(t *testing.T) {
	b, c := seeded(t)
	ctx := context.Background()

	for range 2 {
		if err := c.Authenticate(ctx, "alice", "pw"); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}
	if got := b.calledTimes("Authenticate"); got != 2 {
		t.Errorf("backend Authenticate called %d times, want 2", got)
	}
}

func TestFailedRefreshServesStaleSnapshot(t *testing.T) {
	b, c := seeded(t)
	ctx := context.Background()
	if err := c.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	boom := errors.New("backend down")
	b.fail(boom)
	if err := c.Refresh(ctx); !errors.Is(err, boom) {
		t.Fatalf("Refresh = %v, want the backend error", err)
	}
	list, err := c.List(ctx, users.Query{})
	if err != nil {
		t.Fatalf("List after failed refresh: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("List returned %d users, want the 2 from the stale snapshot", len(list))
	}
}

func TestColdCacheReportsBackendError(t *testing.T) {
	b, c := seeded(t)
	boom := errors.New("backend down")
	b.fail(boom)

	if _, err := c.List(context.Background(), users.Query{}); !errors.Is(err, boom) {
		t.Fatalf("List = %v, want the backend error", err)
	}
}
