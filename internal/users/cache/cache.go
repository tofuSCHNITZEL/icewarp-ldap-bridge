// Package cache wraps a users.Repository with a periodically refreshed
// in-memory snapshot of the whole directory. IceWarp's RPC API is slow and an
// LDAP subtree search costs one backend call per user (list + one read each), so
// reads — Get, List, ListGroups, GroupMembers — are answered from the snapshot
// and only the background sweep talks to the backend. Authentication always goes
// straight through (credentials are never cached); writes go through and then
// patch the snapshot so a change made via the bridge is visible immediately.
package cache

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
)

// loadConcurrency bounds how many per-user backend reads a sweep runs at once.
const loadConcurrency = 8

// snapshot is one immutable view of the directory. It is published as a whole
// and never mutated afterward, so readers can use it without holding a lock.
type snapshot struct {
	users   map[string]users.User // keyed by lower-cased username
	groups  map[string][]string   // lower-cased group name -> member usernames
	takenAt time.Time
}

// Repository is a users.Repository serving reads from a cached snapshot of the
// backend.
type Repository struct {
	backend users.Repository
	ttl     time.Duration
	logger  *slog.Logger

	mu   sync.RWMutex
	snap *snapshot

	loadMu     sync.Mutex  // serializes sweeps, so a burst of reads causes one
	refreshing atomic.Bool // guards the background stale-refresh goroutine
}

var _ users.Repository = (*Repository)(nil)

// New wraps backend with a snapshot considered fresh for ttl. Run keeps it warm;
// without Run the snapshot is loaded on the first read and refreshed in the
// background once it ages past ttl.
func New(backend users.Repository, ttl time.Duration, logger *slog.Logger) *Repository {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Repository{backend: backend, ttl: ttl, logger: logger}
}

// Run loads the snapshot and refreshes it every ttl until ctx is done. Call it
// in its own goroutine. A failed sweep keeps the previous snapshot: stale data
// serves LDAP better than a failing search, which Keycloak may read as "all
// users deleted".
func (r *Repository) Run(ctx context.Context) {
	if err := r.Refresh(ctx); err != nil {
		r.logger.Warn("cache: initial load failed, falling back to on-demand", "err", err)
	}
	t := time.NewTicker(r.ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Refresh(ctx); err != nil {
				r.logger.Warn("cache: refresh failed, serving stale snapshot", "err", err)
			}
		}
	}
}

// Refresh sweeps the backend and replaces the snapshot.
func (r *Repository) Refresh(ctx context.Context) error {
	r.loadMu.Lock()
	defer r.loadMu.Unlock()
	_, err := r.load(ctx)
	return err
}

// --- reads ---

func (r *Repository) Get(ctx context.Context, username string) (users.User, error) {
	s, err := r.current(ctx)
	if err != nil {
		return users.User{}, err
	}
	if u, ok := s.users[key(username)]; ok {
		return u, nil
	}
	// A miss may be an account created since the sweep, so ask the backend
	// rather than reporting a user that exists as deleted.
	return r.backend.Get(ctx, username)
}

func (r *Repository) List(ctx context.Context, q users.Query) ([]users.User, error) {
	s, err := r.current(ctx)
	if err != nil {
		return nil, err
	}
	// An exact-username query the snapshot doesn't know is a single cheap
	// backend lookup; delegating keeps accounts created outside the bridge
	// findable before the next sweep.
	if q.Username != "" {
		if u, ok := s.users[key(q.Username)]; ok {
			return []users.User{u}, nil
		}
		return r.backend.List(ctx, q)
	}

	out := make([]users.User, 0, len(s.users))
	for k, u := range s.users {
		if q.UsernamePrefix != "" && !strings.HasPrefix(k, key(q.UsernamePrefix)) {
			continue
		}
		out = append(out, u)
	}
	return out, nil
}

func (r *Repository) ListGroups(ctx context.Context) ([]users.Group, error) {
	s, err := r.current(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]users.Group, 0, len(s.groups))
	for name := range s.groups {
		out = append(out, users.Group{Name: name})
	}
	return out, nil
}

func (r *Repository) GroupMembers(ctx context.Context, name string) ([]string, error) {
	s, err := r.current(ctx)
	if err != nil {
		return nil, err
	}
	if members, ok := s.groups[key(name)]; ok {
		return append([]string(nil), members...), nil
	}
	return r.backend.GroupMembers(ctx, name)
}

// --- pass-through ---

// Authenticate always hits the backend: passwords are never cached, and only the
// backend can report a disabled or expired account.
func (r *Repository) Authenticate(ctx context.Context, username, password string) error {
	return r.backend.Authenticate(ctx, username, password)
}

func (r *Repository) Create(ctx context.Context, u users.User) error {
	if err := r.backend.Create(ctx, u); err != nil {
		return err
	}
	r.sync(ctx, u.Username)
	return nil
}

func (r *Repository) Update(ctx context.Context, u users.User) error {
	if err := r.backend.Update(ctx, u); err != nil {
		return err
	}
	r.sync(ctx, u.Username)
	return nil
}

// SetPassword needs no cache work — the snapshot holds no credentials.
func (r *Repository) SetPassword(ctx context.Context, username, password string) error {
	return r.backend.SetPassword(ctx, username, password)
}

func (r *Repository) Delete(ctx context.Context, username string) error {
	if err := r.backend.Delete(ctx, username); err != nil {
		return err
	}
	r.publish(func(s *snapshot) { delete(s.users, key(username)) })
	return nil
}

// --- snapshot management ---

// current returns the snapshot to serve reads from, loading one if the cache is
// cold. An aged snapshot is served as-is and replaced in the background, so a
// read never waits on the backend once the cache is warm.
func (r *Repository) current(ctx context.Context) (*snapshot, error) {
	if s := r.peek(); s != nil {
		if time.Since(s.takenAt) > r.ttl {
			r.refreshAsync(ctx)
		}
		return s, nil
	}

	r.loadMu.Lock()
	defer r.loadMu.Unlock()
	if s := r.peek(); s != nil { // filled while we waited for the lock
		return s, nil
	}
	return r.load(ctx)
}

func (r *Repository) peek() *snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snap
}

// refreshAsync starts one background sweep, if none is running. It detaches the
// request's cancellation (the LDAP request it came from will be long gone) but
// keeps its values, and caps the sweep at one refresh interval.
func (r *Repository) refreshAsync(ctx context.Context) {
	if !r.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.refreshing.Store(false)
		sweepCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.ttl)
		defer cancel()
		if err := r.Refresh(sweepCtx); err != nil {
			r.logger.Warn("cache: background refresh failed, serving stale snapshot", "err", err)
		}
	}()
}

// load sweeps the backend and publishes a new snapshot. The caller holds loadMu.
func (r *Repository) load(ctx context.Context) (*snapshot, error) {
	start := time.Now()

	candidates, err := r.backend.List(ctx, users.Query{})
	if err != nil {
		return nil, err
	}
	loaded, err := r.loadUsers(ctx, candidates)
	if err != nil {
		return nil, err
	}
	groups, err := r.loadGroups(ctx)
	if err != nil {
		return nil, err
	}

	s := &snapshot{users: loaded, groups: groups, takenAt: time.Now()}
	r.mu.Lock()
	r.snap = s
	r.mu.Unlock()
	r.logger.Info("cache: snapshot loaded", "users", len(loaded), "groups", len(groups), "took", time.Since(start))
	return s, nil
}

// loadUsers resolves the full record of every candidate, concurrently and
// bounded. A candidate that vanished mid-sweep is dropped; any other error fails
// the sweep so a partial directory is never published.
func (r *Repository) loadUsers(ctx context.Context, candidates []users.User) (map[string]users.User, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	out := make(map[string]users.User, len(candidates))
	sem := make(chan struct{}, loadConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(username string) {
			defer wg.Done()
			defer func() { <-sem }()
			u, err := r.backend.Get(ctx, username)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if errors.Is(err, users.ErrNotFound) {
					return
				}
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				return
			}
			out[key(username)] = u
		}(c.Username)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// loadGroups resolves every group's members, concurrently and bounded. Same
// all-or-nothing rule as loadUsers.
func (r *Repository) loadGroups(ctx context.Context) (map[string][]string, error) {
	list, err := r.backend.ListGroups(ctx)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	out := make(map[string][]string, len(list))
	sem := make(chan struct{}, loadConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for _, g := range list {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			members, err := r.backend.GroupMembers(ctx, name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if errors.Is(err, users.ErrNotFound) {
					return
				}
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				return
			}
			out[key(name)] = members
		}(g.Name)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// sync re-reads one user from the backend into the snapshot after a write, so
// the change is visible to the next search instead of waiting for the sweep. A
// failed re-read leaves the entry alone — the next sweep corrects it.
func (r *Repository) sync(ctx context.Context, username string) {
	u, err := r.backend.Get(ctx, username)
	switch {
	case errors.Is(err, users.ErrNotFound):
		r.publish(func(s *snapshot) { delete(s.users, key(username)) })
	case err != nil:
		r.logger.Warn("cache: re-read after write failed, entry stays stale", "username", username, "err", err)
	default:
		r.publish(func(s *snapshot) { s.users[key(username)] = u })
	}
}

// publish applies mutate to a copy of the current snapshot and installs it.
// Snapshots are immutable once published, so the copy is what keeps concurrent
// readers race-free. It is a no-op on a cold cache: the first load will pick the
// change up anyway.
func (r *Repository) publish(mutate func(*snapshot)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.snap == nil {
		return
	}
	next := &snapshot{
		users:   make(map[string]users.User, len(r.snap.users)),
		groups:  r.snap.groups,
		takenAt: r.snap.takenAt,
	}
	for k, v := range r.snap.users {
		next.users[k] = v
	}
	mutate(next)
	r.snap = next
}

func key(name string) string { return strings.ToLower(name) }
