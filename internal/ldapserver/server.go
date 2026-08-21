// Package ldapserver adapts the gldap protocol server onto a users.Repository.
// It owns all LDAP concerns — DNs, object classes, filters, scopes, the Root
// DSE — translating requests into repository calls and users into LDAP entries
// via Schema.
package ldapserver

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"github.com/jimlambrt/gldap"
	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
)

// rootDSE is the capability advertisement returned for a Root DSE query. It
// lists the controls the server honors — notably paged results, which Keycloak
// probes for before deciding whether to page.
var rootDSE = map[string][]string{
	"objectClass":          {"top"},
	"supportedLDAPVersion": {"3"},
	"supportedControl":     {gldap.ControlTypePaging},
	"vendorName":           {"IceWarp LDAP Bridge"},
}

// Server is a gldap-based LDAP server backed by a users.Repository.
type Server struct {
	repo   users.Repository
	schema Schema
	logger *slog.Logger
	server *gldap.Server

	mu     sync.Mutex
	authed map[int]struct{} // connection IDs that completed a successful bind
}

// New builds a Server presenting repo under schema. logger receives one debug
// line per incoming request (nil disables logging). Extra gldap options
// (logging, TLS, timeouts) are forwarded to the underlying gldap.Server.
func New(repo users.Repository, schema Schema, logger *slog.Logger, opts ...gldap.Option) (*Server, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{repo: repo, schema: schema, logger: logger, authed: make(map[int]struct{})}

	allOpts := append([]gldap.Option{gldap.WithOnClose(s.removeAuthed)}, opts...)
	gs, err := gldap.NewServer(allOpts...)
	if err != nil {
		return nil, err
	}

	mux, err := gldap.NewMux()
	if err != nil {
		return nil, err
	}
	if err := errors.Join(
		mux.Bind(s.bind),
		mux.Search(s.search),
		mux.Add(s.add),
		mux.Modify(s.modify),
		mux.Delete(s.delete),
	); err != nil {
		return nil, err
	}
	if err := gs.Router(mux); err != nil {
		return nil, err
	}

	s.server = gs
	return s, nil
}

// Run starts listening on addr (e.g. ":3389") and blocks until Stop is called.
func (s *Server) Run(addr string) error { return s.server.Run(addr) }

// Stop shuts the server down.
func (s *Server) Stop() error { return s.server.Stop() }

// Ready reports whether the server is accepting connections.
func (s *Server) Ready() bool { return s.server.Ready() }

// --- connection auth state ---

func (s *Server) markAuthed(connID int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authed[connID] = struct{}{}
}

func (s *Server) removeAuthed(connID int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authed, connID)
}

func (s *Server) isAuthed(connID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.authed[connID]
	return ok
}

// --- handlers ---

func (s *Server) bind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		s.logger.Debug("ldap bind: malformed request", "conn", r.ConnectionID(), "err", err)
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.logger.Debug("ldap bind", "dn", m.UserName, "conn", r.ConnectionID())
	// An empty DN and password is an anonymous bind (RFC 4513 §5.1.2). It
	// establishes no authenticated identity, so leave the connection unauthed.
	if m.UserName == "" && len(m.Password) == 0 {
		resp.SetResultCode(gldap.ResultSuccess)
		return
	}
	// An empty password is an unauthenticated bind (RFC 4513 §5.1.2): it must
	// never authenticate, so reject it here rather than relying on the backend.
	if len(m.Password) == 0 {
		return
	}
	username, ok := s.schema.usernameFromDN(m.UserName)
	if !ok {
		return
	}
	if err := s.repo.Authenticate(context.Background(), username, string(m.Password)); err != nil {
		// Only a genuine credential rejection is InvalidCredentials (the default).
		// A backend outage must NOT look like a wrong password, or Keycloak counts
		// it as a failed login and can brute-force-lock the account; report the
		// service as unavailable instead.
		if !errors.Is(err, users.ErrInvalidCredentials) {
			s.logger.Warn("ldap bind: backend unavailable", "dn", m.UserName, "err", err)
			resp.SetResultCode(gldap.ResultUnavailable)
		}
		return
	}
	s.markAuthed(r.ConnectionID())
	resp.SetResultCode(gldap.ResultSuccess)
}

func (s *Server) search(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetSearchMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.logger.Debug("ldap search", "base_dn", m.BaseDN, "scope", int64(m.Scope), "filter", m.Filter, "conn", r.ConnectionID())

	// Root DSE (empty base, base scope) is public capability info.
	if m.BaseDN == "" && int64(m.Scope) == scopeBaseObject {
		_ = w.Write(r.NewSearchResponseEntry("", gldap.WithAttributes(rootDSE)))
		resp.SetResultCode(gldap.ResultSuccess)
		return
	}
	if !s.schema.AllowAnonymousReads && !s.isAuthed(r.ConnectionID()) {
		resp.SetResultCode(gldap.ResultInsufficientAccessRights)
		return
	}

	base := normalizeDN(m.BaseDN)
	scope := int64(m.Scope)

	s.searchContainers(w, r, m, base, scope)

	// The bridge serves entries under two containers: users (BaseUserDN) and,
	// when enabled, groups (GroupBaseDN). Only run the flow for a container the
	// search can actually reach, so a user-only search never enumerates groups
	// (and their members) and vice versa.
	if subtreeInRange(normalizeDN(s.schema.BaseUserDN), base, scope) {
		if err := s.searchUsers(w, r, m, base, scope); err != nil {
			resp.SetResultCode(resultCode(err))
			return
		}
	}
	if s.schema.GroupBaseDN != "" && subtreeInRange(normalizeDN(s.schema.GroupBaseDN), base, scope) {
		if err := s.searchGroups(w, r, m, base, scope); err != nil {
			resp.SetResultCode(resultCode(err))
			return
		}
	}

	// We return everything in one response, so when the client used the paged
	// results control we acknowledge it with an empty cookie (= last page).
	// Clients (e.g. Keycloak) warn if the control is missing from the response.
	if requestedPaging(m.Controls) {
		if pc, err := gldap.NewControlPaging(0); err == nil {
			resp.SetControls(pc)
		}
	}
	resp.SetResultCode(gldap.ResultSuccess)
}

// searchContainers emits synthetic organizationalUnit entries standing in for
// the configured containers (BaseUserDN, GroupBaseDN) themselves, so a client
// can browse down into them from their parent DN — or from an empty base DN,
// treated the same way — the way native LDAP containers work. There is no
// backing data for these entries; List/ListGroups still only serve the real
// user/group entries beneath them.
func (s *Server) searchContainers(w *gldap.ResponseWriter, r *gldap.Request, m *gldap.SearchMessage, base string, scope int64) {
	containers := []string{s.schema.BaseUserDN}
	if s.schema.GroupBaseDN != "" {
		containers = append(containers, s.schema.GroupBaseDN)
	}
	for _, c := range containers {
		switch {
		case scope == scopeBaseObject && base == normalizeDN(c):
			// A base-scoped lookup of the container's own DN.
		case scope != scopeBaseObject && (base == "" || base == normalizeDN(parentDN(c))):
			// A one-level/subtree search browsing from the container's parent
			// (or the empty DN, treated as "somewhere above every container").
		default:
			continue
		}
		attrs := containerAttrs(c)
		if !matchFilter(m.Filter, attrs) {
			continue
		}
		_ = w.Write(r.NewSearchResponseEntry(c, gldap.WithAttributes(attrs)))
	}
}

// parentDN returns dn's parent (everything after its leading RDN), or "" if dn
// has none.
func parentDN(dn string) string {
	_, rest, ok := strings.Cut(dn, ",")
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}

// containerAttrs builds the attributes for a synthetic container entry (see
// searchContainers) from its own DN: a generic organizationalUnit named by the
// DN's leading RDN attribute (typically "ou", but whatever the config uses).
func containerAttrs(dn string) map[string][]string {
	attrs := map[string][]string{"objectclass": {"top", "organizationalUnit"}}
	rdn, _, _ := strings.Cut(dn, ",")
	attr, val, ok := strings.Cut(rdn, "=")
	if ok && attr != "" && val != "" {
		attrs[strings.ToLower(strings.TrimSpace(attr))] = []string{strings.TrimSpace(val)}
	}
	return attrs
}

// Deferred attributes are the membership links the bridge resolves only during
// per-entry enrichment (a separate backend read), so they're absent from the
// cheap List/ListGroups attrs the prefilter sees. mayMatch must not exclude an
// entry on them, or a membership search — Keycloak browsing a group's members
// (memberOf on users) or a user's groups (member on groups) — would wrongly come
// back empty. The exact matchFilter still applies them after enrichment.
var (
	userDeferredAttrs  = map[string]bool{"memberof": true}
	groupDeferredAttrs = map[string]bool{"member": true}
)

// searchUsers emits the user entries matching the search.
func (s *Server) searchUsers(w *gldap.ResponseWriter, r *gldap.Request, m *gldap.SearchMessage, base string, scope int64) error {
	list, err := s.userCandidates(context.Background(), m.Filter)
	if err != nil {
		return err
	}

	// Prefilter on the cheap identity attributes (uid, mail, objectClass,
	// entryUUID) so we only enrich entries we might return. List omits the
	// structured name — it lives behind a per-user backend read — so a filter on
	// a name-only attribute (sn, givenName, …) won't match here; Keycloak filters
	// only on identity attributes, so that's not a limitation in practice. memberOf
	// is likewise resolved during enrichment, so mayMatch defers it (see
	// userDeferredAttrs) instead of excluding users that lack it at this stage.
	var candidates []users.User
	for _, u := range list {
		if inScope(normalizeDN(s.schema.userDN(u.Username)), base, scope) &&
			mayMatch(m.Filter, s.schema.attrs(u), userDeferredAttrs) {
			candidates = append(candidates, u)
		}
	}

	// Enrich the survivors (names) and emit those that still match once their
	// full attributes are known. A backend error fails the whole search rather
	// than emitting a partial set — a missing entry would otherwise read to
	// Keycloak as "user deleted" and get the account removed/disabled.
	enriched, err := s.enrich(context.Background(), candidates)
	if err != nil {
		return err
	}
	for _, u := range enriched {
		attrs := s.schema.attrs(u)
		if !matchFilter(m.Filter, attrs) {
			continue
		}
		_ = w.Write(r.NewSearchResponseEntry(s.schema.userDN(u.Username), gldap.WithAttributes(attrs)))
	}
	return nil
}

// userCandidates returns the lightweight candidate users a search will prefilter
// and enrich. A "(memberOf=<groupDN>)" filter — Keycloak listing a group's
// members under GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE — is pushed down to the
// group's own member list, one backend call, instead of enumerating every user
// just to read each one's memberOf. An unknown group yields no candidates; any
// other filter falls back to the username-hinted List. Candidates carry only the
// username; enrich loads the rest (and the exact filter runs after).
func (s *Server) userCandidates(ctx context.Context, filter string) ([]users.User, error) {
	if group, ok := s.schema.groupFromMemberOfFilter(filter); ok {
		members, err := s.repo.GroupMembers(ctx, group)
		if err != nil {
			if errors.Is(err, users.ErrNotFound) {
				return nil, nil
			}
			return nil, err
		}
		out := make([]users.User, len(members))
		for i, name := range members {
			out[i] = users.User{Username: name}
		}
		return out, nil
	}
	return s.repo.List(ctx, s.schema.queryFromFilter(filter))
}

// searchGroups emits the group entries matching the search. Like the user flow
// it prefilters on cheap attributes (cn, objectClass, entryUUID), then resolves
// members only for the survivors. A base-scoped lookup of a single group DN
// skips the enumeration entirely.
func (s *Server) searchGroups(w *gldap.ResponseWriter, r *gldap.Request, m *gldap.SearchMessage, base string, scope int64) error {
	var candidates []users.Group
	if name, ok := s.schema.groupNameFromDN(base); ok && scope == scopeBaseObject {
		candidates = []users.Group{{Name: name}}
	} else {
		groups, err := s.repo.ListGroups(context.Background())
		if err != nil {
			return err
		}
		for _, g := range groups {
			if inScope(normalizeDN(s.schema.groupDN(g.Name)), base, scope) &&
				mayMatch(m.Filter, s.schema.groupAttrs(g), groupDeferredAttrs) {
				candidates = append(candidates, g)
			}
		}
	}

	enriched, err := s.enrichGroups(context.Background(), candidates)
	if err != nil {
		return err
	}
	for _, g := range enriched {
		attrs := s.schema.groupAttrs(g)
		if !matchFilter(m.Filter, attrs) {
			continue
		}
		_ = w.Write(r.NewSearchResponseEntry(s.schema.groupDN(g.Name), gldap.WithAttributes(attrs)))
	}
	return nil
}

// subtreeInRange reports whether entries living directly under containerDN could
// be in scope of a search at (base, scope). It gates the (potentially expensive)
// per-container flow; per-entry inScope still filters precisely. Both DNs must be
// normalized.
func subtreeInRange(container, base string, scope int64) bool {
	switch scope {
	case scopeBaseObject: // base names a single entry directly under container
		return strings.HasSuffix(base, ","+container)
	case scopeSingleLevel: // entries are the direct children of base
		return base == container
	case scopeWholeSubtree:
		return base == container ||
			strings.HasSuffix(container, ","+base) || // container is below base
			strings.HasSuffix(base, ","+container) // base is at/below container
	}
	return false
}

// enrichConcurrency bounds how many per-user backend reads run at once in enrich.
const enrichConcurrency = 8

// enrich loads the full record (structured name, etc.) for each candidate via
// repo.Get, concurrently and bounded. A candidate that no longer exists
// (ErrNotFound) is dropped silently — it was genuinely deleted. Any other read
// error (a backend outage) returns an error so the caller fails the search
// instead of emitting a partial set: a silently-missing entry reads to Keycloak
// as a deleted user and gets the account removed/disabled. Order is not
// preserved (LDAP search results are unordered).
func (s *Server) enrich(ctx context.Context, candidates []users.User) ([]users.User, error) {
	sem := make(chan struct{}, enrichConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	out := make([]users.User, 0, len(candidates))
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(username string) {
			defer wg.Done()
			defer func() { <-sem }()
			u, err := s.repo.Get(ctx, username)
			if err != nil {
				if errors.Is(err, users.ErrNotFound) {
					return
				}
				s.logger.Warn("ldap search: enrich failed", "username", username, "err", err)
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			out = append(out, u)
			mu.Unlock()
		}(c.Username)
	}
	wg.Wait()
	return out, firstErr
}

// enrichGroups resolves each candidate group's members via repo.GroupMembers,
// concurrently and bounded. A group that no longer exists (ErrNotFound) is
// dropped silently; any other read error (a backend outage) returns an error so
// the caller fails the search rather than emitting a partial set. Order is not
// preserved.
func (s *Server) enrichGroups(ctx context.Context, candidates []users.Group) ([]users.Group, error) {
	sem := make(chan struct{}, enrichConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	out := make([]users.Group, 0, len(candidates))
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			members, err := s.repo.GroupMembers(ctx, name)
			if err != nil {
				if errors.Is(err, users.ErrNotFound) {
					return
				}
				s.logger.Warn("ldap search: group enrich failed", "group", name, "err", err)
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			out = append(out, users.Group{Name: name, Members: members})
			mu.Unlock()
		}(c.Name)
	}
	wg.Wait()
	return out, firstErr
}

func requestedPaging(controls []gldap.Control) bool {
	for _, c := range controls {
		if c != nil && c.GetControlType() == gldap.ControlTypePaging {
			return true
		}
	}
	return false
}

func (s *Server) add(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationAddResponse),
		gldap.WithResponseCode(gldap.ResultInsufficientAccessRights),
	)
	defer func() { _ = w.Write(resp) }()

	if !s.isAuthed(r.ConnectionID()) {
		return
	}
	m, err := r.GetAddMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.logger.Debug("ldap add", "dn", m.DN, "conn", r.ConnectionID())
	username, ok := s.schema.usernameFromDN(m.DN)
	if !ok {
		resp.SetResultCode(gldap.ResultUnwillingToPerform)
		return
	}

	attrs := make(map[string][]string, len(m.Attributes))
	for _, a := range m.Attributes {
		attrs[a.Type] = a.Vals
	}
	if err := s.repo.Create(context.Background(), userFromAttrs(username, attrs)); err != nil {
		resp.SetResultCode(resultCode(err))
		return
	}
	resp.SetResultCode(gldap.ResultSuccess)
}

func (s *Server) modify(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInsufficientAccessRights))
	defer func() { _ = w.Write(resp) }()

	if !s.isAuthed(r.ConnectionID()) {
		return
	}
	m, err := r.GetModifyMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.logger.Debug("ldap modify", "dn", m.DN, "attrs", changeTypes(m.Changes), "conn", r.ConnectionID())
	username, ok := s.schema.usernameFromDN(m.DN)
	if !ok {
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}

	ctx := context.Background()
	u, err := s.repo.Get(ctx, username)
	if err != nil {
		resp.SetResultCode(resultCode(err))
		return
	}

	// Apply the changes to the user, splitting out the password (a separate op).
	var newPassword *string
	profileChanged := false
	for _, c := range m.Changes {
		val := first(unwrapVals(c.Modification.Vals))
		switch strings.ToLower(c.Modification.Type) {
		case "userpassword":
			// Only a replace/add with a non-empty value sets a password. An empty
			// value is skipped, not written: the bridge can't represent "no
			// password" and a blank password must not slip through to IceWarp.
			if c.Operation != gldap.DeleteAttribute && val != "" {
				newPassword = &val
			}
		case "cn":
			u.Fileas, profileChanged = val, true
		case "givenname":
			u.Firstname, profileChanged = val, true
		case "sn":
			u.Lastname, profileChanged = val, true
		case "middlename":
			u.Middlename, profileChanged = val, true
		case "nickname":
			u.Nickname, profileChanged = val, true
		case "suffix":
			u.Suffix, profileChanged = val, true
		case "personaltitle":
			u.Title, profileChanged = val, true
		case "mail":
			// Changing the IceWarp primary address is an account rename: it
			// changes the uid/DN and the entryUUID, breaking Keycloak's
			// federation link, and gldap has no ModifyDN route. The bridge
			// can't honor it, so reject an actual change rather than silently
			// reporting success. A no-op resend (same value) is ignored so it
			// doesn't block other edits Keycloak bundles in.
			if c.Operation != gldap.DeleteAttribute && val != u.Email {
				s.logger.Warn("rejecting mail change (account rename unsupported)", "dn", m.DN, "from", u.Email, "to", val)
				resp.SetResultCode(gldap.ResultUnwillingToPerform)
				return
			}
		}
	}

	if profileChanged {
		if err := s.repo.Update(ctx, u); err != nil {
			resp.SetResultCode(resultCode(err))
			return
		}
	}
	if newPassword != nil {
		if err := s.repo.SetPassword(ctx, username, *newPassword); err != nil {
			resp.SetResultCode(resultCode(err))
			return
		}
	}
	resp.SetResultCode(gldap.ResultSuccess)
}

func (s *Server) delete(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationDelResponse),
		gldap.WithResponseCode(gldap.ResultInsufficientAccessRights),
	)
	defer func() { _ = w.Write(resp) }()

	if !s.isAuthed(r.ConnectionID()) {
		return
	}
	m, err := r.GetDeleteMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.logger.Debug("ldap delete", "dn", m.DN, "conn", r.ConnectionID())
	username, ok := s.schema.usernameFromDN(m.DN)
	if !ok {
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}
	if err := s.repo.Delete(context.Background(), username); err != nil {
		resp.SetResultCode(resultCode(err))
		return
	}
	resp.SetResultCode(gldap.ResultSuccess)
}

// --- mapping helpers ---

// changeTypes lists the attribute names touched by a modify, for debug logs.
func changeTypes(changes []gldap.Change) []string {
	out := make([]string, len(changes))
	for i, c := range changes {
		out[i] = c.Modification.Type
	}
	return out
}

func resultCode(err error) int {
	switch {
	case errors.Is(err, users.ErrInvalidCredentials):
		return gldap.ResultInvalidCredentials
	case errors.Is(err, users.ErrNotFound):
		return gldap.ResultNoSuchObject
	case errors.Is(err, users.ErrAlreadyExists):
		return gldap.ResultEntryAlreadyExists
	default:
		return gldap.ResultOperationsError
	}
}

// unwrapVals works around a gldap v0.1.14 bug: ModifyMessage values arrive still
// wrapped in their BER octet-string TLV rather than decoded.
func unwrapVals(vals []string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = unwrapBERString(v)
	}
	return out
}

func unwrapBERString(v string) string {
	b := []byte(v)
	if len(b) < 2 || b[0] != 0x04 { // 0x04 == ASN.1 OCTET STRING tag
		return v
	}
	length := int(b[1])
	rest := b[2:]
	if length&0x80 != 0 { // long-form length: low 7 bits = number of length bytes
		n := length & 0x7f
		if n == 0 || n > len(rest) {
			return v
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(rest[i])
		}
		rest = rest[n:]
	}
	if length != len(rest) {
		return v
	}
	return string(rest)
}
