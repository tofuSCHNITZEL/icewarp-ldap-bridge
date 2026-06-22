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
	username, ok := s.schema.usernameFromDN(m.UserName)
	if !ok {
		return
	}
	if err := s.repo.Authenticate(context.Background(), username, string(m.Password)); err != nil {
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
	if !s.isAuthed(r.ConnectionID()) {
		resp.SetResultCode(gldap.ResultInsufficientAccessRights)
		return
	}

	list, err := s.repo.List(context.Background(), queryFromFilter(m.Filter))
	if err != nil {
		resp.SetResultCode(resultCode(err))
		return
	}

	base := normalizeDN(m.BaseDN)
	for _, u := range list {
		attrs := s.schema.attrs(u)
		dn := s.schema.userDN(u.Username)
		if !inScope(normalizeDN(dn), base, int64(m.Scope)) || !matchFilter(m.Filter, attrs) {
			continue
		}
		_ = w.Write(r.NewSearchResponseEntry(dn, gldap.WithAttributes(attrs)))
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
			if c.Operation != gldap.DeleteAttribute {
				newPassword = &val
			}
		case "cn":
			u.Fileas, profileChanged = val, true
		case "givenname":
			u.Firstname, profileChanged = val, true
		case "sn":
			u.Lastname, profileChanged = val, true
		case "initials":
			u.Middlename, profileChanged = val, true
		case "displayname":
			u.Nickname, profileChanged = val, true
		case "generationqualifier":
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
