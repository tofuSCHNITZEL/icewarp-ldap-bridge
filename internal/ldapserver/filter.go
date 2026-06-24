package ldapserver

import (
	"errors"
	"strings"
)

// LDAP search scopes (RFC 4511), matching the gldap/wire values.
const (
	scopeBaseObject   = 0
	scopeSingleLevel  = 1
	scopeWholeSubtree = 2
)

// normalizeDN lower-cases a DN and trims whitespace around its RDN components,
// so "uid=Bob, dc=Example" and "uid=bob,dc=example" compare equal.
func normalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return strings.ToLower(strings.Join(parts, ","))
}

// inScope reports whether entryDN falls within baseDN for the given scope. Both
// DNs must be normalized.
func inScope(entryDN, baseDN string, scope int64) bool {
	switch scope {
	case scopeBaseObject:
		return entryDN == baseDN
	case scopeSingleLevel:
		idx := strings.Index(entryDN, ",")
		return idx >= 0 && entryDN[idx+1:] == baseDN
	case scopeWholeSubtree:
		return entryDN == baseDN || strings.HasSuffix(entryDN, ","+baseDN)
	}
	return false
}

// triState is a three-valued filter outcome. It exists for the prefilter: an
// assertion on an attribute the bridge only populates during per-entry
// enrichment can't be judged from the cheap attributes, so it evaluates to
// triUnknown rather than a false "no match".
type triState int8

const (
	triFalse triState = iota
	triTrue
	triUnknown
)

// matchFilter implements the subset of RFC 4515 Keycloak needs: the boolean
// operators (&...) (|...) (!...) over leaf assertions that are equality
// "(attr=value)", presence "(attr=*)" or substring "(attr=a*b*)". Matching is
// case-insensitive; attribute lookups expect lower-cased keys. An empty filter
// matches everything; an unparseable one matches nothing. This is the exact
// matcher: every attribute is judged from attrs (a missing one fails its leaf).
func matchFilter(filter string, attrs map[string][]string) bool {
	return evalFilter(filter, attrs, nil) == triTrue
}

// mayMatch is the prefilter counterpart of matchFilter: it reports whether attrs
// could match filter once the deferred attributes — those the bridge populates
// only during the expensive per-entry enrichment (memberOf on users, member on
// groups) — become known. A leaf on a deferred attribute that is absent from the
// cheap attrs is treated as indeterminate and never excludes the entry; the
// exact matchFilter runs again after enrichment. Keeping a non-match here only
// costs an extra enrichment; dropping a real match would hide group memberships.
func mayMatch(filter string, attrs map[string][]string, deferred map[string]bool) bool {
	return evalFilter(filter, attrs, deferred) != triFalse
}

func evalFilter(filter string, attrs map[string][]string, deferred map[string]bool) triState {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return triTrue
	}
	pred, rest, err := parseFilter(filter)
	if err != nil || strings.TrimSpace(rest) != "" {
		return triFalse
	}
	return pred(attrs, deferred)
}

type predicate func(attrs map[string][]string, deferred map[string]bool) triState

func parseFilter(s string) (predicate, string, error) {
	if len(s) == 0 || s[0] != '(' {
		return nil, s, errors.New("filter: expected '('")
	}
	s = s[1:]
	if len(s) == 0 {
		return nil, s, errors.New("filter: unexpected end")
	}

	switch s[0] {
	case '&', '|', '!':
		op := s[0]
		s = s[1:]
		var preds []predicate
		for len(s) > 0 && s[0] == '(' {
			var p predicate
			var err error
			p, s, err = parseFilter(s)
			if err != nil {
				return nil, s, err
			}
			preds = append(preds, p)
		}
		if len(s) == 0 || s[0] != ')' {
			return nil, s, errors.New("filter: expected ')'")
		}
		s = s[1:] // consume ')'
		pred, err := combine(op, preds)
		return pred, s, err // propagate the remaining input, not ""

	default:
		end := strings.IndexByte(s, ')')
		if end < 0 {
			return nil, s, errors.New("filter: unterminated assertion")
		}
		return leafPredicate(s[:end]), s[end+1:], nil
	}
}

// combine folds child predicates with Kleene three-valued logic: AND is false if
// any child is false else unknown if any is unknown; OR is true if any child is
// true else unknown if any is unknown; NOT swaps true/false and leaves unknown.
// With no deferred attributes (the exact matcher) no child is ever unknown, so
// this reduces to ordinary boolean logic.
func combine(op byte, preds []predicate) (predicate, error) {
	switch op {
	case '&':
		return func(a map[string][]string, d map[string]bool) triState {
			result := triTrue
			for _, p := range preds {
				switch p(a, d) {
				case triFalse:
					return triFalse
				case triUnknown:
					result = triUnknown
				}
			}
			return result
		}, nil
	case '|':
		return func(a map[string][]string, d map[string]bool) triState {
			result := triFalse
			for _, p := range preds {
				switch p(a, d) {
				case triTrue:
					return triTrue
				case triUnknown:
					result = triUnknown
				}
			}
			return result
		}, nil
	default: // '!'
		if len(preds) != 1 {
			return nil, errors.New("filter: '!' takes exactly one filter")
		}
		p := preds[0]
		return func(a map[string][]string, d map[string]bool) triState {
			switch p(a, d) {
			case triTrue:
				return triFalse
			case triFalse:
				return triTrue
			default:
				return triUnknown
			}
		}, nil
	}
}

func leafPredicate(leaf string) predicate {
	attr, val, ok := strings.Cut(leaf, "=")
	if !ok {
		return func(map[string][]string, map[string]bool) triState { return triFalse }
	}
	attr = strings.ToLower(strings.TrimSpace(attr))
	val = strings.TrimSpace(val)

	return func(a map[string][]string, deferred map[string]bool) triState {
		vals, present := a[attr]
		if !present {
			// An attribute the bridge only fills in during enrichment can't be
			// judged from the cheap attrs; defer to the post-enrichment matcher
			// rather than excluding a possible match here.
			if deferred[attr] {
				return triUnknown
			}
			return triFalse
		}
		if leafMatches(val, vals) {
			return triTrue
		}
		return triFalse
	}
}

// leafMatches reports whether any of vals satisfies the assertion value val,
// which is presence ("*"), substring ("a*b*") or case-insensitive equality.
func leafMatches(val string, vals []string) bool {
	if val == "*" {
		return true
	}
	if strings.Contains(val, "*") {
		parts := strings.Split(val, "*")
		for _, v := range vals {
			if substringMatch(parts, v) {
				return true
			}
		}
		return false
	}
	for _, v := range vals {
		if strings.EqualFold(v, val) {
			return true
		}
	}
	return false
}

func substringMatch(parts []string, v string) bool {
	lv := strings.ToLower(v)
	if !strings.HasPrefix(lv, strings.ToLower(parts[0])) {
		return false
	}
	pos := len(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		lp := strings.ToLower(part)
		idx := strings.Index(lv[pos:], lp)
		if idx < 0 {
			return false
		}
		pos += idx + len(lp)
	}
	suffix := strings.ToLower(parts[len(parts)-1])
	return len(lv)-pos >= len(suffix) && strings.HasSuffix(lv, suffix)
}
