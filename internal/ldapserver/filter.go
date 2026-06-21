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

// matchFilter implements the subset of RFC 4515 Keycloak needs: the boolean
// operators (&...) (|...) (!...) over leaf assertions that are equality
// "(attr=value)", presence "(attr=*)" or substring "(attr=a*b*)". Matching is
// case-insensitive; attribute lookups expect lower-cased keys. An empty filter
// matches everything; an unparseable one matches nothing.
func matchFilter(filter string, attrs map[string][]string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	pred, rest, err := parseFilter(filter)
	if err != nil || strings.TrimSpace(rest) != "" {
		return false
	}
	return pred(attrs)
}

type predicate func(map[string][]string) bool

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

func combine(op byte, preds []predicate) (predicate, error) {
	switch op {
	case '&':
		return func(a map[string][]string) bool {
			for _, p := range preds {
				if !p(a) {
					return false
				}
			}
			return true
		}, nil
	case '|':
		return func(a map[string][]string) bool {
			for _, p := range preds {
				if p(a) {
					return true
				}
			}
			return false
		}, nil
	default: // '!'
		if len(preds) != 1 {
			return nil, errors.New("filter: '!' takes exactly one filter")
		}
		p := preds[0]
		return func(a map[string][]string) bool { return !p(a) }, nil
	}
}

func leafPredicate(leaf string) predicate {
	attr, val, ok := strings.Cut(leaf, "=")
	if !ok {
		return func(map[string][]string) bool { return false }
	}
	attr = strings.ToLower(strings.TrimSpace(attr))
	val = strings.TrimSpace(val)

	return func(a map[string][]string) bool {
		vals, present := a[attr]
		if !present {
			return false
		}
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
