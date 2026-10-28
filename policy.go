package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Rule is one path declaration from an ACL policy. Rules with the same Key
// grant the same permissions; Body is the declaration's text for display.
type Rule struct {
	Path, Key, Body string
}

// parseRules splits an HCL or JSON ACL policy into its path declarations.
// Policies with anything else (or syntax it does not recognise) return an
// error so callers can show the full text rather than misrepresent it.
func parseRules(source string) ([]Rule, error) {
	var doc any
	if json.Unmarshal([]byte(source), &doc) == nil {
		return jsonRules(doc)
	}

	toks, err := tokenize(source)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for i := 0; i < len(toks); {
		if i+2 >= len(toks) || toks[i].val != "path" || toks[i+2].val != "{" {
			return nil, errors.New("policy contains non-path or unfamiliar declarations")
		}
		path := toks[i+1].val
		if strings.HasPrefix(path, `"`) {
			if err := json.Unmarshal([]byte(path), &path); err != nil {
				return nil, fmt.Errorf("path label %s: %w", toks[i+1].val, err)
			}
		}
		open, depth, end := i+2, 1, i+3
		for ; end < len(toks); end++ {
			switch toks[end].val {
			case "{":
				depth++
			case "}":
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if depth != 0 {
			return nil, errors.New("unbalanced path block")
		}
		vals := make([]string, 0, end-open)
		for _, t := range toks[open+1 : end] {
			vals = append(vals, t.val)
		}
		body := dedent(strings.Trim(source[toks[open].end:toks[end].start], "\n"))
		rules = append(rules, Rule{Path: path, Key: "hcl\x00" + strings.Join(vals, "\x00"), Body: strings.TrimSpace(body)})
		i = end + 1
	}
	return rules, nil
}

func jsonRules(doc any) ([]Rule, error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, errors.New("JSON policy is not an object")
	}
	for k := range m {
		if k != "path" {
			return nil, errors.New("JSON policy contains non-path declarations")
		}
	}
	paths, ok := m["path"].(map[string]any)
	if !ok && m["path"] != nil {
		return nil, errors.New("unrecognized JSON path block")
	}
	var rules []Rule
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		bodies, ok := paths[path].([]any)
		if !ok {
			bodies = []any{paths[path]}
		}
		for _, body := range bodies {
			if _, ok := body.(map[string]any); !ok {
				return nil, errors.New("unrecognized JSON path body")
			}
			key, _ := marshalJSON(body, "")
			rendered, _ := marshalJSON(body, "  ")
			rules = append(rules, Rule{Path: path, Key: "json\x00" + key, Body: rendered})
		}
	}
	return rules, nil
}

// marshalJSON renders v with sorted keys and without HTML escaping.
func marshalJSON(v any, indent string) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	err := enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n"), err
}

type token struct {
	val        string
	start, end int
}

var (
	heredocStart = regexp.MustCompile(`^<<(-?)([A-Za-z_][A-Za-z_0-9]*)[ \t]*\r?\n`)
	ident        = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9-]*`)
)

// tokenize splits HCL into significant tokens (strings, identifiers,
// heredocs and single punctuation characters), dropping whitespace and
// comments so that formatting differences do not change a rule's identity.
func tokenize(src string) ([]token, error) {
	var toks []token
	for i := 0; i < len(src); {
		rest := src[i:]
		r, size := utf8.DecodeRuneInString(rest)
		n := 0
		switch {
		case strings.HasPrefix(rest, "<<"):
			m := heredocStart.FindStringSubmatch(rest)
			if m == nil {
				return nil, errors.New("unrecognized heredoc")
			}
			indent := ""
			if m[1] != "" {
				indent = `[ \t]*`
			}
			end := regexp.MustCompile(`(?m)^` + indent + regexp.QuoteMeta(m[2]) + `[ \t]*\r?$`).FindStringIndex(rest[len(m[0]):])
			if end == nil {
				return nil, errors.New("unterminated heredoc")
			}
			n = len(m[0]) + end[1]
			toks = append(toks, token{rest[:n], i, i + n})
		case unicode.IsSpace(r):
			n = len(rest) - len(strings.TrimLeftFunc(rest, unicode.IsSpace))
		case strings.HasPrefix(rest, "//") || r == '#':
			n = strings.IndexByte(rest, '\n')
			if n < 0 {
				n = len(rest)
			}
		case strings.HasPrefix(rest, "/*"):
			end := strings.Index(rest[2:], "*/")
			if end < 0 {
				return nil, errors.New("unterminated comment")
			}
			n = end + 4
		case r == '"':
			for n = 1; n < len(rest) && rest[n] != '"'; n++ {
				if rest[n] == '\\' {
					n++
				}
			}
			if n >= len(rest) {
				return nil, errors.New("unterminated string")
			}
			n++
			toks = append(toks, token{rest[:n], i, i + n})
		default:
			n = len(ident.FindString(rest))
			if n == 0 {
				n = size
			}
			toks = append(toks, token{rest[:n], i, i + n})
		}
		i += n
	}
	return toks, nil
}

// dedent removes the whitespace prefix common to all non-blank lines.
func dedent(s string) string {
	lines := strings.Split(s, "\n")
	prefix, first := "", true
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		ws := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
		if first {
			prefix, first = ws, false
			continue
		}
		for !strings.HasPrefix(ws, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			lines[i] = ""
		} else {
			lines[i] = strings.TrimPrefix(l, prefix)
		}
	}
	return strings.Join(lines, "\n")
}
