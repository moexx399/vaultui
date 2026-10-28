package main

import (
	"slices"
	"strings"
	"testing"
)

func TestParseRulesHCL(t *testing.T) {
	rules, err := parseRules(`
# header comment
path "secret/*" {
    capabilities = ["read"] // trailing
    /* block */
}
path "sys/policy" { capabilities = ["deny"] }
path "kv/{{identity.entity.id}}/*" {
  capabilities = ["create"]
  allowed_parameters = {
    "note" = []
  }
}`)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range rules {
		paths = append(paths, r.Path)
	}
	if !slices.Equal(paths, []string{"secret/*", "sys/policy", "kv/{{identity.entity.id}}/*"}) {
		t.Fatalf("paths %v", paths)
	}
	if rules[0].Body != "capabilities = [\"read\"] // trailing\n/* block */" {
		t.Fatalf("body %q", rules[0].Body)
	}
	if !strings.Contains(rules[2].Body, "allowed_parameters") {
		t.Fatalf("nested block lost: %q", rules[2].Body)
	}

	// Formatting and comments do not change a rule's identity.
	same, err := parseRules(`path "x" {capabilities=["read"]}`)
	if err != nil || same[0].Key != rules[0].Key {
		t.Fatalf("keys differ: %q vs %q (%v)", same[0].Key, rules[0].Key, err)
	}
}

func TestParseRulesJSON(t *testing.T) {
	rules, err := parseRules(`{"path": {"b": {"capabilities": ["read"]}, "a": [{"capabilities": ["list"]}, {"capabilities": ["read"]}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0].Path != "a" || rules[2].Path != "b" || rules[1].Key != rules[2].Key {
		t.Fatalf("rules %+v", rules)
	}
}

func TestParseRulesRejectsUnfamiliar(t *testing.T) {
	for _, src := range []string{
		`name = "x"`,
		`path "a" { capabilities = ["read"]`,
		`path "a" { x = "unterminated }`,
		`{"path": {}, "other": 1}`,
		`path "a" { policy = <<EOF`,
	} {
		if _, err := parseRules(src); err == nil {
			t.Errorf("parseRules(%q) succeeded", src)
		}
	}
	rules, err := parseRules("path \"a\" {\n  x = <<-EOT\n  }\n  EOT\n}")
	if err != nil || len(rules) != 1 {
		t.Fatalf("heredoc: %v %v", rules, err)
	}
}

func TestReportMergesIdenticalRules(t *testing.T) {
	r := &Report{
		Context: "dev", Address: "http://v",
		Entities: []Entity{{ID: "e1", Name: "jane", Groups: []Group{
			{ID: "g1", Name: "a", Policies: []string{"p1", "p2"}, Membership: "direct"},
			{ID: "g2", Name: "b", Policies: []string{"p2", "raw"}, Membership: "inherited"},
		}}},
		Policies: map[string]string{
			"p1":  `path "x" { capabilities = ["read"] }`,
			"p2":  "path \"x\" {\n  capabilities = [\"read\"]\n}\npath \"y\" { capabilities = [\"read\"] }",
			"raw": `name = "nope"`,
		},
		PolicyErrors: map[string]string{},
	}
	text := r.Text()
	for _, s := range []string{
		"3 path declarations -> 2 distinct rules across 1 permission sets.",
		"  x  [P1, P2]",
		"  y  [P2]",
		"UNCONSOLIDATED POLICY [P3] raw",
		"    Groups: a, b",
	} {
		if !strings.Contains(text, s) {
			t.Errorf("missing %q in:\n%s", s, text)
		}
	}
	paths := r.Paths()
	if len(paths) != 2 || strings.Contains(paths[0].Detail, "RULE 2") || !strings.Contains(paths[0].Detail, "p2: a, b") {
		t.Fatalf("paths %+v", paths)
	}
	if r.unparsable() != 1 {
		t.Fatalf("unparsable = %d", r.unparsable())
	}
}
