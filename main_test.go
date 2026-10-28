package main

import (
	"context"
	"flag"
	"maps"
	"net"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

func TestParseEnv(t *testing.T) {
	got, err := parseEnv("export VAULT_ADDR='https://v';\nexport VAULT_TOKEN='a'\\''b';\nunset VAULT_CACERT;\n")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"VAULT_ADDR": "https://v", "VAULT_TOKEN": "a'b"}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, err := parseEnv("set -gx VAULT_ADDR 'x';"); err == nil {
		t.Fatal("expected error for non-POSIX output")
	}
}

func TestMatchEntities(t *testing.T) {
	keyInfo := map[string]any{
		"e1": map[string]any{"name": "jane", "aliases": []any{map[string]any{"name": "Jane.Doe@Example.com"}}},
		"e2": map[string]any{"name": "WILSSEB"},
		"e3": map[string]any{"name": "other"},
	}
	got := matchEntities(keyInfo, []string{"jane.doe@example.com", " wilsseb ", ""})
	slices.Sort(got)
	if !slices.Equal(got, []string{"e1", "e2"}) {
		t.Fatalf("got %v", got)
	}
	if got := matchEntities(keyInfo, []string{"", ""}); len(got) != 0 {
		t.Fatalf("empty queries matched %v", got)
	}
}

// TestEndToEnd runs against `vault server -dev` with a vaultctx context
// configured for it. It is skipped unless both binaries are on PATH.
func TestEndToEnd(t *testing.T) {
	for _, bin := range []string{"vault", vaultctxBin} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	const root = "root-token"
	srv := exec.Command("vault", "server", "-dev", "-dev-root-token-id="+root, "-dev-listen-address="+addr)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Process.Kill(); srv.Wait() })

	home := t.TempDir()
	t.Setenv("VAULTCTX_HOME", home)
	t.Setenv("VAULTCTX_CONTEXT", "")
	ctx := context.Background()
	if out, err := exec.Command(vaultctxBin, "add", "dev", "--address", "http://"+addr, "--method", "token").CombinedOutput(); err != nil {
		t.Fatalf("vaultctx add: %v: %s", err, out)
	}

	cfg := api.DefaultConfig()
	cfg.Address = "http://" + addr
	admin, _ := api.NewClient(cfg)
	admin.SetToken(root)
	for range 50 {
		if _, err = admin.Sys().HealthWithContext(ctx); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}

	// replication-status needs no login: it reaches every context, and
	// reports ones it cannot reach.
	if out, err := exec.Command(vaultctxBin, "add", "down", "--address", "http://127.0.0.1:1", "--method", "token").CombinedOutput(); err != nil {
		t.Fatalf("vaultctx add: %v: %s", err, out)
	}
	tops, err := collectStatus(ctx, statusOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(tops) != 2 || tops[0].Name != "dev" || tops[1].Name != "down" {
		t.Fatalf("topologies: %+v", tops)
	}
	dev := tops[0].Clusters[0]
	if dev.Err != "" || dev.HealthCode != 200 || dev.Version == "" || len(dev.Modes) != 0 {
		t.Fatalf("dev cluster: %+v", dev)
	}
	if page := renderTopology(tops[0], 100); !strings.Contains(page, "not configured on any queried cluster") || !strings.Contains(page, "Overall: HEALTHY") {
		t.Fatalf("dev page:\n%s", page)
	}
	if tops[1].Clusters[0].Err == "" {
		t.Fatal("down context should be unreachable")
	}

	if _, err := connect(ctx, "dev"); err != errNeedsLogin {
		t.Fatalf("connect before login: got %v, want errNeedsLogin", err)
	}
	login := loginCmd("dev")
	login.Stdin = strings.NewReader(root + "\n") // answers the token prompt
	if out, err := login.CombinedOutput(); err != nil {
		t.Fatalf("vaultctx login: %v: %s", err, out)
	}
	client, err := connect(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}

	write := func(path string, data map[string]any) string {
		s, err := admin.Logical().Write(path, data)
		if err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		if s == nil {
			return ""
		}
		return str(s.Data["id"])
	}
	if err := admin.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{Type: "userpass"}); err != nil {
		t.Fatal(err)
	}
	auths, _ := admin.Sys().ListAuth()
	entity := write("identity/entity", map[string]any{"name": "jane", "policies": []string{"self"}})
	write("identity/entity-alias", map[string]any{"name": "WILSSEB", "canonical_id": entity, "mount_accessor": auths["userpass/"].Accessor})
	if err := admin.Sys().PutPolicy("dev-read", `
# comments and spacing do not change a rule
path "secret/data/dev/*" {
  capabilities = ["read", "list"]
}`); err != nil {
		t.Fatal(err)
	}
	if err := admin.Sys().PutPolicy("eng", `{"path": {"secret/data/dev/*": {"capabilities": ["read", "list"]}, "secret/data/eng": {"capabilities": ["deny"]}}}`); err != nil {
		t.Fatal(err)
	}
	child := write("identity/group", map[string]any{"name": "devs", "policies": []string{"dev-read", "gone"}, "member_entity_ids": []string{entity}})
	write("identity/group", map[string]any{"name": "eng", "policies": []string{"eng"}, "member_group_ids": []string{child}})

	r, err := lookup(ctx, client, "", "wilsseb")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Entities) != 1 || r.Entities[0].Name != "jane" || !slices.Equal(r.Entities[0].Policies, []string{"self"}) {
		t.Fatalf("entities: %+v", r.Entities)
	}
	groups := map[string]string{}
	for _, g := range r.Entities[0].Groups {
		groups[g.Name] = g.Membership + ":" + strings.Join(g.Policies, ",")
	}
	want := map[string]string{"devs": "direct:dev-read,gone", "eng": "inherited:eng"}
	if !maps.Equal(groups, want) {
		t.Fatalf("groups %v, want %v", groups, want)
	}
	if _, ok := r.PolicyErrors["gone"]; !ok || len(r.Policies) != 2 {
		t.Fatalf("policies %v, errors %v", slices.Collect(maps.Keys(r.Policies)), r.PolicyErrors)
	}
	paths := r.Paths()
	if len(paths) != 2 || paths[0].Path != "secret/data/dev/*" || paths[1].Path != "secret/data/eng" {
		t.Fatalf("paths: %+v", paths)
	}
	// The HCL and JSON spellings of the dev rule stay separate: their bodies differ.
	if !strings.Contains(paths[0].Detail, "RULE 2") || !strings.Contains(paths[0].Detail, "eng: eng") {
		t.Fatalf("dev path detail:\n%s", paths[0].Detail)
	}
	text := r.Text()
	for _, s := range []string{"WARNING: INCOMPLETE - 1 policies could not be read", "3 path declarations -> 3 distinct rules across 3 permission sets.", "[P3] gone [UNREADABLE / MISSING]"} {
		if !strings.Contains(text, s) {
			t.Errorf("report missing %q:\n%s", s, text)
		}
	}
}

func TestRunArgs(t *testing.T) {
	var out strings.Builder
	if err := run([]string{"-h"}, &out); err != flag.ErrHelp || !strings.Contains(out.String(), "user-policies") {
		t.Fatalf("help: %v\n%s", err, out.String())
	}
	if err := run([]string{"nope"}, &out); err == nil || !strings.Contains(err.Error(), `unknown function "nope"`) {
		t.Fatalf("unknown function: %v", err)
	}
	if err := run([]string{"user-policies", "--email", "a@b", "extra"}, &out); err == nil {
		t.Fatal("expected error for extra arguments")
	}
}
