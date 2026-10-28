package main

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/vault/api"
)

// Entity is a Vault identity entity and the groups it belongs to.
type Entity struct {
	ID       string
	Name     string
	Policies []string // attached directly to the entity
	Aliases  []Alias
	Groups   []Group
}

type Alias struct{ Name, MountPath string }

type Group struct {
	ID, Name   string
	Policies   []string
	Membership string // direct, inherited, or unspecified
}

// Report is everything known about the identities matching a search.
type Report struct {
	Context, Address string
	Email, Username  string
	Entities         []Entity
	Policies         map[string]string // ACL policy text by name, for group policies
	PolicyErrors     map[string]string // group policies that could not be read
}

// lookup finds the entities matching email or username and reads the text
// of every policy attached to their groups. Unreadable policies are recorded
// in PolicyErrors rather than failing the lookup.
func lookup(ctx context.Context, client *api.Client, email, username string) (*Report, error) {
	entities, err := findEntities(ctx, client, []string{email, username})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entities {
		for _, g := range e.Groups {
			names = append(names, g.Policies...)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)

	texts, errs := make([]string, len(names)), make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			texts[i], errs[i] = client.Sys().GetPolicyWithContext(ctx, name)
			if errs[i] == nil && texts[i] == "" {
				errs[i] = fmt.Errorf("no policy named %q", name)
			}
		})
	}
	wg.Wait()

	r := &Report{
		Address: client.Address(), Email: email, Username: username, Entities: entities,
		Policies: map[string]string{}, PolicyErrors: map[string]string{},
	}
	for i, name := range names {
		if errs[i] != nil {
			r.PolicyErrors[name] = errs[i].Error()
		} else {
			r.Policies[name] = texts[i]
		}
	}
	return r, nil
}

// findEntities returns entities whose name or any alias name equals one of
// queries (case-insensitively), with their aliases and group memberships.
func findEntities(ctx context.Context, client *api.Client, queries []string) ([]Entity, error) {
	list, err := client.Logical().ListWithContext(ctx, "identity/entity/id")
	if err != nil {
		return nil, fmt.Errorf("list entities: %w", err)
	}
	var ids []string
	if list != nil {
		ids = matchEntities(list.Data["key_info"], queries)
	}

	entities := make([]Entity, len(ids))
	groups := newGroupCache()
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Go(func() { entities[i], errs[i] = readEntity(ctx, client, id, groups) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].Name < entities[j].Name })
	return entities, nil
}

// matchEntities filters the key_info of a detailed entity listing.
func matchEntities(keyInfo any, queries []string) []string {
	var want []string
	for _, q := range queries {
		if q = strings.ToLower(strings.TrimSpace(q)); q != "" {
			want = append(want, q)
		}
	}
	info, _ := keyInfo.(map[string]any)
	var ids []string
	for id, v := range info {
		e, _ := v.(map[string]any)
		names := []string{str(e["name"])}
		aliases, _ := e["aliases"].([]any)
		for _, a := range aliases {
			am, _ := a.(map[string]any)
			names = append(names, str(am["name"]))
		}
		if slices.ContainsFunc(names, func(n string) bool { return slices.Contains(want, strings.ToLower(n)) }) {
			ids = append(ids, id)
		}
	}
	return ids
}

func readEntity(ctx context.Context, client *api.Client, id string, groups *groupCache) (Entity, error) {
	s, err := client.Logical().ReadWithContext(ctx, "identity/entity/id/"+id)
	if err != nil {
		return Entity{}, fmt.Errorf("read entity %s: %w", id, err)
	}
	if s == nil {
		return Entity{}, fmt.Errorf("entity %s not found", id)
	}
	e := Entity{ID: id, Name: str(s.Data["name"]), Policies: strs(s.Data["policies"])}
	aliases, _ := s.Data["aliases"].([]any)
	for _, a := range aliases {
		am, _ := a.(map[string]any)
		e.Aliases = append(e.Aliases, Alias{Name: str(am["name"]), MountPath: str(am["mount_path"])})
	}

	direct, inherited := strs(s.Data["direct_group_ids"]), strs(s.Data["inherited_group_ids"])
	all := slices.Concat(strs(s.Data["group_ids"]), direct, inherited)
	slices.Sort(all)
	all = slices.Compact(all)
	for _, gid := range all {
		g, err := groups.get(gid, func() (Group, error) {
			s, err := client.Logical().ReadWithContext(ctx, "identity/group/id/"+gid)
			if err != nil {
				return Group{}, fmt.Errorf("read group %s: %w", gid, err)
			}
			if s == nil {
				return Group{ID: gid, Name: gid}, nil // deleted since the entity was read
			}
			return Group{ID: gid, Name: str(s.Data["name"]), Policies: strs(s.Data["policies"])}, nil
		})
		if err != nil {
			return Entity{}, err
		}
		g.Membership = "unspecified"
		switch {
		case slices.Contains(direct, gid):
			g.Membership = "direct"
		case slices.Contains(inherited, gid):
			g.Membership = "inherited"
		}
		e.Groups = append(e.Groups, g)
	}
	sort.Slice(e.Groups, func(i, j int) bool { return e.Groups[i].Name < e.Groups[j].Name })
	return e, nil
}

// groupCache reads each group once across concurrent entity reads.
type groupCache struct {
	mu     sync.Mutex
	groups map[string]func() (Group, error)
}

func newGroupCache() *groupCache { return &groupCache{groups: map[string]func() (Group, error){}} }

func (c *groupCache) get(id string, load func() (Group, error)) (Group, error) {
	c.mu.Lock()
	f, ok := c.groups[id]
	if !ok {
		f = sync.OnceValues(load)
		c.groups[id] = f
	}
	c.mu.Unlock()
	return f()
}

func str(v any) string { s, _ := v.(string); return s }

func strs(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s := str(it); s != "" {
			out = append(out, s)
		}
	}
	return out
}
