package main

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
)

// pathEntry is one path an entity's group policies declare, with a detail
// view of every distinct rule for it and where each rule comes from.
type pathEntry struct {
	Path, Entity string
	Detail       string
}

// policySources maps each policy attached to e's groups to the sorted names
// of the groups that attach it.
func policySources(e Entity) map[string][]string {
	sources := map[string][]string{}
	for _, g := range e.Groups {
		for _, p := range g.Policies {
			if !slices.Contains(sources[p], g.Name) {
				sources[p] = append(sources[p], g.Name)
			}
		}
	}
	for _, groups := range sources {
		slices.Sort(groups)
	}
	return sources
}

// unparsable counts the readable policies parseRules cannot consolidate,
// once per entity they apply to.
func (r *Report) unparsable() int {
	n := 0
	for _, e := range r.Entities {
		for name := range policySources(e) {
			if text, ok := r.Policies[name]; ok {
				if _, err := parseRules(text); err != nil {
					n++
				}
			}
		}
	}
	return n
}

// Paths returns the declared paths of every entity, sorted per entity.
func (r *Report) Paths() []pathEntry {
	var entries []pathEntry
	for _, e := range r.Entities {
		sources := policySources(e)
		type rule struct {
			body     string
			policies []string
		}
		rules := map[string][]*rule{} // path -> distinct rules in first-seen order
		byKey := map[string]*rule{}   // path + key -> rule
		for _, name := range slices.Sorted(maps.Keys(sources)) {
			text, ok := r.Policies[name]
			if !ok {
				continue
			}
			parsed, err := parseRules(text)
			if err != nil {
				continue
			}
			for _, pr := range parsed {
				id := pr.Path + "\x00" + pr.Key
				ru, ok := byKey[id]
				if !ok {
					ru = &rule{body: pr.Body}
					byKey[id] = ru
					rules[pr.Path] = append(rules[pr.Path], ru)
				}
				if !slices.Contains(ru.policies, name) {
					ru.policies = append(ru.policies, name)
				}
			}
		}
		for _, path := range slices.Sorted(maps.Keys(rules)) {
			lines := []string{
				"Path: " + path,
				fmt.Sprintf("Entity: %s (%s)", e.Name, e.ID),
				"Group policy declarations, not guaranteed effective access.",
			}
			if n := len(r.PolicyErrors); n > 0 {
				lines = append(lines, fmt.Sprintf("WARNING: %d policies unreadable/missing. Ctrl+R for details.", n))
			}
			for i, ru := range rules[path] {
				lines = append(lines, "", fmt.Sprintf("RULE %d", i+1), ru.body, "", "Sources:")
				for _, name := range ru.policies {
					lines = append(lines, fmt.Sprintf("  %s: %s", name, strings.Join(sources[name], ", ")))
				}
			}
			entries = append(entries, pathEntry{Path: path, Entity: e.Name, Detail: strings.Join(lines, "\n")})
		}
	}
	return entries
}

// Overview summarises the search, entities, aliases and groups in lines
// wrapped to width.
func (r *Report) Overview(width int) string {
	wrap := lipgloss.NewStyle().Width(max(20, width))
	lines := []string{
		fmt.Sprintf("Vault: %s (%s)", r.Context, r.Address),
		fmt.Sprintf("Email: %s | Username: %s", orDefault(r.Email, "(not supplied)"), orDefault(r.Username, "(not supplied)")),
	}
	for _, e := range r.Entities {
		lines = append(lines, fmt.Sprintf("Entity: %s (%s)", e.Name, e.ID))
		var aliases, groups []string
		for _, a := range e.Aliases {
			aliases = append(aliases, fmt.Sprintf("%s [%s]", a.Name, a.MountPath))
		}
		for _, g := range e.Groups {
			groups = append(groups, fmt.Sprintf("%s (%s)", g.Name, g.Membership))
		}
		if len(aliases) > 0 {
			lines = append(lines, wrap.Render("Aliases: "+strings.Join(aliases, ", ")))
		}
		lines = append(lines, wrap.Render(fmt.Sprintf("Groups (%d): %s", len(groups), orDefault(strings.Join(groups, ", "), "none"))))
	}
	return strings.Join(lines, "\n")
}

// Text renders the full report: each entity's groups, then its group
// policies' path declarations with identical permission bodies merged.
func (r *Report) Text() string {
	lines := []string{
		fmt.Sprintf("Vault: %s (%s)", r.Context, r.Address),
		fmt.Sprintf("Email: %s | Username: %s", orDefault(r.Email, "(not supplied)"), orDefault(r.Username, "(not supplied)")),
		"",
	}
	if len(r.Entities) == 0 {
		return strings.Join(append(lines, "No matching Vault identities found."), "\n")
	}
	for _, e := range r.Entities {
		lines = append(lines, fmt.Sprintf("Entity: %s (%s)", e.Name, e.ID))
		for _, a := range e.Aliases {
			lines = append(lines, fmt.Sprintf("Alias: %s [%s]", a.Name, a.MountPath))
		}
		if len(e.Policies) > 0 {
			lines = append(lines, "Entity policies (not included below): "+strings.Join(e.Policies, ", "))
		}
		if len(e.Groups) == 0 {
			lines = append(lines, "No Vault group memberships.", "")
			continue
		}
		var groups strings.Builder
		tw := tabwriter.NewWriter(&groups, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "Groups (%d):\n", len(e.Groups))
		fmt.Fprintln(tw, "  GROUP\tMEMBERSHIP\tID")
		for _, g := range e.Groups {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", g.Name, g.Membership, g.ID)
		}
		tw.Flush()
		lines = append(lines, strings.TrimSuffix(groups.String(), "\n"))
		lines = append(lines, r.entityPolicies(e)...)
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (r *Report) entityPolicies(e Entity) []string {
	sources := policySources(e)
	names := slices.Sorted(maps.Keys(sources))
	lines := []string{
		"",
		fmt.Sprintf("GROUP POLICY DECLARATIONS (%d unique policies)", len(names)),
		"Not an effective-access calculation. Only group-attached ACL policies are included.",
		"Login/token, entity-attached policies, Sentinel and namespace controls are not included.",
		"Exact duplicates are removed; identical permission bodies share one path list.",
		"Overlapping patterns and different rules for the same path remain separate.",
		"Vault path priority, deny rules, templates and constraints still apply.",
		"",
	}
	var missing []string
	for _, name := range names {
		if _, ok := r.PolicyErrors[name]; ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		lines = append(lines, fmt.Sprintf("WARNING: INCOMPLETE - %d policies could not be read:", len(missing)))
		for _, name := range missing {
			lines = append(lines, "  "+name, indent(r.PolicyErrors[name], "    "))
		}
		lines = append(lines, "")
	}

	ids := map[string]string{}
	for i, name := range names {
		ids[name] = fmt.Sprintf("P%d", i+1)
	}
	type section struct {
		body  string
		paths map[string][]string // path -> source policy ids
	}
	sections := map[string]*section{}
	type rawPolicy struct{ name, reason, text string }
	var raw []rawPolicy
	declarations := 0
	for _, name := range names {
		text, ok := r.Policies[name]
		if !ok {
			continue
		}
		rules, err := parseRules(text)
		if err != nil {
			raw = append(raw, rawPolicy{name, err.Error(), text})
			continue
		}
		declarations += len(rules)
		for _, ru := range rules {
			s, ok := sections[ru.Key]
			if !ok {
				s = &section{body: ru.Body, paths: map[string][]string{}}
				sections[ru.Key] = s
			}
			if !slices.Contains(s.paths[ru.Path], ids[name]) {
				s.paths[ru.Path] = append(s.paths[ru.Path], ids[name])
			}
		}
	}

	distinct := 0
	ordered := slices.Collect(maps.Values(sections))
	for _, s := range ordered {
		distinct += len(s.paths)
	}
	slices.SortFunc(ordered, func(a, b *section) int {
		if c := strings.Compare(slices.Min(slices.Collect(maps.Keys(a.paths))), slices.Min(slices.Collect(maps.Keys(b.paths)))); c != 0 {
			return c
		}
		return strings.Compare(a.body, b.body)
	})
	lines = append(lines, fmt.Sprintf("%d path declarations -> %d distinct rules across %d permission sets.", declarations, distinct, len(ordered)))
	for i, s := range ordered {
		lines = append(lines, "", fmt.Sprintf("PERMISSION SET %d", i+1), indent(s.body, "  "), "Paths (source policies):")
		for _, path := range slices.Sorted(maps.Keys(s.paths)) {
			slices.SortFunc(s.paths[path], comparePolicyIDs)
			lines = append(lines, fmt.Sprintf("  %s  [%s]", path, strings.Join(s.paths[path], ", ")))
		}
	}
	for _, p := range raw {
		lines = append(lines, "", fmt.Sprintf("UNCONSOLIDATED POLICY [%s] %s", ids[p.name], p.name),
			"Full text retained: "+p.reason, p.text)
	}
	lines = append(lines, "", "POLICY SOURCES")
	for _, name := range names {
		status := ""
		if _, ok := r.PolicyErrors[name]; ok {
			status = " [UNREADABLE / MISSING]"
		}
		lines = append(lines, fmt.Sprintf("  [%s] %s%s", ids[name], name, status),
			"    Groups: "+strings.Join(sources[name], ", "))
	}
	return lines
}

// comparePolicyIDs orders P2 before P10.
func comparePolicyIDs(a, b string) int {
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

var (
	warnSt  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#D20F39", Dark: "#F38BA8"})
	headSt2 = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#1E66F5", Dark: "#89B4FA"})
	metaSt  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#179299", Dark: "#94E2D5"})
	capSt   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#40A02B", Dark: "#A6E3A1"})
	paramSt = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#DF8E1D", Dark: "#F9E2AF"})
	denyRe  = regexp.MustCompile(`["']deny["']`)
)

// colorize highlights report lines: warnings and deny rules, headings,
// metadata, capabilities, and parameter constraints.
func colorize(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		s := strings.TrimLeft(l, " \t")
		has := func(prefixes ...string) bool {
			return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
		}
		switch {
		case strings.Contains(l, "WARNING:") || strings.Contains(l, "UNREADABLE") ||
			strings.Contains(l, "UNCONSOLIDATED") || denyRe.MatchString(l):
			lines[i] = warnSt.Render(l)
		case has("Vault:", "Entity:", "Path:", "PERMISSION SET", "RULE ", "GROUP POLICY", "POLICY SOURCES"):
			lines[i] = headSt2.Render(l)
		case has("Email:", "Username:", "Aliases:", "Alias:", "Groups", "Sources:", "Paths", "Entity policies"):
			lines[i] = metaSt.Render(l)
		case strings.Contains(l, "capabilities"):
			lines[i] = capSt.Render(l)
		case strings.Contains(l, "parameters") || strings.Contains(l, "wrapping_ttl") || strings.Contains(l, "control_group"):
			lines[i] = paramSt.Render(l)
		}
	}
	return strings.Join(lines, "\n")
}
