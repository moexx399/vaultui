package main

import (
	"context"
	"flag"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var replicationStatusDef = functionDef{
	name:        "replication-status",
	description: "DR and performance replication topology, WAL lag, node health and TLS for every vaultctx context (no login needed)",
	flags: func(fs *flag.FlagSet) func(session) function {
		opts := statusOptions{}
		fs.DurationVar(&opts.Timeout, "timeout", 10*time.Second, "per-request timeout")
		fs.BoolVar(&opts.NoTLS, "no-tls", false, "skip fetching TLS certificate details")
		watch := fs.Duration("watch", 0, "refresh continuously at this interval, e.g. 30s")
		page := fs.String("page", "", "open the topology containing this vaultctx context")
		return func(session) function {
			return &replicationStatus{opts: opts, watch: *watch, page: *page, view: viewport.New(0, 0),
				spin: spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(headSt))}
		}
	},
}

var (
	okSt      = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#40A02B", Dark: "#A6E3A1"})
	primarySt = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#8839EF", Dark: "#CBA6F7"})
	nodeSt    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#1E66F5", Dark: "#89B4FA"})
	sectionSt = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#179299", Dark: "#94E2D5"})
	tabSt     = lipgloss.NewStyle().Padding(0, 1)
	activeTab = tabSt.Bold(true).Reverse(true)
)

type statusMsg struct {
	tops []topology
	at   time.Time
	err  error
}

type refreshMsg struct{}

// replicationStatus pages through replication topologies, one per tab.
type replicationStatus struct {
	opts    statusOptions
	watch   time.Duration
	page    string // context whose topology to open first
	spin    spinner.Model
	view    viewport.Model
	tops    []topology
	at      time.Time
	err     error
	loading bool
	tab     int
	all     bool // every topology on one page
	width   int
}

func (r *replicationStatus) Init() tea.Cmd { return r.load() }

func (r *replicationStatus) load() tea.Cmd {
	r.loading = true
	opts := r.opts
	return tea.Batch(r.spin.Tick, func() tea.Msg {
		tops, err := collectStatus(context.Background(), opts)
		return statusMsg{tops, time.Now(), err}
	})
}

func (r *replicationStatus) Update(msg tea.Msg) (function, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width = msg.Width
		r.view.Width, r.view.Height = msg.Width, max(1, msg.Height-4) // status, tabs, help
		r.render()
		return r, nil
	case spinner.TickMsg:
		if !r.loading {
			return r, nil
		}
		var cmd tea.Cmd
		r.spin, cmd = r.spin.Update(msg)
		return r, cmd
	case refreshMsg:
		if r.loading {
			return r, nil
		}
		return r, r.load()
	case statusMsg:
		r.loading, r.err, r.at = false, msg.err, msg.at
		if msg.err == nil {
			current := r.page
			if current == "" && r.tab < len(r.tops) {
				current = r.tops[r.tab].Name
			}
			r.tops, r.page = msg.tops, ""
			r.tab = max(0, slices.IndexFunc(r.tops, func(t topology) bool {
				return t.Name == current || slices.ContainsFunc(t.Clusters, func(c *cluster) bool { return slices.Contains(c.Contexts, current) })
			}))
			r.render()
		}
		if r.watch > 0 {
			return r, tea.Tick(r.watch, func(time.Time) tea.Msg { return refreshMsg{} })
		}
		return r, nil
	case tea.KeyMsg:
		n := len(r.tops)
		switch key := msg.String(); key {
		case "esc":
			return r, back
		case "q":
			return r, tea.Quit
		case "r":
			if !r.loading {
				return r, r.load()
			}
			return r, nil
		case "a":
			r.all = !r.all
		case "right", "l", "n", "tab", " ":
			if n > 0 {
				r.tab = (r.tab + 1) % n
			}
		case "left", "h", "p", "shift+tab":
			if n > 0 {
				r.tab = (r.tab + n - 1) % n
			}
		default:
			if i, err := strconv.Atoi(key); err == nil && i >= 1 && i <= n {
				r.tab = i - 1
			} else {
				var cmd tea.Cmd
				r.view, cmd = r.view.Update(msg)
				return r, cmd
			}
		}
		r.render()
		r.view.GotoTop()
		return r, nil
	}
	return r, nil
}

func (r *replicationStatus) render() {
	if len(r.tops) == 0 {
		r.view.SetContent(dimSt.Render("No vaultctx contexts to query."))
		return
	}
	pages := []topology{r.tops[min(r.tab, len(r.tops)-1)]}
	if r.all {
		pages = r.tops
	}
	var parts []string
	for _, t := range pages {
		if r.all {
			parts = append(parts, lipgloss.NewStyle().Bold(true).Render("TOPOLOGY: "+strings.ToUpper(t.Name)))
		}
		parts = append(parts, renderTopology(t, r.width))
	}
	r.view.SetContent(strings.Join(parts, "\n\n"))
}

func (r *replicationStatus) View() string {
	status := lipgloss.NewStyle().Bold(true).Render("Vault Replication Status")
	switch {
	case r.loading && r.tops == nil:
		return status + "\n\n" + r.spin.View() + " Querying every vaultctx context..."
	case r.loading:
		status += " " + r.spin.View() + dimSt.Render(" refreshing")
	default:
		status += dimSt.Render(" (" + r.at.UTC().Format("2006-01-02 15:04:05Z") + ")")
		if r.watch > 0 {
			status += dimSt.Render(" every " + r.watch.String())
		}
	}
	if r.err != nil {
		status += "\n" + errSt.Render(r.err.Error())
	}
	help := dimSt.Render("←/→ topology • 1-9 jump • ↑/↓ scroll • r refresh • a show all • esc back • q quit")
	return status + "\n" + r.tabBar() + "\n" + r.view.View() + "\n" + help
}

func (r *replicationStatus) tabBar() string {
	tabs := make([]string, len(r.tops))
	for i, t := range r.tops {
		lvl, ok := t.overall()
		glyph := dimSt.Render("?")
		if ok {
			glyph = levelStyle(lvl).Render("●")
		}
		label := fmt.Sprintf("%d:%s", i+1, t.Name)
		if i == r.tab && !r.all {
			tabs[i] = activeTab.Render(label) + glyph
		} else {
			tabs[i] = tabSt.Render(label) + glyph
		}
	}
	return lipgloss.NewStyle().Width(r.width).Render(strings.Join(tabs, " "))
}

func levelStyle(l level) lipgloss.Style {
	switch l {
	case levelOK:
		return okSt
	case levelWarn:
		return paramSt
	case levelCrit:
		return warnSt
	}
	return dimSt
}

func mark(l level) string {
	return levelStyle(l).Render(map[level]string{levelOK: "OK  ", levelUnknown: "????", levelWarn: "WARN", levelCrit: "CRIT"}[l])
}

func section(label string, width int) string {
	return sectionSt.Render("── " + label + " " + strings.Repeat("─", max(0, min(width, 80)-len(label)-4)))
}

func reasons(indent string, v verdict) []string {
	if len(v.Reasons) == 0 {
		return nil
	}
	return []string{dimSt.Render(indent + "! " + strings.Join(v.Reasons, "; "))}
}

func fmtWAL(v *int64) string {
	if v == nil {
		return "-"
	}
	s := strconv.FormatInt(abs(*v), 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if *v < 0 {
		return "-" + s
	}
	return s
}

func fmtLag(r *replication) string {
	if r.WALLag == nil {
		return dimSt.Render("n/a")
	}
	s := fmtWAL(r.WALLag)
	if *r.WALLag >= 0 {
		s = "+" + s
	}
	switch a := abs(*r.WALLag); {
	case a >= walLagCrit:
		return warnSt.Render(s)
	case a >= walLagWarn:
		return paramSt.Render(s)
	}
	return okSt.Render(s)
}

// via notes how a cluster no context points at was found.
func via(c *cluster) string {
	if c.DiscoveredVia == "" {
		return ""
	}
	return dimSt.Render(" (discovered via " + c.DiscoveredVia + ")")
}

// field renders "label: value" indented under a node, wrapping the value
// with a hanging indent.
func field(label, value string, width int) string {
	const indent = 18 // "         " + "subject: "
	body := lipgloss.NewStyle().Width(max(20, width-indent)).Render(value)
	body = strings.ReplaceAll(body, "\n", "\n"+strings.Repeat(" ", indent))
	return dimSt.Render(fmt.Sprintf("         %-9s", label+":") + body)
}

func orNA(s string) string { return orDefault(s, "n/a") }

func fmtMS(s string) string {
	if s == "" {
		return "n/a"
	}
	return s + "ms"
}

func fmtVersion(c *cluster) string {
	if c == nil || c.Version == "" {
		return dimSt.Render("vault=n/a")
	}
	return "vault=" + c.Version
}

// renderTopology draws one topology: the node each context reaches, the DR
// and performance replication trees, unreachable contexts, TLS certificates,
// and an overall verdict.
func renderTopology(t topology, width int) string {
	var out []string
	add := func(lines ...string) { out = append(out, lines...) }

	reachable := slices.ContainsFunc(t.Clusters, func(c *cluster) bool { return c.Err == "" })
	if reachable {
		add(section("Clusters", width))
	}
	for _, c := range t.Clusters {
		if c.Err != "" {
			continue
		}
		v := nodeHealth(c)
		add(fmt.Sprintf("  %s %s %s state=%s %s cluster=%s%s", mark(v.Level), nodeSt.Render(c.Name()), dimSt.Render(c.Address),
			healthState(c.HealthCode), fmtVersion(c), orNA(c.ClusterName), via(c)))
		add(reasons("         ", v)...)
	}
	if reachable {
		add("")
	}

	for _, mode := range []struct{ key, label string }{{"dr", "DR Replication"}, {"performance", "Performance Replication"}} {
		if !reachable {
			break
		}
		add(section(mode.label, width))
		var primaries, secondaries []*cluster
		for _, c := range t.Clusters {
			if r := c.Modes[mode.key]; r != nil && r.Role == "primary" {
				primaries = append(primaries, c)
			} else if r != nil {
				secondaries = append(secondaries, c)
			}
		}
		if len(primaries)+len(secondaries) == 0 {
			add(dimSt.Render("   (not configured on any queried cluster)"), "")
			continue
		}
		for _, p := range primaries {
			pr := p.Modes[mode.key]
			v := syncHealth(pr)
			add(fmt.Sprintf("  %s %s %s %s state=%s wal=%s merkle=%.12s", mark(v.Level), primarySt.Render(p.Name()),
				dimSt.Render("[PRIMARY]"), fmtVersion(p), pr.State, fmtWAL(pr.LastWAL), pr.MerkleRoot))
			add(reasons("         ", v)...)
			kids := children(p, mode.key, t.Clusters)
			for i, ch := range kids {
				elbow, pad := "├─▶", "   │    "
				if i == len(kids)-1 {
					elbow, pad = "└─▶", "        "
				}
				var sv verdict
				var detail string
				if ch.Repl != nil {
					sv = syncHealth(ch.Repl)
					detail = fmt.Sprintf("state=%s conn=%s remote_wal=%s lag=%s", ch.Repl.State, ch.Repl.ConnectionState, fmtWAL(ch.Repl.LastRemoteWAL), fmtLag(ch.Repl))
				} else {
					sv = verdict{Level: levelUnknown, Reasons: []string{"not queried directly"}}
					conn := "unknown"
					if ch.Link != nil {
						conn = orDefault(ch.Link.ConnectionStatus, "unknown")
					}
					detail = dimSt.Render("conn=" + conn)
				}
				add(fmt.Sprintf("   %s %s %s %s %s %s", elbow, mark(sv.Level), nodeSt.Render(ch.Name), dimSt.Render("[SECONDARY]"), fmtVersion(ch.Cluster), detail))
				if l := ch.Link; l != nil {
					hb := "unknown"
					if l.HeartbeatAge != nil {
						hb = fmt.Sprintf("%.0fs ago", l.HeartbeatAge.Seconds())
					}
					add(dimSt.Render(fmt.Sprintf("%s  link: %s heartbeat=%s skew=%s canary=%s", pad, orDefault(l.ConnectionStatus, "unknown"), hb, fmtMS(l.ClockSkew), fmtMS(l.CanaryAge))))
				} else {
					add(dimSt.Render(pad+"  link: ") + warnSt.Render("no link reported by primary"))
				}
				add(reasons(pad+"  ", sv)...)
			}
			add("")
		}
		for _, s := range secondaries {
			sr := s.Modes[mode.key]
			if sr.Primary != nil {
				continue
			}
			v := syncHealth(sr)
			add(fmt.Sprintf("  %s %s %s %s of %s %s state=%s remote_wal=%s", mark(v.Level), nodeSt.Render(s.Name()), dimSt.Render("[SECONDARY]"),
				fmtVersion(s), primarySt.Render(sr.PrimaryName), dimSt.Render("(primary not queried)"), sr.State, fmtWAL(sr.LastRemoteWAL)))
			add(reasons("         ", v)...)
			add("")
		}
	}

	var unreachable []string
	for _, c := range t.Clusters {
		if c.Err != "" {
			unreachable = append(unreachable, fmt.Sprintf("  %s %s: %s%s", warnSt.Render("CRIT"), c.Name(), c.Err, via(c)))
		}
	}
	if len(unreachable) > 0 {
		add(warnSt.Bold(true).Render("── Unreachable " + strings.Repeat("─", max(0, min(width, 80)-15))))
		add(unreachable...)
		add("")
	}

	var certs []*cluster
	for _, c := range t.Clusters {
		if c.TLS != nil {
			certs = append(certs, c)
		}
	}
	if len(certs) > 0 {
		add(section("TLS Certificates", width))
		if v := certConsistency(certs); len(v.Reasons) > 0 {
			add(fmt.Sprintf("  %s cluster cert consistency: mismatch detected", mark(v.Level)))
			for _, r := range v.Reasons {
				add(dimSt.Render("         ! " + r))
			}
			add("")
		}
		for _, c := range certs {
			info, v := c.TLS, tlsHealth(c.TLS)
			if info.Err != "" {
				add(fmt.Sprintf("  %s %s %s %s", mark(v.Level), nodeSt.Render(c.Name()), info.Host, warnSt.Render(info.Err)), "")
				continue
			}
			add(fmt.Sprintf("  %s %s %s expires=%s (%dd)", mark(v.Level), nodeSt.Render(c.Name()), info.Host, info.NotAfter.UTC().Format("Jan _2 15:04:05 2006 MST"), info.DaysRemaining))
			for _, f := range [][2]string{
				{"subject", info.Subject}, {"issuer", info.Issuer}, {"sans", strings.Join(info.SANs, ", ")},
				{"serial", info.Serial}, {"sha256", info.Fingerprint},
			} {
				add(field(f[0], orNA(f[1]), width))
			}
			add(reasons("         ", v)...)
			add("")
		}
	}

	switch lvl, ok := t.overall(); {
	case !ok:
		add(dimSt.Render("Overall: nothing to check"))
	case lvl == levelCrit:
		add(warnSt.Bold(true).Render("Overall: DEGRADED"))
	case lvl == levelWarn:
		add(paramSt.Bold(true).Render("Overall: WARNING"))
	default:
		add(okSt.Bold(true).Render("Overall: HEALTHY"))
	}
	return lipgloss.NewStyle().Width(width).Render(strings.Join(out, "\n"))
}
