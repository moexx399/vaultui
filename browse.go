package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	previewSt = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(subtle).Padding(0, 1)
	matchSt   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#DF8E1D", Dark: "#F9E2AF"}).Bold(true)
	cursorSt  = lipgloss.NewStyle().Foreground(accent).Bold(true)
)

// browser shows the paths a search's group policies declare: a fuzzy-filtered
// list with a preview of the selected path's rules, and the full report.
type browser struct {
	report  *Report
	entries []pathEntry
	filter  textinput.Model
	matches []list.Rank
	cursor  int
	offset  int
	preview viewport.Model
	full    viewport.Model
	// showFull shows the full report instead of the path list. It is the
	// only view when no path could be listed.
	showFull bool

	width, height, listHeight int
}

func newBrowser(r *Report, width, height int) browser {
	f := textinput.New()
	f.Prompt = headSt.Render("Path > ")
	f.Placeholder = "type to filter"
	f.Cursor.Style = headSt
	f.Focus()
	b := browser{report: r, entries: r.Paths(), filter: f, preview: viewport.New(0, 0), full: viewport.New(0, 0)}
	b.showFull = len(b.entries) == 0
	b.refilter()
	b.setSize(width, height)
	return b
}

func (b *browser) setSize(width, height int) {
	b.width, b.height = width, height
	b.full.Width, b.full.Height = width, max(1, height-lipgloss.Height(b.fullHeader())-1)
	b.full.SetContent(colorize(lipgloss.NewStyle().Width(width).Render(b.report.Text())))

	rest := height - lipgloss.Height(b.header()) - 2 // filter line and spacing
	previewHeight := max(5, rest*45/100)
	b.listHeight = max(1, rest-previewHeight)
	fw, fh := previewSt.GetFrameSize()
	b.preview.Width, b.preview.Height = max(10, width-fw), max(1, previewHeight-fh)
	b.filter.Width = max(10, width-lipgloss.Width(b.filter.Prompt)-12) // room for the match count
	b.select_(b.cursor)
}

func (b *browser) refilter() {
	paths := make([]string, len(b.entries))
	for i, e := range b.entries {
		paths[i] = e.Path
	}
	if term := b.filter.Value(); term != "" {
		b.matches = list.DefaultFilter(term, paths)
	} else {
		b.matches = make([]list.Rank, len(paths))
		for i := range paths {
			b.matches[i] = list.Rank{Index: i}
		}
	}
	b.offset = 0
	b.select_(0)
}

// select_ moves the cursor to i, keeps it visible, and loads its preview.
func (b *browser) select_(i int) {
	b.cursor = max(0, min(i, len(b.matches)-1))
	if b.cursor < b.offset {
		b.offset = b.cursor
	}
	if b.cursor >= b.offset+b.listHeight {
		b.offset = b.cursor - b.listHeight + 1
	}
	if len(b.matches) == 0 {
		b.preview.SetContent(dimSt.Render("No matching paths."))
		return
	}
	detail := b.entries[b.matches[b.cursor].Index].Detail
	b.preview.SetContent(colorize(lipgloss.NewStyle().Width(b.preview.Width).Render(detail)))
	b.preview.GotoTop()
}

func (b browser) Update(msg tea.Msg) (browser, tea.Cmd) {
	k, isKey := msg.(tea.KeyMsg)
	if b.showFull {
		if isKey && (k.String() == "ctrl+r" || k.String() == "esc" || k.String() == "q") && len(b.entries) > 0 {
			b.showFull = false
			return b, nil
		}
		var cmd tea.Cmd
		b.full, cmd = b.full.Update(msg)
		return b, cmd
	}
	if isKey {
		switch k.String() {
		case "up", "ctrl+p":
			b.select_(b.cursor - 1)
			return b, nil
		case "down", "ctrl+j":
			b.select_(b.cursor + 1)
			return b, nil
		case "pgup":
			b.select_(b.cursor - b.listHeight)
			return b, nil
		case "pgdown":
			b.select_(b.cursor + b.listHeight)
			return b, nil
		case "ctrl+d":
			b.preview.HalfPageDown()
			return b, nil
		case "ctrl+u":
			b.preview.HalfPageUp()
			return b, nil
		case "ctrl+r":
			b.showFull = true
			b.full.GotoTop()
			return b, nil
		}
	}
	before := b.filter.Value()
	var cmd tea.Cmd
	b.filter, cmd = b.filter.Update(msg)
	if b.filter.Value() != before {
		b.refilter()
	}
	return b, cmd
}

func (b browser) View() string {
	if b.showFull {
		return b.fullHeader() + "\n" + b.full.View()
	}
	var s strings.Builder
	s.WriteString(b.header() + "\n")
	s.WriteString(b.filter.View() + dimSt.Render(fmt.Sprintf("  %d/%d", len(b.matches), len(b.entries))) + "\n")
	for row := range b.listHeight {
		i := b.offset + row
		if i >= len(b.matches) {
			s.WriteString("\n")
			continue
		}
		e := b.entries[b.matches[i].Index]
		path := highlight(e.Path, b.matches[i].MatchedIndexes)
		if i == b.cursor {
			s.WriteString(cursorSt.Render("▌ ") + lipgloss.NewStyle().Bold(true).Render(path))
		} else {
			s.WriteString("  " + path)
		}
		s.WriteString("  " + dimSt.Render(e.Entity) + "\n")
	}
	s.WriteString(previewSt.Render(b.preview.View()))
	return s.String()
}

func (b browser) header() string {
	lines := []string{
		colorize(b.report.Overview(b.width)),
		"",
		dimSt.Render(fmt.Sprintf("%d paths • type to filter • ↑/↓ select • ctrl+d/u scroll preview • ctrl+r full report", len(b.entries))),
		dimSt.Render("esc new search • ctrl+c quit • Preview: group policy declarations, NOT effective access."),
	}
	if w := b.warning(); w != "" {
		lines = append(lines, warnSt.Render(w))
	}
	return lipgloss.NewStyle().Width(b.width).Render(strings.Join(lines, "\n"))
}

func (b browser) fullHeader() string {
	help := "↑/↓ scroll • esc new search • q quit"
	if len(b.entries) > 0 {
		help = "↑/↓ scroll • esc/ctrl+r back to paths • ctrl+c quit"
	} else if len(b.report.Entities) > 0 {
		help = "No browsable paths; showing the full report. " + help
	}
	s := dimSt.Render(help)
	if w := b.warning(); w != "" {
		s += "\n" + warnSt.Render(w)
	}
	return lipgloss.NewStyle().Width(b.width).Render(s)
}

func (b browser) warning() string {
	unreadable, unparsable := len(b.report.PolicyErrors), b.report.unparsable()
	if unreadable == 0 && unparsable == 0 {
		return ""
	}
	return fmt.Sprintf("WARNING: INCOMPLETE - %d unreadable/missing policies; %d unconsolidated policies. Ctrl+R for details.", unreadable, unparsable)
}

// highlight emphasises the matched byte offsets of s.
func highlight(s string, matched []int) string {
	if len(matched) == 0 {
		return s
	}
	var b strings.Builder
	set := map[int]bool{}
	for _, i := range matched {
		set[i] = true
	}
	for i, r := range s {
		if set[i] {
			b.WriteString(matchSt.Render(string(r)))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
