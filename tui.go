package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/vault/api"
)

type screen int

const (
	pickContext screen = iota
	connecting
	searchForm
	searching
	browsing
)

var (
	accent  = lipgloss.AdaptiveColor{Light: "#5A3FC0", Dark: "#9D8CFF"}
	subtle  = lipgloss.AdaptiveColor{Light: "#6B6B6B", Dark: "#8A8A8A"}
	titleSt = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(accent).Padding(0, 1)
	headSt  = lipgloss.NewStyle().Bold(true).Foreground(accent)
	dimSt   = lipgloss.NewStyle().Foreground(subtle)
	errSt   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#C0392B", Dark: "#FF6B6B"})
	labelSt = lipgloss.NewStyle().Width(10)
	appSt   = lipgloss.NewStyle().Padding(1, 2)
)

type (
	contextsMsg struct {
		names   []string
		current string
		err     error
	}
	connectedMsg struct {
		client *api.Client
		err    error
	}
	loginDoneMsg struct{ err error }
	resultsMsg   struct {
		report *Report
		err    error
	}
)

type item string

func (i item) FilterValue() string { return string(i) }
func (i item) Title() string       { return string(i) }
func (i item) Description() string { return "" }

type model struct {
	screen   screen
	contexts list.Model
	spin     spinner.Model
	inputs   []textinput.Model
	focus    int
	browser  browser

	context    string // selected vaultctx context
	client     *api.Client
	triedLogin bool
	err        error
	status     string
	autoSearch bool

	width, height int
}

func newModel(contextName, email, username string) model {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	delegate.SetSpacing(0)
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.Foreground(accent).BorderForeground(accent)
	l := list.New(nil, delegate, 0, 0)
	l.Title = "Vault context"
	l.Styles.Title = titleSt
	l.SetShowStatusBar(false)
	l.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "connect"))}
	}

	in := func(prompt, placeholder, value string) textinput.Model {
		t := textinput.New()
		t.Prompt = labelSt.Render(prompt)
		t.Placeholder = placeholder
		t.SetValue(value)
		t.Cursor.Style = headSt
		t.Width = 50
		return t
	}
	inputs := []textinput.Model{
		in("Email", "jane.doe@example.com", email),
		in("Username", "seven-letter username, e.g. WILSSEB", username),
	}
	inputs[0].Focus()

	m := model{
		contexts:   l,
		spin:       spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(headSt)),
		inputs:     inputs,
		context:    contextName,
		autoSearch: email != "" || username != "",
	}
	if contextName != "" {
		m.screen, m.status = connecting, "Connecting to "+contextName+"..."
	}
	return m
}

func (m model) Init() tea.Cmd {
	load := func() tea.Msg {
		names, current, err := listContexts(context.Background())
		return contextsMsg{names, current, err}
	}
	if m.screen == connecting { // --context skips the picker; load it for "change context"
		return tea.Batch(load, m.spin.Tick, connectCmd(m.context))
	}
	return load
}

func connectCmd(name string) tea.Cmd {
	return func() tea.Msg {
		c, err := connect(context.Background(), name)
		return connectedMsg{c, err}
	}
}

func (m model) searchCmd() tea.Cmd {
	client, contextName, q := m.client, m.context, m.queries()
	return func() tea.Msg {
		r, err := lookup(context.Background(), client, q[0], q[1])
		if r != nil {
			r.Context = contextName
		}
		return resultsMsg{r, err}
	}
}

func (m model) queries() []string {
	return []string{strings.TrimSpace(m.inputs[0].Value()), strings.TrimSpace(m.inputs[1].Value())}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		w, h := appSt.GetFrameSize()
		m.contexts.SetSize(msg.Width-w, msg.Height-h)
		if m.browser.report != nil {
			m.browser.setSize(m.bodySize())
		}
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case contextsMsg:
		if msg.err != nil {
			if m.screen == pickContext {
				m.err = msg.err
			}
			return m, nil
		}
		if m.context != "" {
			msg.current = m.context
		}
		items := make([]list.Item, len(msg.names))
		for i, n := range msg.names {
			items[i] = item(n)
		}
		cmd := m.contexts.SetItems(items)
		for i, n := range msg.names {
			if n == msg.current {
				m.contexts.Select(i)
			}
		}
		return m, cmd

	case connectedMsg:
		switch {
		case errors.Is(msg.err, errNeedsLogin) && !m.triedLogin:
			m.triedLogin = true
			return m, tea.ExecProcess(loginCmd(m.context), func(err error) tea.Msg { return loginDoneMsg{err} })
		case msg.err != nil:
			m.screen, m.err = pickContext, msg.err
			if errors.Is(msg.err, errNeedsLogin) {
				m.err = fmt.Errorf("could not log in to %q", m.context)
			}
			return m, nil
		}
		m.client, m.err = msg.client, nil
		if m.autoSearch {
			m.autoSearch = false
			if m.validQuery() {
				m.screen, m.status = searching, "Searching Vault identities..."
				return m, m.searchCmd()
			}
		}
		m.screen = searchForm
		return m, textinput.Blink

	case loginDoneMsg:
		if msg.err != nil {
			m.screen, m.err = pickContext, fmt.Errorf("vaultctx login %s: %w", m.context, msg.err)
			return m, nil
		}
		return m, tea.Batch(m.spin.Tick, connectCmd(m.context))

	case resultsMsg:
		if msg.err != nil {
			m.screen, m.err = searchForm, msg.err
			return m, nil
		}
		m.screen, m.err = browsing, nil
		w, h := m.bodySize()
		m.browser = newBrowser(msg.report, w, h)
		return m, textinput.Blink
	}

	switch m.screen {
	case pickContext:
		return m.updatePicker(msg)
	case searchForm:
		return m.updateForm(msg)
	case browsing:
		return m.updateBrowser(msg)
	}
	return m, nil
}

func (m model) updatePicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" && m.contexts.FilterState() != list.Filtering {
		if it, ok := m.contexts.SelectedItem().(item); ok {
			m.context, m.triedLogin, m.err = string(it), false, nil
			m.screen, m.status = connecting, "Connecting to "+m.context+"..."
			return m, tea.Batch(m.spin.Tick, connectCmd(m.context))
		}
	}
	var cmd tea.Cmd
	m.contexts, cmd = m.contexts.Update(msg)
	return m, cmd
}

func (m model) validQuery() bool {
	q := m.queries()
	return q[0] != "" || q[1] != ""
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			m.screen, m.err = pickContext, nil
			return m, nil
		case "tab", "shift+tab", "up", "down":
			m.inputs[m.focus].Blur()
			m.focus = (m.focus + 1) % len(m.inputs)
			return m, m.inputs[m.focus].Focus()
		case "enter":
			if !m.validQuery() {
				m.err = errors.New("enter an email or username")
				return m, nil
			}
			m.screen, m.status, m.err = searching, "Searching Vault identities...", nil
			return m, tea.Batch(m.spin.Tick, m.searchCmd())
		}
	}
	var cmd tea.Cmd
	m.inputs[m.focus], cmd = m.inputs[m.focus].Update(msg)
	return m, cmd
}

func (m model) updateBrowser(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		// The full report is the only view when there are no paths, so it
		// takes the keys the path list would otherwise need for filtering.
		reportOnly := len(m.browser.entries) == 0
		switch key := k.String(); {
		case key == "ctrl+n" || reportOnly && (key == "n" || key == "/"):
			m.screen = searchForm
			return m, textinput.Blink
		case key == "ctrl+t" || reportOnly && key == "c":
			m.screen = pickContext
			return m, nil
		case key == "esc" && !m.browser.showFull, reportOnly && (key == "esc" || key == "q"):
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.browser, cmd = m.browser.Update(msg)
	return m, cmd
}

// bodySize is the space below the title line.
func (m model) bodySize() (int, int) {
	w, h := appSt.GetFrameSize()
	return m.width - w, m.height - h - 2
}

func (m model) View() string {
	var b strings.Builder
	switch m.screen {
	case pickContext:
		if m.err != nil && len(m.contexts.Items()) == 0 {
			b.WriteString(titleSt.Render("Vault user policies") + "\n\n" + errSt.Render(m.err.Error()) + "\n\n" + dimSt.Render("ctrl+c quit"))
			break
		}
		b.WriteString(m.contexts.View())
		if m.err != nil {
			b.WriteString("\n" + errSt.Render(m.err.Error()))
		}
	case connecting, searching:
		b.WriteString(m.header() + "\n\n" + m.spin.View() + " " + m.status)
	case searchForm:
		b.WriteString(m.header() + "\n\n")
		b.WriteString(dimSt.Render("Find Vault identities by email or username (either is enough).") + "\n\n")
		for _, in := range m.inputs {
			b.WriteString(in.View() + "\n")
		}
		if m.err != nil {
			b.WriteString("\n" + errSt.Render(m.err.Error()) + "\n")
		}
		b.WriteString("\n" + dimSt.Render("tab switch field • enter search • esc change context • ctrl+c quit"))
	case browsing:
		b.WriteString(m.header() + "\n\n" + m.browser.View())
	}
	return appSt.Render(b.String())
}

func (m model) header() string {
	h := titleSt.Render("Vault user policies") + " " + headSt.Render(m.context)
	if m.client != nil {
		h += " " + dimSt.Render(m.client.Address())
	}
	return h
}
