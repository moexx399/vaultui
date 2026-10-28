package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/vault/api"
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

// session is a connection to one vaultctx context.
type session struct {
	Context string
	Client  *api.Client
}

// function is one tool in the menu. It is shown below the app header, gets
// every message but ctrl+c (window sizes are its own area), and returns
// to the menu with backMsg.
type function interface {
	Init() tea.Cmd
	Update(tea.Msg) (function, tea.Cmd)
	View() string
}

type backMsg struct{}

func back() tea.Msg { return backMsg{} }

type functionDef struct {
	name, description string
	// needsSession functions run against one context, picked and logged in
	// to first; the others manage their own connections.
	needsSession bool
	// flags registers the function's command-line flags and returns its
	// constructor; the menu starts it with the flags' defaults.
	flags func(*flag.FlagSet) func(session) function
}

var functions = []functionDef{userPoliciesDef, replicationStatusDef}

func findFunction(name string) (functionDef, bool) {
	for _, f := range functions {
		if f.name == name {
			return f, true
		}
	}
	return functionDef{}, false
}

type screen int

const (
	menu screen = iota
	pickContext
	connecting
	running
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
)

type item struct{ title, desc string }

func (i item) FilterValue() string { return i.title }
func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }

// app offers a menu of functions and runs the chosen one, first picking a
// vaultctx context and connecting (logging in when needed) for those that
// need a session.
type app struct {
	screen   screen
	contexts list.Model
	menu     list.Model
	spin     spinner.Model

	session    session
	triedLogin bool
	fn         function
	fnDef      functionDef
	pending    func(session) function // started on connect instead of the menu
	err        error

	width, height int
}

func newList(title, enterHelp string, items []list.Item, descriptions bool) list.Model {
	d := list.NewDefaultDelegate()
	d.ShowDescription = descriptions
	if !descriptions {
		d.SetSpacing(0)
	}
	d.Styles.SelectedTitle = d.Styles.SelectedTitle.Foreground(accent).BorderForeground(accent)
	d.Styles.SelectedDesc = d.Styles.SelectedDesc.BorderForeground(accent)
	l := list.New(items, d, 0, 0)
	l.Title = title
	l.Styles.Title = titleSt
	l.SetShowStatusBar(false)
	l.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", enterHelp))}
	}
	return l
}

// newApp starts at the menu, or at start (built by newFn from its flags)
// when given. contextName, when given, is connected to without the picker.
func newApp(contextName string, start *functionDef, newFn func(session) function) app {
	items := make([]list.Item, len(functions))
	for i, f := range functions {
		items[i] = item{f.name, f.description}
	}
	a := app{
		contexts: newList("Vault context", "connect", nil, false),
		menu:     newList("Functions", "open", items, true),
		spin:     spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(headSt)),
		session:  session{Context: contextName},
	}
	a.menu.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
			key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "change context")),
		}
	}
	switch {
	case start != nil && !start.needsSession:
		a.screen, a.fnDef, a.fn = running, *start, newFn(session{})
		return a
	case start != nil:
		a.fnDef, a.pending, a.screen = *start, newFn, pickContext
	}
	if contextName != "" {
		a.screen = connecting
	}
	return a
}

func (a app) Init() tea.Cmd {
	cmds := []tea.Cmd{func() tea.Msg {
		names, current, err := listContexts(context.Background())
		return contextsMsg{names, current, err}
	}}
	switch a.screen {
	case connecting:
		cmds = append(cmds, a.spin.Tick, connectCmd(a.session.Context))
	case running:
		cmds = append(cmds, a.fn.Init())
	}
	return tea.Batch(cmds...)
}

func connectCmd(name string) tea.Cmd {
	return func() tea.Msg {
		c, err := connect(context.Background(), name)
		return connectedMsg{c, err}
	}
}

// bodySize is the space below the header.
func (a app) bodySize() tea.WindowSizeMsg {
	w, h := appSt.GetFrameSize()
	return tea.WindowSizeMsg{Width: a.width - w, Height: a.height - h - 2}
}

func (a app) startFunction(def functionDef, newFn func(session) function) (tea.Model, tea.Cmd) {
	a.screen, a.fnDef, a.fn = running, def, newFn(a.session)
	var sizeCmd tea.Cmd
	a.fn, sizeCmd = a.fn.Update(a.bodySize())
	return a, tea.Batch(a.fn.Init(), sizeCmd)
}

func (a app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		w, h := appSt.GetFrameSize()
		a.contexts.SetSize(msg.Width-w, msg.Height-h)
		a.menu.SetSize(msg.Width-w, msg.Height-h-2)
		if a.fn != nil {
			var cmd tea.Cmd
			a.fn, cmd = a.fn.Update(a.bodySize())
			return a, cmd
		}
		return a, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return a, tea.Quit
		}

	case backMsg:
		a.screen, a.fn = menu, nil
		return a, nil

	case contextsMsg:
		if msg.err != nil {
			a.err = msg.err
			return a, nil
		}
		if a.session.Context != "" {
			msg.current = a.session.Context
		}
		items := make([]list.Item, len(msg.names))
		for i, n := range msg.names {
			items[i] = item{title: n}
		}
		cmd := a.contexts.SetItems(items)
		for i, n := range msg.names {
			if n == msg.current {
				a.contexts.Select(i)
			}
		}
		return a, cmd

	case connectedMsg:
		switch {
		case errors.Is(msg.err, errNeedsLogin) && !a.triedLogin:
			a.triedLogin = true
			return a, tea.ExecProcess(loginCmd(a.session.Context), func(err error) tea.Msg { return loginDoneMsg{err} })
		case msg.err != nil:
			a.screen, a.err = pickContext, msg.err
			if errors.Is(msg.err, errNeedsLogin) {
				a.err = fmt.Errorf("could not log in to %q", a.session.Context)
			}
			return a, nil
		}
		a.session.Client, a.err = msg.client, nil
		if a.pending != nil {
			start := a.pending
			a.pending = nil
			return a.startFunction(a.fnDef, start)
		}
		a.screen = menu
		return a, nil

	case loginDoneMsg:
		if msg.err != nil {
			a.screen, a.err = pickContext, fmt.Errorf("vaultctx login %s: %w", a.session.Context, msg.err)
			return a, nil
		}
		return a, tea.Batch(a.spin.Tick, connectCmd(a.session.Context))
	}

	switch a.screen {
	case connecting:
		if _, ok := msg.(spinner.TickMsg); ok {
			var cmd tea.Cmd
			a.spin, cmd = a.spin.Update(msg)
			return a, cmd
		}
	case pickContext:
		if k, ok := msg.(tea.KeyMsg); ok && a.contexts.FilterState() == list.Unfiltered {
			switch k.String() {
			case "enter":
				if it, ok := a.contexts.SelectedItem().(item); ok {
					a.session = session{Context: it.title}
					a.screen, a.triedLogin, a.err = connecting, false, nil
					return a, tea.Batch(a.spin.Tick, connectCmd(it.title))
				}
			case "esc":
				a.screen, a.pending, a.err = menu, nil, nil
				return a, nil
			}
		}
		var cmd tea.Cmd
		a.contexts, cmd = a.contexts.Update(msg)
		return a, cmd
	case menu:
		if k, ok := msg.(tea.KeyMsg); ok && a.menu.FilterState() != list.Filtering {
			switch k.String() {
			case "enter":
				if it, ok := a.menu.SelectedItem().(item); ok {
					def, _ := findFunction(it.title)
					newFn := def.flags(flag.NewFlagSet(def.name, flag.ContinueOnError))
					if !def.needsSession || a.session.Client != nil {
						return a.startFunction(def, newFn)
					}
					a.screen, a.fnDef, a.pending = pickContext, def, newFn
					return a, nil
				}
			case "c":
				if a.menu.FilterState() == list.Unfiltered {
					a.screen = pickContext
					return a, nil
				}
			}
		}
		var cmd tea.Cmd
		a.menu, cmd = a.menu.Update(msg)
		return a, cmd
	case running:
		var cmd tea.Cmd
		a.fn, cmd = a.fn.Update(msg)
		return a, cmd
	}
	return a, nil
}

func (a app) View() string {
	var b strings.Builder
	switch a.screen {
	case pickContext:
		if a.err != nil && len(a.contexts.Items()) == 0 {
			b.WriteString(titleSt.Render("vaultui") + "\n\n" + errSt.Render(a.err.Error()) + "\n\n" + dimSt.Render("esc back • ctrl+c quit"))
			break
		}
		b.WriteString(a.contexts.View())
		if a.err != nil {
			b.WriteString("\n" + errSt.Render(a.err.Error()))
		}
	case connecting:
		b.WriteString(a.header() + "\n\n" + a.spin.View() + " Connecting to " + a.session.Context + "...")
	case menu:
		b.WriteString(a.header() + "\n\n" + a.menu.View())
		if a.err != nil {
			b.WriteString("\n" + errSt.Render(a.err.Error()))
		}
	case running:
		b.WriteString(a.header() + "\n\n" + a.fn.View())
	}
	return appSt.Render(b.String())
}

func (a app) header() string {
	h := titleSt.Render("vaultui")
	if a.session.Context != "" && (a.screen != running || a.fnDef.needsSession) {
		h += " " + headSt.Render(a.session.Context)
		if a.session.Client != nil {
			h += " " + dimSt.Render(a.session.Client.Address())
		}
	}
	if a.screen == running {
		h += dimSt.Render(" › ") + headSt.Render(a.fnDef.name)
	}
	return h
}
