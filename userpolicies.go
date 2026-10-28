package main

import (
	"context"
	"errors"
	"flag"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

var userPoliciesDef = functionDef{
	name:         "user-policies",
	needsSession: true,
	description:  "Find a user's identities and groups, and browse the paths their group policies declare",
	flags: func(fs *flag.FlagSet) func(session) function {
		email := fs.String("email", "", "email to search for")
		username := fs.String("username", "", "username to search for")
		return func(s session) function { return newUserPolicies(s, *email, *username) }
	},
}

type upScreen int

const (
	upForm upScreen = iota
	upSearching
	upBrowsing
)

type reportMsg struct {
	report *Report
	err    error
}

// userPolicies searches for a user's identities and browses their group
// policies' path declarations.
type userPolicies struct {
	session session
	screen  upScreen
	inputs  []textinput.Model
	focus   int
	spin    spinner.Model
	browser browser
	err     error
	size    tea.WindowSizeMsg
	// autoSearch searches as soon as it starts, for queries from flags.
	autoSearch bool
}

func newUserPolicies(s session, email, username string) function {
	in := func(prompt, placeholder, value string) textinput.Model {
		t := textinput.New()
		t.Prompt = labelSt.Render(prompt)
		t.Placeholder = placeholder
		t.SetValue(value)
		t.Cursor.Style = headSt
		t.Width = 50
		return t
	}
	u := &userPolicies{
		session: s,
		inputs: []textinput.Model{
			in("Email", "jane.doe@example.com", email),
			in("Username", "seven-letter username, e.g. WILSSEB", username),
		},
		spin:       spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(headSt)),
		autoSearch: email != "" || username != "",
	}
	u.inputs[0].Focus()
	return u
}

func (u *userPolicies) Init() tea.Cmd {
	if u.autoSearch {
		return u.search()
	}
	return textinput.Blink
}

func (u *userPolicies) queries() (email, username string) {
	return strings.TrimSpace(u.inputs[0].Value()), strings.TrimSpace(u.inputs[1].Value())
}

func (u *userPolicies) search() tea.Cmd {
	email, username := u.queries()
	if email == "" && username == "" {
		u.err = errors.New("enter an email or username")
		return nil
	}
	u.screen, u.err = upSearching, nil
	s := u.session
	return tea.Batch(u.spin.Tick, func() tea.Msg {
		r, err := lookup(context.Background(), s.Client, email, username)
		if r != nil {
			r.Context = s.Context
		}
		return reportMsg{r, err}
	})
}

func (u *userPolicies) Update(msg tea.Msg) (function, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		u.size = msg
		if u.browser.report != nil {
			u.browser.setSize(msg.Width, msg.Height)
		}
		return u, nil
	case spinner.TickMsg:
		if u.screen != upSearching {
			return u, nil
		}
		var cmd tea.Cmd
		u.spin, cmd = u.spin.Update(msg)
		return u, cmd
	case reportMsg:
		if msg.err != nil {
			u.screen, u.err = upForm, msg.err
			return u, nil
		}
		u.screen = upBrowsing
		u.browser = newBrowser(msg.report, u.size.Width, u.size.Height)
		return u, textinput.Blink
	}

	switch u.screen {
	case upForm:
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "esc":
				return u, back
			case "tab", "shift+tab", "up", "down":
				u.inputs[u.focus].Blur()
				u.focus = (u.focus + 1) % len(u.inputs)
				return u, u.inputs[u.focus].Focus()
			case "enter":
				return u, u.search()
			}
		}
		var cmd tea.Cmd
		u.inputs[u.focus], cmd = u.inputs[u.focus].Update(msg)
		return u, cmd
	case upBrowsing:
		if k, ok := msg.(tea.KeyMsg); ok {
			// The full report is the only view when there are no paths.
			reportOnly := len(u.browser.entries) == 0
			switch {
			case k.String() == "esc" && (reportOnly || !u.browser.showFull):
				u.screen = upForm
				return u, textinput.Blink
			case k.String() == "q" && reportOnly:
				return u, tea.Quit
			}
		}
		var cmd tea.Cmd
		u.browser, cmd = u.browser.Update(msg)
		return u, cmd
	}
	return u, nil
}

func (u *userPolicies) View() string {
	switch u.screen {
	case upSearching:
		return u.spin.View() + " Searching Vault identities and reading group policies..."
	case upBrowsing:
		return u.browser.View()
	}
	var b strings.Builder
	b.WriteString(dimSt.Render("Find Vault identities by email or username (either is enough).") + "\n\n")
	for _, in := range u.inputs {
		b.WriteString(in.View() + "\n")
	}
	if u.err != nil {
		b.WriteString("\n" + errSt.Render(u.err.Error()) + "\n")
	}
	b.WriteString("\n" + dimSt.Render("tab switch field • enter search • esc back • ctrl+c quit"))
	return b.String()
}
