// Command vault-user-policies looks up a user's Vault identity entities and
// their group memberships and policies, using vaultctx contexts to connect.
package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

var version = "dev"

func main() {
	contextName := flag.String("context", "", "vaultctx context to use (skips the picker)")
	email := flag.String("email", "", "email to search for")
	username := flag.String("username", "", "username to search for")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: vault-user-policies [flags]\n\n"+
			"Interactively find a user's Vault identities, groups and policies.\n"+
			"Contexts and logins come from vaultctx (brew install --cask moexx399/tap/vaultctx).\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}

	m := newModel(*contextName, *email, *username)
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "vault-user-policies:", err)
		os.Exit(1)
	}
}
