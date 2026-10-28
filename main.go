// Command vaultui is a terminal UI for HashiCorp Vault. It connects through
// vaultctx contexts and offers a menu of functions, such as user-policies.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

var version = "dev"

func main() {
	err := run(os.Args[1:], os.Stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
	case err != nil:
		fmt.Fprintln(os.Stderr, "vaultui:", err)
		os.Exit(2)
	}
}

func run(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("vaultui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	contextName := fs.String("context", "", "vaultctx context to use (skips the picker)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: vaultui [--context NAME] [FUNCTION [flags]]\n\n"+
			"A terminal UI for HashiCorp Vault. Contexts and logins come from vaultctx\n"+
			"(brew install --cask moexx399/tap/vaultctx). Without FUNCTION, pick one from a menu.\n\nFunctions:\n")
		for _, f := range functions {
			fmt.Fprintf(stderr, "  %-15s %s\n", f.name, f.description)
		}
		fmt.Fprint(stderr, "\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprint(stderr, "\nRun 'vaultui FUNCTION -h' for a function's flags.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	var start *functionDef
	var newFn func(session) function
	if fs.NArg() > 0 {
		def, ok := findFunction(fs.Arg(0))
		if !ok {
			fs.Usage()
			return fmt.Errorf("unknown function %q", fs.Arg(0))
		}
		ffs := flag.NewFlagSet("vaultui "+def.name, flag.ContinueOnError)
		ffs.SetOutput(stderr)
		if def.needsSession {
			ffs.StringVar(contextName, "context", *contextName, "vaultctx context to use (skips the picker)")
		}
		newFn = def.flags(ffs)
		if err := ffs.Parse(fs.Args()[1:]); err != nil {
			return err
		}
		if ffs.NArg() > 0 {
			return fmt.Errorf("unexpected arguments: %v", ffs.Args())
		}
		start = &def
	}

	_, err := tea.NewProgram(newApp(*contextName, start, newFn), tea.WithAltScreen()).Run()
	return err
}
