package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/vault/api"
)

// vaultctxBin is the vaultctx executable (https://github.com/moexx399/vaultctx),
// which owns Vault contexts, logins and cached tokens.
const vaultctxBin = "vaultctx"

// vaultctxCmd runs vaultctx without the shell-integration and fzf behaviour
// meant for interactive shells.
func vaultctxCmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, vaultctxBin, args...)
	cmd.Env = append(os.Environ(), "VAULTCTX_IGNORE_FZF=1", "NO_COLOR=1", "VAULTCTX_ENV_FILE=")
	return cmd
}

// listContexts returns the configured context names and the active one ("" if none).
func listContexts(ctx context.Context) ([]string, string, error) {
	out, err := output(vaultctxCmd(ctx))
	if err != nil {
		return nil, "", err
	}
	names := strings.Fields(out)
	if len(names) == 0 {
		return nil, "", errors.New("no vaultctx contexts; add one with 'vaultctx add NAME --address URL'")
	}
	current, _ := output(vaultctxCmd(ctx, "-c")) // fails when there is no current context
	return names, strings.TrimSpace(current), nil
}

// loginCmd logs in to a context interactively; it needs the terminal.
func loginCmd(name string) *exec.Cmd {
	return vaultctxCmd(context.Background(), "login", name)
}

// errNeedsLogin means the context has no valid cached token.
var errNeedsLogin = errors.New("needs login")

// connect builds a Vault client from the context's environment as reported by
// `vaultctx env`, without switching the user's active context.
func connect(ctx context.Context, name string) (*api.Client, error) {
	out, err := output(vaultctxCmd(ctx, "env", "--shell", "bash", name))
	if err != nil {
		return nil, err
	}
	env, err := parseEnv(out)
	if err != nil {
		return nil, err
	}
	if env["VAULT_TOKEN"] == "" {
		return nil, errNeedsLogin
	}

	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	cfg.Address = env["VAULT_ADDR"]
	if err := cfg.ConfigureTLS(&api.TLSConfig{
		CACert:     env["VAULT_CACERT"],
		ClientCert: env["VAULT_CLIENT_CERT"],
		ClientKey:  env["VAULT_CLIENT_KEY"],
		Insecure:   env["VAULT_SKIP_VERIFY"] == "true",
	}); err != nil {
		return nil, err
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(env["VAULT_TOKEN"])
	client.SetNamespace(env["VAULT_NAMESPACE"])

	_, err = client.Auth().Token().LookupSelfWithContext(ctx)
	var respErr *api.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == 403 {
		return nil, errNeedsLogin
	}
	if err != nil {
		return nil, fmt.Errorf("verify token for %q: %w", name, err)
	}
	return client, nil
}

// parseEnv reads vaultctx's POSIX env output: lines of `export K='v';` and
// `unset K;`, where a single quote inside a value is escaped shell-style.
func parseEnv(s string) (map[string]string, error) {
	env := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSuffix(strings.TrimSpace(sc.Text()), ";")
		if line == "" || strings.HasPrefix(line, "unset ") {
			continue
		}
		kv, ok := strings.CutPrefix(line, "export ")
		k, v, ok2 := strings.Cut(kv, "=")
		if !ok || !ok2 || len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
			return nil, fmt.Errorf("unexpected vaultctx env output: %q", line)
		}
		env[k] = strings.ReplaceAll(v[1:len(v)-1], `'\''`, `'`)
	}
	return env, sc.Err()
}

// output runs cmd and returns stdout, folding stderr into any error.
func output(cmd *exec.Cmd) (string, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		return "", errors.New("vaultctx not found; install it with 'brew install --cask moexx399/tap/vaultctx'")
	}
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("%s: %s", strings.Join(cmd.Args, " "), msg)
		}
		return "", fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return string(out), nil
}
