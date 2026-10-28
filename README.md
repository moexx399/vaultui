# vault-user-policies

A terminal UI that answers "what can this person do in Vault?". Pick a Vault
context, enter an email or username, and browse every path the user's group
policies declare, with the rules for each path and the policies and groups
they come from.

```text
 Vault: prd-cloud (https://vault.example.com)
 Email: (not supplied) | Username: wilsseb
 Entity: jane (ebfbb456-534b-f307-8aab-872380c9bc94)
 Aliases: WILSSEB [auth/userpass/]
 Groups (2): devs (direct), eng (inherited)

 Path > trans                                                          1/4
 ▌ transit/encrypt/app  jane
 ╭─────────────────────────────────────────────────────────────────────────╮
 │ Path: transit/encrypt/app                                               │
 │ RULE 1                                                                  │
 │ capabilities = ["update"]                                               │
 │ allowed_parameters = { "plaintext" = [] }                               │
 │ Sources:                                                                │
 │   eng: eng                                                              │
 ╰─────────────────────────────────────────────────────────────────────────╯
```

Entities match when their name or any alias name equals the email or username
(case-insensitive). For each entity it reads the ACL policies attached to its
groups (direct and inherited) and:

- **Path browser** — every declared path, fuzzy-filtered as you type, with a
  preview of each distinct rule for that path and its source policies and groups.
- **Full report** (`ctrl+r`) — the groups and memberships, then the policies'
  path declarations with identical permission bodies merged into permission
  sets (`P1`, `P2`, … identify the source policies).

This shows **declarations, not effective access**: login/token and
entity-attached policies, Sentinel and namespace controls are not included,
and Vault's path priority, deny rules and templates still apply. HCL and JSON
policies are parsed; any policy with other syntax is shown in full as
"unconsolidated", and policies that cannot be read are flagged as incomplete.

## Install

```bash
brew tap moexx399/tap
brew trust --cask moexx399/tap/vault-user-policies   # Homebrew 6+ requires trusting non-official taps
brew install --cask vault-user-policies
```

This also installs [vaultctx](https://github.com/moexx399/vaultctx), which
provides the Vault contexts and logins. Add your contexts with `vaultctx add`
first.

Or with Go: `go install github.com/moexx399/vault-user-policies@latest` (and
install vaultctx separately).

## Usage

```text
vault-user-policies [--context NAME] [--email EMAIL] [--username USER]
```

Without flags it opens a context picker. Picking a context reuses its cached
vaultctx token, or runs `vaultctx login` in the terminal when there is none;
it never changes your active vaultctx context. With `--context` it skips the
picker, and with `--email`/`--username` too it searches straight away.

The token needs `list` on `identity/entity/id` and `read` on
`identity/entity/id/*`, `identity/group/id/*` and `sys/policies/acl/*`.

| Screen  | Keys |
|---------|------|
| Context | `↑`/`↓` move, `/` filter, `enter` connect, `q` quit |
| Search  | `tab` switch field, `enter` search, `esc` change context |
| Paths   | type to filter, `↑`/`↓`/`PgUp`/`PgDn` select, `ctrl+d`/`ctrl+u` scroll preview, `ctrl+r` full report, `ctrl+n` new search, `ctrl+t` change context, `esc` quit |
| Report  | `↑`/`↓`/`PgUp`/`PgDn` scroll, `esc`/`ctrl+r` back to paths |

### tmux popup

```tmux
# prefix + u: browse a Vault user's group policies
bind-key u display-popup -E -w 95% -h 95% vault-user-policies
```
