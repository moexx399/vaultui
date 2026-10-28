# vaultui

A terminal UI for HashiCorp Vault, built on the contexts you manage with
[vaultctx](https://github.com/moexx399/vaultctx). It opens a menu of functions:

| Function             | What it does |
|----------------------|--------------|
| `user-policies`      | Find a user's identities and groups, and browse the paths their group policies declare |
| `replication-status` | DR and performance replication topology, WAL lag, node health and TLS for every vaultctx context |

Functions that act as you (user-policies) ask for a context and log in if
needed, reusing vaultctx's cached tokens. replication-status uses only
unauthenticated endpoints, so it needs no login.

## user-policies

Answers "what can this person do in Vault?". Enter an email or username and
browse every path the user's group policies declare, with the rules for each
path and the policies and groups they come from.

```text
 Vault: prd-cloud (https://vault.example.com)
 Email: (not supplied) | Username: moexx399
 Entity: jane (ebfbb456-534b-f307-8aab-872380c9bc94)
 Aliases: moexx399 [auth/userpass/]
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

## replication-status

Checks every vaultctx context's address (contexts reaching the same cluster
are merged) without logging in, using `sys/health`, `sys/replication/status`
and the TLS handshake:

- **Contexts**: the node each address reaches. Anything but the active node
  (standby, DR secondary, performance standby) is a warning; sealed or
  uninitialized is critical.
- **DR and performance replication**: each primary with its secondaries as a
  tree, with state, connection, WAL position and lag (warn at 100 entries,
  critical at 1000), and the primary's link record (heartbeat, clock skew,
  canary age). Secondaries are linked to primaries by replication cluster ID,
  so contexts may point at load-balancer aliases. Secondaries the primary
  reports but no context reaches are listed as not queried.
- **Unreachable** contexts and **TLS certificates** (expiry warns at 30 days,
  critical at 7; a certificate that differs from the rest of the topology is
  critical).

Clusters linked by replication form a topology; each is a tab with a health
dot, named after its primary.

| Keys | |
|------|-|
| `←`/`→`, `n`/`p`, `tab` | previous/next topology |
| `1`-`9` | jump to a topology |
| `↑`/`↓`/`PgUp`/`PgDn` | scroll |
| `r` | refresh |
| `a` | show every topology on one page |
| `esc` / `q` | back to the menu / quit |

```text
vaultui replication-status [--page CONTEXT] [--watch 30s] [--timeout 10s] [--no-tls]
```

`--page` opens the topology containing a context; `--watch` refreshes on an
interval.

## Install

```bash
brew tap moexx399/tap
brew trust --cask moexx399/tap/vaultui   # Homebrew 6+ requires trusting non-official taps
brew install --cask vaultui
```

This also installs [vaultctx](https://github.com/moexx399/vaultctx), which
provides the Vault contexts and logins. Add your contexts with `vaultctx add`
first.

Or with Go: `go install github.com/moexx399/vaultui@latest` (and install
vaultctx separately).

## Usage

```text
vaultui [--context NAME]                  open the menu
vaultui [--context NAME] FUNCTION [flags] go straight to a function
vaultui user-policies [--email EMAIL] [--username USER]
vaultui replication-status [--page CONTEXT] [--watch 30s]
```

For user-policies, picking a context reuses its cached vaultctx token, or
runs `vaultctx login` in the terminal when there is none; it never changes
your active vaultctx context. `--context` skips the picker, and `--email` or
`--username` searches straight away.

`esc` goes back a level (for example results → search → menu); `c` in the
menu changes context; `ctrl+c` quits.

| Screen        | Keys |
|---------------|------|
| Menu, context | `↑`/`↓` move, `/` filter, `enter` choose, `c` change context (menu), `esc` back |
| Search        | `tab` switch field, `enter` search |
| Paths         | type to filter, `↑`/`↓`/`PgUp`/`PgDn` select, `ctrl+d`/`ctrl+u` scroll preview, `ctrl+r` full report |
| Report        | `↑`/`↓`/`PgUp`/`PgDn` scroll, `esc`/`ctrl+r` back to paths |

The token needs `list` on `identity/entity/id` and `read` on
`identity/entity/id/*`, `identity/group/id/*` and `sys/policies/acl/*` for
user-policies.

### tmux popup

```tmux
# prefix + u: browse a Vault user's group policies
bind-key u display-popup -E -w 95% -h 95% 'vaultui user-policies'
# prefix + v: replication status of every vaultctx context
bind-key v display-popup -E -w 95% -h 95% 'vaultui replication-status'
```
