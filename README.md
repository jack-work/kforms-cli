# kforms — CLI

A small CLI for [gluck-forms](https://github.com/jack-work/gluck-forms),
authenticated against [Authelia](https://auth.kelliher.info) via OIDC's
RFC 8628 device authorization flow, with the resulting refresh token
stored in the [hush](https://github.com/jack-work/hush) agent.

```
kforms login                             # RFC 8628 device flow → hush stores refresh
kforms whoami                            # who does the API think you are?
kforms create   -f rol.yaml              # POST /forms from a YAML file
kforms edit     <slug>                   # GET → $EDITOR (YAML) → PUT
kforms show     <slug>                   # pretty-print
kforms freeze   <slug>                   # POST /forms/<slug>/freeze
kforms list                              # GET /forms (tabwriter)
kforms mint     <slug> [--hint N] [--days D] [--uses U]
kforms tokens   <slug>                   # list SAS tokens
kforms revoke   <token-id>               # POST /tokens/<id>/revoke
kforms responses <slug> [--json]         # list responses
kforms response  <id>                    # one response as JSON
kforms fetch     <blob-id> [-o FILE]     # save a blob to disk
kforms logout
```

Sibling of [`gluck-todo-cli`](https://github.com/jack-work/gluck-todo-cli);
identical auth model.

## Auth model

1. `kforms login` calls Authelia's device authorization endpoint. Authelia
   returns a `user_code`; the CLI prints it and a verification URL. Open
   that URL on any device with a browser, authenticate, and confirm the
   user code.
2. Meanwhile the CLI polls the token endpoint; on approval it receives
   an access token + refresh token and hands both to hush's `OAuthRegister`.
   Hush persists the refresh token age-encrypted on disk.
3. On every API call the CLI asks hush for the current access token and
   sends it as `Authorization: Bearer <jwt>`. The API validates the JWT
   against Authelia's JWKS.
4. On a `401` the CLI calls `OAuthRefresh` on hush and retries once.
   If the refresh token itself is rejected, the CLI tells you to
   `kforms login` again.

## Prerequisites

- `hush up -d` running (the CLI will nag if it isn't).

## Configuration

Environment variables (all optional, sensible defaults):

| Var                 | Default                        |
|---------------------|--------------------------------|
| `KFORMS_API`        | `https://forms.kelliher.info`  |
| `KFORMS_ISSUER`     | `https://auth.kelliher.info`   |
| `KFORMS_CLIENT_ID`  | `kforms-cli`                   |
| `KFORMS_HUSH_NAME`  | `kforms`                       |
| `KFORMS_TOKEN`      | *(escape hatch; overrides hush)* |

## YAML form format

```yaml
slug: wfh-rol-2026
title: Wheeler-Farley House — Release of Liability
description: |
  You are signing a release of liability for our Oct 29 – Nov 1 stay
  at 149 Farley Lane, Tidioute, PA.
fields:
  - name: legal_name
    label: Legal name (as it should appear on the signed form)
    kind: short_text
    config: { max_length: 100 }
  - name: age_18
    label: I confirm I am 18 or older
    kind: checkbox
    config: { must_check: true }
  - name: email
    label: Email
    kind: email
  - name: phone
    label: Phone
    kind: phone
    required: false
  - name: agreed
    label: I have read and agree to the Release of Liability
    kind: checkbox
    config: { must_check: true }
  - name: signature
    label: Signature
    kind: signature
    config: { mode: both }
```

`required` defaults to `true`; only explicit `required: false` opts out.

## Building

```
go build ./...
# or, inside the flake:
nix develop
go build ./...
```

Note: `go.mod` currently pins `github.com/jack-work/hush` to a local
worktree via `replace`. Adjust that line if you're building outside
Jack's laptop.
