# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A SAML v2.0 Service Provider implemented purely in XQuery, packaged as an eXist-db
application library (XAR). It lets an eXist-db app delegate authentication to a
remote SAML identity provider (IDP). Supports the SAML2 Web Browser SSO Profile:
SP-initiated SSO Redirect-POST and IDP-initiated SSO POST.

Requires eXist-db >= 5.3.0 and the EXPath `crypto` package (`http://expath.org/ns/crypto`).

## Build / deploy

```sh
ant              # default target "xar" -> build/existdb-saml-<version>.xar
ant clean
```

There is no test suite, no linter, and no CI. Verification is manual: install the
XAR via the eXist-db package manager (Dashboard) and exercise the flow. For local
testing without a real IDP, enable the `<fake-idp>` element in
`content/config-exsaml.xml` and point `idp/@endpoint` at the local `/SAML2IDP`
route (see the `controller.xql` example in README.md).

The authoritative version is `build.properties.xml` (`app/version`) — that is what
the build stamps into the package metadata. `VERSION.txt` duplicates it, is read by
nothing, and must be bumped by hand on release. `expath-pkg.xml` and `repo.xml` are
generated at build time from the `.tmpl` files via Ant token filtering, so edit
the templates, never the generated files.

## Architecture

Everything of substance is `content/exsaml.xqm` (~700 lines, module namespace
`http://exist-db.org/xquery/exsaml`). The rest of the repo is packaging,
configuration, and install lifecycle.

### Integration contract with consuming apps

The library has no controller of its own — the *consuming application's*
`controller.xql` is the SP endpoint and gatekeeper. It must:

1. route POSTs to `/SAML2SP` into `exsaml:process-saml-response-post()`, then
   redirect to `@relaystate` on success (`@code >= 0`);
2. guard every protected route with
   `exsaml:is-enabled() and not(exsaml:check-valid-saml-token())` → redirect to
   `exsaml:build-authnreq-redir-url($return-path, $realm)`;
3. call `exsaml:invalidate-saml-token()` on logout.

README.md holds the canonical example. This means a misconfigured controller,
not a bug in this module, is the likeliest cause of "resources readable without
auth" — see `doc/SECURITY_ASSESSMENT` §2.

### Request flow

- **Outbound**: `build-authnreq-redir-url` → `build-saml-authnreq` builds
  `samlp:AuthnRequest`, stores its ID (see below), deflates + base64 + urlencodes
  it into the IDP redirect URL. The realm is smuggled to the response side by
  prefixing RelayState as `"<realm>#<relaystate>"`.
- **Inbound**: `process-saml-response-post` → `validate-saml-response` →
  `validate-saml-assertion` is a single `if/else if` chain returning an
  `exsaml:funcret` with a numeric `@res`. **Negative `@res` means failure,
  zero-or-positive means success** — this convention propagates out to the
  controller as `authresult/@code`. On success: optionally create the DB user,
  `xmldb:login()` as that user, and set the session token.

### Three things that carry state

1. **Session token** — `nameid=validTo=HMAC-SHA-256(nameid=validTo, hmac-key)`,
   stored as a session attribute (`token/@name`). Its lifetime (`token/@valid-mins`)
   is how long eXist trusts a SAML assertion before another IDP roundtrip.
   Logout works by re-issuing a token with a 1970 expiry.
2. **Issued request IDs** — `/db/apps/existdb-saml/saml-request-ids`, one doc per
   AuthnRequest ID, mode `rwx------` owned by `exsaml`. Required by the SAML spec
   to reject responses to requests we never sent; the doc is deleted on
   consumption. Stale IDs are purged by `content/clean-reqids.xql` (> 1h old),
   which must be scheduled as a cron job — see `content/scheduler.xql` and README.
3. **Local DB users** — created on demand (only when `sso-users/@create-users` is
   `"true"`) with password `HMAC(nameid, hmac-key)`, which is also how login
   happens for pre-existing users. Consequence: **changing `crypto/@hmac-key`
   invalidates every existing DB user's password**, not just live tokens.

### Privilege escalation

All `sm:*` and reqid-collection operations run through `exsaml:suexec`, which
wraps `system:as-user($exsaml-user, $exsaml-pass, fn:apply(...))` using the
credentials in `exsaml-creds`. The dedicated `exsaml` dba user is created at
install time with a default password; the operator must run
`sm:passwd('exsaml', ...)` to match `exsaml-creds/@pass`. If those two ever
disagree, everything requiring `suexec` fails.

### Realms (v2 feature)

`content/sso-users.xml` maps an authenticated `nameid` + realm → primary group
and additional groups, so several apps on one eXist-db host can share an IDP with
distinct permissions. Lookup falls back to the `default-user` entry for that
realm. Groups are **not** auto-created; access control itself comes from document
permissions (typically `repo.xml`'s `<permissions>` in the consuming app), not
from this file.

## Configuration lifecycle (easy to break)

`content/config-exsaml.xml` and `content/sso-users.xml` are live, operator-edited
files shipped with defaults. `cleanup.xql` (uninstall/upgrade) moves both to
`/db/exsaml-backup/`; `post-install.xql` moves them back and chmods the config to
`rw-r-----`. When adding or renaming a config file, both scripts must be updated
in lockstep. Note `cleanup.xql` has a leftover `$configuration-filename :=
"tuttle.xml"` variable that is unused but misleading.

`exsaml.xqm` resolves `config-exsaml.xml` and `../expath-pkg.xml` by *relative*
path, so the module only works when deployed at its expected location; the
`saml-request-ids` base path is hardcoded to `/db/apps/existdb-saml`.

## Conventions

- Logging goes through `exsaml:log($level, $msg)` / `exsaml:log($level, $id, $msg)`
  and `exsaml:debug(...)` (the latter is a no-op unless `config/@debug="true"`).
  Always pass the SAML request ID as the correlation `$id` where one exists.
- Side effects are threaded through throwaway `let $log := ...` / `let $debug := ...`
  bindings; conditions sometimes use `and exsaml:log(...)` to log inside a branch
  test. Match this style rather than restructuring it.
- Config values are read once into `%private` module variables at import time.
  Config edits require the module to be re-imported to take effect.
