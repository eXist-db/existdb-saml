# TODO

* finalize and release v2.0.0

# Current Version

Version 2.0.0-RC1 (unreleased)

**Requires eXist-db 5.3.0 or higher.**

## Incompatible Changes

* Support for eXist-db versions before 5.3.0 has been dropped, along with the
  workarounds they required. The EXPath `crypto` package is now a hard dependency.
* The format of `sso-users.xml` changed: each `user` element now carries a
  `@realm` and a mandatory primary `@group`, with optional additional groups in
  a `groups` child element. Existing files must be migrated.
* Group membership derived from SAML attribute assertions was removed. Group
  membership is now assigned exclusively via `sso-users.xml`. The
  `<group-attribute>` config element is gone.
* Config option `crypto/@hmac-alg` was removed; the HMAC algorithm is fixed at
  HMAC-SHA-256.
* Config option `idp/@certfile` was removed. Signature validation is now
  controlled by `idp/@validate-signatures`.

## New Features

* [feature] support multiple authentication realms. Several applications on one
  eXist-db host can authenticate against the same SAML IDP while assigning
  distinct group membership, and therefore distinct permissions, per app. Adds
  `config/sso-users/@default-realm` and a two-argument
  `exsaml:build-authnreq-redir-url#2` taking an explicit realm; the
  single-argument form remains and uses the default realm.
* [feature] back up and restore `config-exsaml.xml` and `sso-users.xml` across
  package updates, so operator edits survive a reinstall.
* [feature] support the SAML `AssertionConsumerServiceIndex` attribute via
  `config/sp/@assertion-consumer-service-index`. If unset, an
  `AssertionConsumerServiceURL` holding the configured endpoint is sent instead.
* [feature] debug logging, enabled with `config/@debug="true"`. Log messages are
  correlated by SAML request ID.
* XML signature validation is enabled again after the 1.6.3 hotfix, and can be
  turned off with `idp/@validate-signatures="false"`.

## Fixes and Improvements

* [fix] ensure group membership for the primary group of an `sso-users.xml`
  record when the user account already exists.
* [fix] issued SAML request ID collection handling, including creation and
  permissions of the collection.
* [fix] privileged operations consistently go through `exsaml:suexec()`, run as
  the dedicated `exsaml` user.
* [fix] handle a missing or unreadable configuration file with a clear error
  instead of failing obscurely.
* [fix] correct the `controller.xql` example in the README; the if/else logic
  was wrong. Thanks to @adamretter for reporting.
* [fix] explicit type casts for integer comparisons, and correct use of value
  vs. general comparison operators throughout.
* [fix] serialize data for log output only when debug mode is enabled.
* [improve] declare internal functions private, add function return types, and
  use `xs:dateTime` rather than strings for date handling.
* [doc] document multi-realm configuration in the README.

# Previous Versions

## Version 1.6.3 (Jun 25 2021)

### New Features

### Fixes and Improvements

* [bugfix] add missing doc to set password for user exsaml
* [hotfix] disable XML signature validation until crypto-lib issues resolved
  Code that references a currently undefined crypto-lib function commented out
