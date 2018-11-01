# existdb-saml - SAML v2.0 Implementation in XQuery

**NOTE** You will need **eXist v4.4 or higher** to run this code (a required
compression function has been added in that release).

## Overview

This is a partial implementation of SAML v2.0 in XQuery that allows eXist DB
to delegate authentication to a third-party identity provider using SAML.

The current implementation supports the SAML2 Web Browser SSO Profile with
- SP-initiated SSO Redirect-POST
- IDP-initiated SSO POST

For details on the SAML profiles see https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf

This code is considered stable and production-ready. A slightly earlier
version of this code runs in production on a large site, interfacing with a
"PingFederate" SAML IDP installation.

This code passed auditing and pen-testing by a third party on behalf of the
customer.

## How to use (in simple terms)

You have an application running on eXist. In SAML terminology, this is the
service provider (SP), because the eXist DB service provides access to data.

You don't want to manage users and passwords with eXist, possibly because you
expect a high number of users.  Instead, you want to delegate user 
authentication to a third party, the identity provider (IDP) in SAML terms.

Basically, the IDP is responsible for keeping user/password data and handling
client authentication. Effectively, the IDP presents a username/password
dialog, authenticates a user, and then presents a SAML assertion "this user
has successfully authenticated" to the SP.

Consider a sports event and you're heading to your seats in block B-52. The
gatekeeper tells you that your ticket is not valid yet, please go to the IDP
counter and login to get a valid ticket, then come back and get access. In
SAML terms, this is "SP-initiated SSO", because clients access your resources
(eXist DB, service provider), and your application gatekeeper redirects clients
to the IDP, which sends them back after authentication.

A variation of this is "IDP-initiated SSO POST" where an IDP actively sends a
client to some SP resource, as in "give this authenticated user access to
resource /X". In the sports event analogy these are comparable to sponsored
VIP lounge tickets issued by the IDP, to bypass the SP crowd.

## How to use (in technical terms)

Existdb-saml is an application library that can be added through the eXist
package manager.  You will need to edit its configuration file (eg in eXide)
and and you will need to modify the `controller.xql` file of your application
to intercept requests to be authenticated by SAML.

### Exchange peering data with IDP

The SAML protocol requires that both peers (SP and IDP) present and validate
the identity of each other. Also, each peer needs to know the URI endpoint of
the other side to redirect clients correctly.

It is quite common that SAML responses from the IDP are signed using XML
signature. The SAML standard mandates to validate XML signatures if they are
present. In order to do this you need the X.509 certificate file from the IDP
containing the public key needed to validate the signatures.

### Edit config-exsaml.xml file

In the `<config>` element, set the `enabled` attribute to `true` to enable
SAML.

In the `<sp>` element, set your entity name (a namestring in URI format) and
your endpoint URI (handled by your `controller.xql` file.
`fallback-relaystate` is only relevant if IDP-initiated SSO is enabled, it is
the default landing page if an IDP-initiated SSO does not specify where the
client should go.

In the `<idp>` element, set the `entity` name and `endpoint` URI that was
provided by your IDP peer. If the IDP sends XML signed responses, specify
`certfile` with the path to the X.509 certificate.
To enable IDP-initiated SSO (default off) set `accept-unsolicited` to true. To
force IDP-initiated clients to a certain URI, specify this URI in
`force-relaystate`.
`verify-issuer` can be turned off to disable issuer verification mandated by
the SAML standard. This was required to deal with a misconfigured IDP peer.

In the `<crypto>` element, set a unique password in `hmac-key`.

In the `<token>` element, set `valid-mins` to the desired token validity time
in minutes. After successful SAML authentication, a token is set in the user's
browser, effectively caching authentication credentials. If the token has
expired, another SAML roundtrip will happen between SP and IDP.

In the `<exsaml-creds>` element, set a password for the privileged `exsaml`
user.

If you need to store user specific settings such as the preferred language,
you may want to set `create` to `true` in the `<dynamic-users>` element. By
default, users are not created in eXist DB because usernames and passwords
are kept at the IDP.

A SAML IDP may send additional data as SAML attribute assertions, e.g. to
assign group membership for an authenticated user, as shown in the
`<group-attribute>` element. Note this only works if the IDP is configured
to send these attributes.

The `<fake-idp>` element may be used for debugging if no "real" IDP is 
available yet. This element should be empty for production use.

### Edit controller.xql of Your Application

You need to adjust the `controller.xql` of your application like this in order
to use SAML:

```
(: import exsaml module :)
import module namespace exsaml="http://exist-db.org/xquery/exsaml" at 'xmldb:///db/apps/existdb-saml/content/exsaml.xqm';

(: this is required for SAML so that the IDP response can be rendered as a form
   that gets auto-submitted by the user's browser, back to the SP (eXist) :)
declare option exist:serialize "method=html media-type=text/html indent=no";

(: if no valid token, redirect to SAML auth :)
if (exsaml:is-enabled() and not(exsaml:check-valid-saml-token()))
then (
    let $debug := exsaml:log('info', "controller: no valid token, redirect to SAML auth")
    let $return-path := "/exist/apps" || $exist:controller || $exist:path
    return
        <dispatch xmlns="http://exist.sourceforge.net/NS/exist">
            <redirect url="{exsaml:build-authnreq-redir-url($return-path)}">
                <set-header name="Cache-Control" value="no-cache, no-store" />
                <set-header name="Pragma" value="no-cache" />
            </redirect>
        </dispatch>
    )

(: if logout, invalidate SAML token :)
else if ($exist:path = '/logout')
then (
    if (exsaml:is-enabled())
    then exsaml:invalidate-saml-token()
    else ()
    ,
    <dispatch> ... </dispatch>
    )

(: handle SP endpoint to process SAML response in HTTP POST :)
else if($exist:path = "/SAML2SP")
then (
    let $log := util:log('info', "SAML2SP: processing SAML response")
    let $status := exsaml:process-saml-response-post()
    let $log := util:log('debug', "endpoint SAML2SP; status: " || $status/@code)
    return
        if ($status/@code >= 0) then
            (: forward to page that was requested by the user :)
            let $debug := util:log("info", "Auth success - code " || $status/@code || " - relaystate: " || $status/@relaystate)
            return
                <dispatch xmlns="http://exist.sourceforge.net/NS/exist">
                    <redirect url="{$status/@relaystate}"/>
                </dispatch>
        else
            (: if SAML failed, display an error message for now :)
            <data>{string($status/@msg) || ": " || string($status/@data)}</data>
)

else (
    (: your controller code here :)
)
```

## Misc

### Security

See doc/SECURITY_ASSESSMENT for details.

### Handling of SAML request IDs

The SAML standard requires that the SP checks SAML responses from the IDP such
that the request ID that the SAML response refers to was actually sent by the
SP. To do this, the SP needs to keep a collection of request IDs that it sent.
When the IDP sent a SAML response, the SP will remove the correspondig request
ID from this collection.

There may be (error) conditions where a request never gets a response, so that
the request ID stays in the collection forever. For this reason, the
`clean-reqids.xql` XQuery should be run periodically as a scheduled job to
purge outdated request IDs. Use something like this in `conf.xml`.

```
    <scheduler>
        <job    type="user"
                name="clean-up-sso-reqids"
                xquery="/db/apps/existdb-saml/content/clean-reqids.xql"
                cron-trigger="0 0 * * * ? *"/>
    </scheduler>
```
