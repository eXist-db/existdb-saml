# existdb-saml - SAML V2.0 Implementation in XQuery for eXist-db

**NOTE** You will need **eXist-db version 6.0.1 or higher** to run this code.

## Overview

This is a partial implementation of OASIS [SAML V2.0](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) in XQuery for eXist-db that allows eXist-db to act as an SP (Service Provider) and delegate authentication to a third-party IdP (Identity Provider).

This implementation provides the following bindings of the [Web Browser SSO Profile](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.Web%20Browser%20SSO%20Profile|outline):
1. [SP-Initiated SSO: Redirect/POST Bindings](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.2.SP-Initiated%20SSO:%20%20Redirect/POST%20Bindings|outline)
2. [IdP-Initiated SSO: POST Binding](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.4.IdP-Initiated%20SSO:%20%20POST%20Binding|outline)

This library may be useful when you have an XQuery application running atop eXist-db where you need users to authenticate with a 3rd-party provider.


## Introduction

In SAML parlance:

1. SP (Service Provider) is Your Application.
    
    Your application running atop eXist-db is known as the SP (Service Provider); due to the fact that it provides some sort of "service" to one or more 3rd-party users and/or applications (User Agents).

2. IdP (Identity Provider) performs the Authentication (e.g. Microsoft, Google, etc.).

    A separate 3rd-party (trusted by both yourself and the 3rd-party user/application), that provides an authentication service to your application is known as the IdP (Identity Provider); due to the fact that they establish the identity of the 3rd-party User Agent (by some form of authentication and possibly authorization).

### SP-Initiated SSO

This is typically the most common approach. If you are new to configuring a SAML system, we recommend that you focus on this approach first.

When using this approach the sequence of events that happen are as follows:

1. The User Agent visits your application (i.e. SP)
2. The SP (i.e. your application) checks if the User Agent already has access (i.e. recently already authenticated with IdP), if so it supplies the service to the User Agent. Else...
3. The SP provides an SAML Authn request to the User Agent, and tells them to redirect their SAML Authn request to the IdP
4. The User Agent sends their SAML Authn request to the IdP
5. The IdP validates the SAML Authn request. If it is invalid the User agent is notified, Else...
6. The IdP challenges the User Agent for their credentials (e.g. Username and Password)
7. The 3rd-party User Agent provides their credentials to the IdP
8. The Idp validates the User Agent credentials. If authentication is unsuccessful, the User Agent is notified. Else...
9. The IdP provides a SAML Response to the User Agent, an an HTML Form.
10. The User Agent submits the HTML form, thus sending the SAML Response to the SP.
11. The SP validates the SAML Response. If the SAML Response is invalid, the User Agent is notified. Else...
12. The SP supplies the service to the User Agent.

![Diagram of SP-Initiated SSO Flow Chart](https://raw.githubusercontent.com/eXist-db/existdb-saml/master/doc/sp-initiated-sso-flow-chart.png)

### IdP-initiated SSO

**TODO**

A variation of this is "IDP-initiated SSO POST" where an IDP actively sends a
client to some SP resource, as in "give this authenticated user access to
resource /X". In the sports event analogy these are comparable to sponsored
VIP lounge tickets issued by the IDP, to bypass the SP crowd.

## How to Deploy

existdb-saml is an application library that can be added through the eXist-db Dashboard's Package Manager, or downloaded from the [eXist-db EXPath Package Repository](https://exist-db.org/exist/apps/public-repo/)

In basic terms you will need to undertake 3 steps:

1. Assign a password of your choice to the `exsaml` user.
2. Edit the existdb-saml configuration file (`/db/apps/existdb-saml/config-exsaml.xml`).
3. Modify the URL Rewrite Controller (`controller.xq`) file of your application to intercept requests to be authenticated by existdb-saml.

### Exchange peering data with IDP

The SAML protocol requires that both peers (SP and IDP) present and validate
the identity of each other. Also, each peer needs to know the URI endpoint of
the other side to redirect clients correctly.

It is quite common that SAML responses from the IDP are signed using XML
signature. The SAML standard mandates to validate XML signatures if they are
present. In order to do this you need the X.509 certificate file from the IDP
containing the public key needed to validate the signatures.

### 1. Set the password for the `exsaml` DB User

During installation of the existdb-saml package, a special DB user named `exsaml` gets created if it does not already exist. This user will be created with a default password.

You need to choose a reasonable password for the `exsaml` user, and then set that as the user's password. The following XQuery when executed will perform such a task:
```xquery
sm:passwd('exsaml', 'YOUR PASSWORD HERE')
```

### 2. Edit the `config-exsaml.xml` file

In the `<config>` element, set the `enabled` attribute to `true` to enable
SAML.

In the `<sp>` element, set your entity name (a namestring in URI format) and
your endpoint URI (handled by your `controller.xq` file.
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

In the `<exsaml-creds>` element, set the password for the privileged `exsaml` user that you previously chose.

If you need to store user specific settings such as the preferred language,
you may want to set `create` to `true` in the `<dynamic-users>` element. By
default, users are not created in eXist-db because usernames and passwords
are kept at the IDP.

A SAML IDP may send additional data as SAML attribute assertions, e.g. to
assign group membership for an authenticated user, as shown in the
`<group-attribute>` element. Note this only works if the IDP is configured
to send these attributes.

The `<fake-idp>` element may be used for debugging if no "real" IDP is 
available yet. This element should be empty for production use.

### 3. Edit the `controller.xq` of Your Application

You need to adjust the `controller.xq` of your application like this in order
to use SAML:

```xquery
(: import exsaml module :)
import module namespace exsaml="http://exist-db.org/xquery/exsaml" at 'xmldb:///db/system/repo/existdb-saml/content/exsaml.xqm';

(: this is required for SAML so that the IDP response can be rendered as a form
   that gets auto-submitted by the user's browser, back to the SP (eXist) :)
declare option exist:serialize "method=html media-type=text/html indent=no";

declare variable $cid := exsaml:generate-correlation-id();

(: handle SP endpoint to process SAML response in HTTP POST :)
if ($exist:path = "/SAML2SP")
then
    let $log := exsaml:log('info', $cid, "SAML2SP: processing SAML response")
    let $status := exsaml:process-saml-response-post()
    let $log := exsaml:log('debug', $cid, "endpoint SAML2SP; status: " || $status/@code)
    return
        if ($status/@code >= 0) then
            (: forward to page that was requested by the user :)
            let $debug := exsaml:log("info", $cid, "Auth success - code " || $status/@code || " - relaystate: " || $status/@relaystate)
            return
                <dispatch xmlns="http://exist.sourceforge.net/NS/exist">
                    <redirect url="{$status/@relaystate}"/>
                </dispatch>
        else
            (: if SAML failed, display an error message for now :)
            <data cid="{$cid}">{string($status/@msg) || ": " || string($status/@data)}</data>

(: if logout, invalidate SAML token :)
else if ($exist:path = '/logout')
then
    let $_ :=
            if (exsaml:is-enabled($cid))
            then
                exsaml:invalidate-saml-token($cid)
            else ()
    return
        <dispatch> ... </dispatch>

(: if no valid token, redirect to SAML auth :)
else if (exsaml:is-enabled($cid) and not(exsaml:check-valid-saml-token($cid)))
then
    let $debug := exsaml:log('info', $cid, "controller: no valid token, redirect to SAML auth")
    let $return-path := "/exist/apps" || $exist:controller || $exist:path
    return
        <dispatch xmlns="http://exist.sourceforge.net/NS/exist">
            <redirect url="{exsaml:build-authnreq-redir-url($cid, $return-path)}">
                <set-header name="Cache-Control" value="no-cache, no-store" />
                <set-header name="Pragma" value="no-cache" />
            </redirect>
        </dispatch>

else
    (: your controller code here :)
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

```xml
    <scheduler>
        <job    type="user"
                name="clean-up-sso-reqids"
                xquery="/db/system/repo/existdb-saml/content/clean-reqids.xql"
                cron-trigger="0 0 * * * ? *"/>
    </scheduler>
```
