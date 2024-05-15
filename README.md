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
package manager.  You will need to edit its configuration file (eg in eXide),
you need to assign a password of your choice to the `exsaml` user and you
will need to modify the `controller.xql` file of your application to intercept
requests to be authenticated by SAML.

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
user. You also need to assign this password to `exsaml` user, see below.

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

### Set Password for the `exsaml` DB User

During installation of the existdb-saml package, a special DB user `exsaml`
gets created if it does not exist. This user will be created with a default
password (in order to not ship with a blank password).

You need to assign your chosen password as configured in file
`config-exsaml.xml` (tag `exsaml-creds/@pass`) to the `exsaml` DB user.

In EXide, you could do this by executing
`sm:passwd('exsaml', 'THE PASSWORD YOU CONFIGURED')`.

### Edit controller.xql of Your Application

You need to adjust the `controller.xql` of your application like this in order
to use SAML:

```xquery
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

## Using existdb-saml with Multiple Apps

Ignore this section if there is only a single eXist-db application that uses `existdb-saml`.

### History

`existdb-saml` was initially written to support SAML for a single eXist-db app. For this, the
`controller.xql` has to be edited to add SAML handling as shown in the example above. Effectively,
this application controls the use of SAML on this eXist-db host, because its `controller.xql`
implements the service provider endpoint that the IDP posts SAML authentication responses to.

It was possible to support SAML in a second application on the same eXist-db host, but this required
a somewhat arcane controller configuration in both the "leading" app that interacts with the SAML
IDP, and the second application that piggybacks on the "leading" app doing SAML transactions.
Also, it would only work if the two applications shared the same userbase.  It was not possible
to specify a user that is authenticated to only one app, but not the other.

`existdb-saml` v2 addresses this issue by introducing support for multiple authentication realms.

### Multiple Authentication Realms: Basic Concepts

The SAML IDP confirms that a certain username is authenticated. This username is mapped to
an eXist-db user that executes queries.

eXist-db applications can specify authentication contexts called "realms". A realm maps
an authenticated username to an eXist-db user with certain group membership, for a specific
app.

This way, multiple apps running on the same eXist-db server can authenticate against the
same SAML IDP, but still assign fine grained access control to their resources.

Configuration file `sso-users.xml` defines a list of recognized user names, the authentication
realms they are assigned to, and their group memberships for a specific realm. `existdb-saml`
will create the specified user as an eXist-db user (unless prohibited, see below).
It will login these users to eXist-db, and their group membership defines what these users can
read or write.

Access control is defined by group permissions of the installed application files. This is
usually specified by the `meta/permissions` element in file `repo.xml` of an application.

### On-Demand User Creation

`existdb-saml` is able to create eXist-db users dynamically if they do not exist yet, assigning
group membership as specified in configuration file `sso-users.xml`.

This is **disabled** by default, as user creation is not required for simple configurations.

Having some or all SAML-authenticated users created as eXist-db is required in the
following situations:

- for a single app, different user roles with different permissions are used (eg "read-only" vs.
  "read-write" users)
- multiple SAML-authenticated apps are used, and different users for different apps need
  different permissions
- an app requires eXist-db user, eg to keep user specific settings

In these cases, it is *recommended* to let `existdb-saml` create users dynamically by
setting `config/sso-users/@create-users="true"`.

Sites that want explicit control over eXist-db user creation may choose to leave this
disabled. The eXist-db exist must then be created by other means, with correct group
membership and a password that matches the passwords genereated by `existdb-saml` (HMAC
of SAML-authenticated user ID). This may get cumbersome. The examples below assume
`create-users=true` for simplicity.

### Multiple Authentication Realms: Configuration Examples

Scenario: ACME Org uses eXist-db for their data and SAML for authentication. ACME Org is
growing from a single project team to multiple project teams that each run their own
eXist-db application, and will need finer grained aces control for these apps.

#### Most Simple Use Case: Single Default Realm, Only Default User

This simple configuration would be used if there is only a single application that needs SAML
authentication, and all SAML-authenticated users share the same access privileges.
Because there is only one realm, the built-in default realm can be used (without having to
define a specific realm), and because all users share the same privileges, these privileges
can be assigned to the default user for that realm. This configuration is actually the
default in the configuration files shipped with `existdb-saml`.

File `config-exsaml.xml`, element `config/sso-users` looks like this (assuming `create-users=true`):
```
    <sso-users create-users="true" data="/db/apps/existdb-saml/content/sso-users.xml"
               default-realm="default-realm"/>
```

File `sso-users.xml` would look like this (setting group membership for all users to `acme`):
```
<sso-users>
    <user name="default-user" realm="default-realm" group="acme">
        <groups/>
    </user>
</sso-users>
```

To have an application (a Xar package) install files with the required permissions, it would use
a line like this in file `repo.xml` (note "group=acme, and mode allows read and write for group
members):
```
  <permissions user="acme" group="acme" password="somepassword" mode="rwxrwxr-x"/>
```

#### Use Case: Single App, but Multiple Roles for Different Users

In this use case, there is a single app "acme-reports" that allows read access to everyone, but
write access only to members of the `acme-editor` group.

For a single app, the built-in default realm may still be used, but it may make more sense to
choose meaningful realm names in the configuration. A realm name is just a string identifier.
in this example, the name of the app is used as the realm name, which improves readability of
the ``sso-users.xml` file.

File `config-exsaml.xml`, element `config/sso-users` gets changed to use default realm
`acme-reports` which happens to be the name of the single app.
```
    <sso-users create-users="true" data="/db/apps/existdb-saml/content/sso-users.xml"
               default-realm="acme-reports"/>
```

File `sso-users.xml` defines certain editor users in the `acme-reports` realm. These users
become members of the `acme-editors` group, and will have write permissions for the app data.
All other authenticated users for this realm are not specified, so they get mapped to the
default user for this realm. Note all user definition refer to realm "acme-reports".
```
<sso-users>
    <!-- users jack and jill are editors with write permissions, being a member of group
         "report-editors". They are also a member of the general "acme" group that everyone
         else is a member of. -->
    <user name="jack@example.org" realm="acme-reports" group="report-editors">
        <groups>
            <group>acme</group>
        </groups>
    </user>
    <user name="jill@example.org" realm="acme-reports" group="report-editors">
        <groups>
            <group>acme</group>
        </groups>
    </user>
    <!-- every other authenticated user is mapped to the default user for this realm.
         That means, member of the (read-only) "acme" group, but not member of the
         (read-and-write) "report-editors" group. -->
    <user name="default-user" realm="acme-reports" group="acme">
        <groups/>
    </user>
</sso-users>
```

The "acme-reports" app would install all documents owned by group "acme-reports". Only members
of this group are allowed to modify a document, while all other users may read them. The relevant
line in `repo.xml` of this app might look like:
```
  <permissions user="acme" group="report-editors" password="somepassword" mode="rwxrwxr-x"/>
```

#### Use Case: Two Different Apps, Disjunct User Groups

Extending the previous example, ACME Org establishes a new "acme-research" group in addition to
the "acme-reports" group. Both groups publish their data in their own apps named after their
groups.

File `sso-users.xml` defines 3 named users who have editor permissions for one or both apps.
As before, realms are named after the app they relate to.
```
<sso-users>
    <!-- user jack is an editor with write permissions for both "acme-reports" and
         "acme-research", being a member of both groups, and also the general "acme" group. -->
    <user name="jack@example.org" realm="acme-reports" group="report-editors">
        <groups>
            <group>acme</group>
        </groups>
    </user>
    <user name="jack@example.org" realm="acme-research" group="research-editors">
        <groups>
            <group>acme</group>
        </groups>
    </user>
    <!-- user jill is an editor with write permissions for "acme-reports", and member of the "acme" group. -->
    <user name="jill@example.org" realm="acme-reports" group="report-editors">
        <groups>
            <group>acme</group>
        </groups>
    </user>
    <!-- user james is an editor with write permissions for "acme-research", and member of the "acme" group. -->
    <user name="james@example.org" realm="acme-research" group="research-editors">
        <groups>
            <group>acme</group>
        </groups>
    </user>
    <!-- every other authenticated user is mapped to the default user for this realm.
         That means, member of the (read-only) "acme" group, but not member of the
         (read-and-write) "report-editors" group. -->
    <user name="default-user" realm="acme-reports" group="acme">
        <groups/>
    </user>
    <user name="default-user" realm="acme-research" group="acme">
        <groups/>
    </user>
</sso-users>
```

#### More Complex Use Cases

More complex use cases with finer grained control are possible, but that gets too
complex for this documentation. General recommendations:

- if you need to configure multiple realms, choose recognizable realm names. Using
  the app name for the realm name may be a good start;
- use the "default-user" concept where possible, so you only have to define users
  whose permissions deviate from the defaults;
- permissions are set **on the data**. eXist-db apps are expected to assign
  owner/group/permissions to the documents they install. The multi-realm mechanism
  only serves to assign group membership to a SAML authenticated user
  - a simple way to specify permissions is to use the `permissions` element in the
    `repo.xml` config file of the application, as shown in the examples above. This
    way, the specifed `user` and `group` get automatically created during app
    installation, and all documents have correct default permissions;
  - more complex scenarios could be set up from `post-install.xql` (creating
    additional groups or assigning specific permissions on selected documents)

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
                xquery="/db/apps/existdb-saml/content/clean-reqids.xql"
                cron-trigger="0 0 * * * ? *"/>
    </scheduler>
```
