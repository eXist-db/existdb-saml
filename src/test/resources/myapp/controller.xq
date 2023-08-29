xquery version "3.1";

declare namespace exist = "http://exist.sourceforge.net/NS/exist";

(: import exsaml module :)
import module namespace exsaml = "http://exist-db.org/xquery/exsaml" at 'xmldb:///db/system/repo/existdb-saml-xquery-1.7.0-SNAPSHOT/modules/exsaml.xqm';

declare variable $exist:controller external;
declare variable $exist:path external;

(: this is required for SAML so that the IDP response can be rendered as a form
   that gets auto-submitted by the user's browser, back to the SP (eXist) :)
declare option exist:serialize "method=html media-type=text/html indent=no";

(: handle SP endpoint to process SAML response in HTTP POST :)
if ($exist:path = "/SAML2SP")
then
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

(: if logout, invalidate SAML token :)
else if ($exist:path = '/logout')
then
    let $_ :=
            if (exsaml:is-enabled())
            then
                exsaml:invalidate-saml-token()
            else ()
    return
        <dispatch xmlns="http://exist.sourceforge.net/NS/exist">
            <redirect url="https://www.evolvedbinary.com"/>
        </dispatch>

(: if no valid token, redirect to SAML auth :)
else if (exsaml:is-enabled() and not(exsaml:check-valid-saml-token()))
then
    let $debug := exsaml:log('info', "controller: no valid token, redirect to SAML auth")
    let $return-path := "/exist/apps" || $exist:controller || $exist:path
    return
        <dispatch xmlns="http://exist.sourceforge.net/NS/exist">
            <redirect url="{exsaml:build-authnreq-redir-url($return-path)}">
                <set-header name="Cache-Control" value="no-cache, no-store" />
                <set-header name="Pragma" value="no-cache" />
            </redirect>
        </dispatch>

(: We have an existing valid SAML token! :)
else
    <ignore xmlns="http://exist.sourceforge.net/NS/exist">
      <cache-control cache="no"/>
    </ignore>
