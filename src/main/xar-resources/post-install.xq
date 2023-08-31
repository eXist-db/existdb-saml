xquery version "3.1";

import module namespace sm = "http://exist-db.org/xquery/securitymanager";
import module namespace xmldb = "http://exist-db.org/xquery/xmldb";

(: the target collection into which the app is deployed :)
declare variable $target external;

declare variable $saml-user-name := "${exist.saml.username}";
declare variable $saml-request-ids-collection-name := "saml-request-ids";
declare variable $saml-request-ids-collection-path := $target || "/" || $saml-request-ids-collection-name;
declare variable $saml-request-ids-collection-uri := xs:anyURI($saml-request-ids-collection-path);

let $_ :=
    if (fn:not(xmldb:collection-available($saml-request-ids-collection-path)))
    then
      xmldb:create-collection($target, $saml-request-ids-collection-name)
    else()
return
    let $_ := sm:chmod($saml-request-ids-collection-uri, "rwxr-x---")
    return
        sm:chown($saml-request-ids-collection-uri, $saml-user-name || ":" || $saml-user-name)
