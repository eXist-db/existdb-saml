xquery version "3.1";

import module namespace sm = "http://exist-db.org/xquery/securitymanager";

(: the target collection into which the app is deployed :)
declare variable $target external;

declare variable $saml-request-ids-collection-name := "saml-request-ids";
declare variable $saml-request-ids-collection-path := $target || "/" || $saml-request-ids-collection-name;

sm:chmod(xs:anyURI($saml-request-ids-collection-path), "rwx------")