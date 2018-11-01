xquery version "3.1";

(: the target collection into which the app is deployed :)
declare variable $target external;

sm:chmod(xs:anyURI($target||'/saml-request-ids'), 'rwx------')
