xquery version "3.1";

import module namespace sm = "http://exist-db.org/xquery/securitymanager";

declare variable $saml-user-name := "exsaml";

(: Create the default 'exsaml' user account :)
if (fn:not(sm:user-exists($saml-user-name)))
then
  sm:create-account($saml-user-name, $saml-user-name, (), "existdb-saml", "existdb-saml-xquery SAML Authentication Account")
else()