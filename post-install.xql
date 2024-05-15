xquery version "3.1";

declare namespace sm="http://exist-db.org/xquery/securitymanager";

import module namespace exsaml="http://exist-db.org/xquery/exsaml" at "/db/apps/existdb-saml/content/exsaml.xqm";

(: the target collection into which the app is deployed :)
declare variable $target external;

declare variable $configuration-collection := $target || "/content/";
declare variable $backup-collection := "/db/exsaml-backup/";
declare variable $configuration-filename := "config-exsaml.xml";
declare variable $users-filename := "sso-users.xml";

(: look for backed up existdb-saml configuration :)
if (doc-available($backup-collection || $configuration-filename))
then ((: move/copy to collection :)
    util:log("info", "Restoring existdb-saml configuration from backup."),
    xmldb:move($backup-collection, $configuration-collection, $configuration-filename)
)
else (),
(: look for backed up sso-users configuration :)
if (doc-available($backup-collection || $users-filename))
then ((: move/copy to collection :)
    util:log("info", "Restoring sso-users configuration from backup."),
    xmldb:move($backup-collection, $configuration-collection, $users-filename)
)
else (),
if (xmldb:collection-available($backup-collection))
then (
    xmldb:remove($backup-collection)
)
else ()
,
(: tighten security for configuration file :)
sm:chmod(xs:anyURI($configuration-collection || $configuration-filename), "rw-r-----")
,
exsaml:ensure-authnreqid-collection()
