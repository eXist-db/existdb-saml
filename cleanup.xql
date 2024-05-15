xquery version "3.1";

declare namespace sm="http://exist-db.org/xquery/securitymanager";

(: TODO: $target is not set in cleanup phase :)
declare variable $configuration-collection := "/db/apps/existdb-saml/content/";
declare variable $backup-collection := "/db/exsaml-backup/"; 
declare variable $configuration-filename := "tuttle.xml";

(: backup existdb-saml configuration :)
if (not(xmldb:collection-available($backup-collection)))
then ((: move/copy to collection :)
    util:log("info", "Creating configuration backup collection"),
    xmldb:create-collection("/db", "exsaml-backup"),
    sm:chmod(xs:anyURI($backup-collection), "rwxr-x---")
)
else ()
,
util:log("info", "Backing up configuration"),
xmldb:move($configuration-collection, $backup-collection, 'config-exsaml.xml'),
xmldb:move($configuration-collection, $backup-collection, 'sso-users.xml')
