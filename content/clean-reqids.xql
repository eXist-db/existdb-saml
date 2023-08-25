xquery version "3.1";

import module namespace exsaml = "http://exist-db.org/xquery/exsaml" at "/db/system/repo/existdb-saml/content/exsaml.xqm";
import module namespace functx = "http://www.functx.com";

declare function local:clean-reqids() {
    let $reqid-col := "/db/system/repo/existdb-saml/saml-request-ids"
    let $reqids := for $reqid in collection($reqid-col)/reqid
                        let $duration := xs:dateTime(current-dateTime()) - xs:dateTime($reqid)
                        return
                            if(functx:total-hours-from-duration($duration) > 1)
                                then (
                                    let $resource-name := util:document-name($reqid)
                                    let $delete := xmldb:remove($reqid-col, $resource-name)
                                    return
                                        <deleted>{$resource-name}</deleted>
                                )
                                else ()

    return
        <reqids count="{count(collection($reqid-col)/reqid)}" deletet="{count($reqids)}">
            {$reqids}
        </reqids>

};

system:as-user($exsaml:exsaml-user, $exsaml:exsaml-pass,local:clean-reqids())

