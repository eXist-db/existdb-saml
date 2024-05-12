xquery version "3.1";

module namespace exsaml="http://exist-db.org/xquery/exsaml";

(: namespace declarations for building SAML nodes :)
declare namespace saml="urn:oasis:names:tc:SAML:2.0:assertion";
declare namespace samlp="urn:oasis:names:tc:SAML:2.0:protocol";
declare namespace ds="http://www.w3.org/2000/09/xmldsig#";
declare namespace xs="http://www.w3.org/2001/XMLSchema";
declare namespace xsi="http://www.w3.org/2001/XMLSchema-instance";

(: additional modules needed for SAML processing :)
import module namespace compression="http://exist-db.org/xquery/compression";
import module namespace crypto="http://expath.org/ns/crypto";

declare variable $exsaml:version := doc("../expath-pkg.xml")/*:package/@version/string();

(: pull config from config-exsaml.xml :)
(: NEED TO CHECK IF CONFIG EXISTS :)
declare %private variable $exsaml:config   := doc("config-exsaml.xml")/config;

declare %private variable $exsaml:debug    := data($exsaml:config/@debug);
declare %private variable $exsaml:sp-ent   := data($exsaml:config/sp/@entity);
declare %private variable $exsaml:sp-uri   := data($exsaml:config/sp/@endpoint);
declare %private variable $exsaml:sp-assertion-consumer-service-index := data($exsaml:config/sp/@assertion-consumer-service-index);
declare %private variable $exsaml:sp-fallback-rs := data($exsaml:config/sp/@fallback-relaystate);
declare %private variable $exsaml:idp-ent  := data($exsaml:config/idp/@entity);
declare %private variable $exsaml:idp-uri  := data($exsaml:config/idp/@endpoint);
declare %private variable $exsaml:idp-validate-signatures := data($exsaml:config/idp/@validate-signatures);
declare %private variable $exsaml:idp-unsolicited := data($exsaml:config/idp/@accept-unsolicited);
declare %private variable $exsaml:idp-force-rs    := data($exsaml:config/idp/@force-relaystate);
declare %private variable $exsaml:idp-verify-issuer := data($exsaml:config/idp/@verify-issuer);

declare %private variable $exsaml:hmac-key := data($exsaml:config/crypto/@hmac-key);
declare %private variable $exsaml:hmac-alg := data($exsaml:config/crypto/@hmac-alg);
declare %private variable $exsaml:token-minutes  := data($exsaml:config/token/@valid-mins);
declare %private variable $exsaml:token-name     := data($exsaml:config/token/@name);
declare %private variable $exsaml:token-separator := "=";
(: needed for priv escalation :)
declare %private variable $exsaml:exsaml-user   := data($exsaml:config/exsaml-creds/@username);
declare %private variable $exsaml:exsaml-pass   := data($exsaml:config/exsaml-creds/@pass);
(: SSO users configuration :)
declare %private variable $exsaml:sso-create-users  := data($exsaml:config/sso-users/@create-users);
declare %private variable $exsaml:sso-userdata      := data($exsaml:config/sso-users/@data);
declare %private variable $exsaml:sso-default-realm := data($exsaml:config/sso-users/@default-realm);
(: only used for fake IDP response testing :)
declare %private variable $exsaml:minutes-valid := data($exsaml:config/fake-idp/@minutes-valid);
declare %private variable $exsaml:fake-result := data($exsaml:config/fake-idp/@result);
declare %private variable $exsaml:fake-user   := data($exsaml:config/fake-idp/@user);
declare %private variable $exsaml:fake-group  := data($exsaml:config/fake-idp/@group);

(: SAML specific constants and non-configurable vars :)
declare %private variable $exsaml:saml-coll-reqid-base := "/db/apps/existdb-saml";
declare %private variable $exsaml:saml-coll-reqid-name := "saml-request-ids";
declare %private variable $exsaml:saml-version   := "2.0";
declare %private variable $exsaml:status-success := "urn:oasis:names:tc:SAML:2.0:status:Success";
(: debugging only to simulate failure in fake-idp :)
declare %private variable $exsaml:status-badauth := "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

(: may be used to check if SAML is enabled at all :)
declare function exsaml:is-enabled() as xs:boolean {
    $exsaml:config/@enabled eq "true"
};

(: dump current config data :)
declare function exsaml:info() {
    map {
      'enabled': exsaml:is-enabled(),
      'version': $exsaml:version,
      'hmacAlgorithm': $exsaml:hmac-alg,
      'idpEntity': $exsaml:idp-ent,
      'idpUri': $exsaml:idp-uri,
      'tokenLifetime': $exsaml:token-minutes
    }
};

(: ==== FUNCTIONS TO SEND A SAML AUTHN REQUEST ==== :)

(:~
 : Build a SAML authentication request and encode it suitable for an HTTP
 : redirect URL, as specified in the SAML Web Browser SSO Redirect-POST profile.
 : This function is called from the controller when a request without valid
 : token is found, so that the user gets sent to the SAML IDP.
 :
 : @param relaystate this is the path component of the resource that the user
 :  initially requested, so that she gets sent there after SAML auth.
 :)
declare function exsaml:build-authnreq-redir-url($relaystate as xs:string) as xs:string {
    exsaml:build-authnreq-redir-url($relaystate, $exsaml:sso-default-realm)
};

declare function exsaml:build-authnreq-redir-url($relaystate as xs:string, $realm as xs:string) as xs:string {
    let $id := exsaml:gen-id()
    let $log := exsaml:log("info", $id, "building SAML auth request redir-url; relaystate: " || $relaystate || " - realm: " || $realm)
    let $req := exsaml:build-saml-authnreq($id)
    let $debug := exsaml:debug($id, "build-authnreq-redir-url; authnreq: ", $req)

    (: deflate and base64 encode request :)
    let $ser := fn:serialize($req)
    let $bin := util:string-to-binary($ser)
    let $zip := compression:deflate($bin, true())
    (: urlencode base64 request data :)
    let $urlenc := xmldb:encode($zip)

    let $rs := $realm || "#" || $relaystate
    let $debug := exsaml:debug($id, "build-authnreq-redir-url; realm: " || $realm || " relaystate: " || $rs || " urlenc: " || $urlenc)

    return $exsaml:idp-uri || "?SAMLRequest=" || $urlenc || "&amp;RelayState=" || xmldb:encode($rs)
};

(: build and return SAML AuthnRequest node :)
declare %private function exsaml:build-saml-authnreq($id as xs:string) as element(samlp:AuthnRequest) {
    let $instant := fn:current-dateTime()
    let $store := exsaml:store-authnreqid($id, $instant)

    return
        <samlp:AuthnRequest ID="{$id}" Version="{$exsaml:saml-version}" IssueInstant="{$instant}">
        {
            if (fn:exists($exsaml:sp-assertion-consumer-service-index))
            then
                attribute AssertionConsumerServiceIndex { $exsaml:sp-assertion-consumer-service-index }
            else
                attribute AssertionConsumerServiceURL { $exsaml:sp-uri }
        }
            <saml:Issuer>{$exsaml:sp-ent}</saml:Issuer>
        </samlp:AuthnRequest>
};

(: ==== FUNCTIONS TO PROCESS AND VALIDATE A SAML AUTHN RESPONSE ==== :)

(:~
 : Process a SAML response posted to our /SAML2SP endpoint.  Pull SAMLResponse
 : and RelayState from HTTP POST parameters and validate response.  If
 : authentication is valid, create local DB user and put SAML token into
 : session parameters.  Finally return authentication data to the caller,
 : so the user can be redirected to the requested resource.
 :)
declare function exsaml:process-saml-response-post() as element(exsaml:authresult) {
    let $saml-resp := request:get-parameter("SAMLResponse", "NONE")
    return
        if ($saml-resp eq "NONE")
        then (
            let $log := exsaml:log("notice", "--", "No SAML response data provided")
            return
                <authresult msg="No SAML response data provided"/>
        )
        else (
            let $resp := fn:parse-xml-fragment(util:base64-decode($saml-resp))
            return
                exsaml:process-saml-response-post-parsed($resp/samlp:Response)
        )
};

(:~
 : Process a SAML response and return authentication data to the caller,
 : so the user can be redirected to the requested resource.
 :)
declare %private function exsaml:process-saml-response-post-parsed($resp as element(samlp:Response)) as element(exsaml:authresult) {
    let $id := $resp/@InResponseTo
    let $debug := exsaml:debug($id, "process-saml-response-parsed; response: ", $resp)
    let $valresult := exsaml:validate-saml-response($resp)
    return
        if (xs:integer($valresult/@res) lt 0)
        then (
            $valresult
        )
        else (
            let $rsseq := fn:tokenize(request:get-parameter("RelayState", ""), "#")
            let $realm := $rsseq[1]
            let $relayurl := exsaml:determine-relay-state($id, $rsseq[2])

            (: Return an element with all SAML validation data to the controller.
               If SAML success, this is basically username and group membership.
               IF SAML fail, pass enough info to allow meaningful error messages. :)
            let $auth :=
                <authresult code="{$valresult/@res}" msg="{$valresult/@msg}" rid="{$id}"
                            nameid="{$resp/saml:Assertion/saml:Subject/saml:NameID}" realm="{$realm}"
                            relaystate="{$relayurl}" authndate="{$resp/saml:Assertion/@IssueInstant}" />

            (: create SAML user if not exists yet :)
            let $u :=
                if ($exsaml:sso-create-users eq "true" and xs:integer($auth/@code) ge 0)
                then exsaml:ensure-saml-user($id, $auth/@nameid, $realm)
                else ()

            let $pass := exsaml:create-user-password($auth/@nameid)
            let $log-in := xmldb:login("/db/apps", $auth/@nameid, $pass, true())
            let $log := exsaml:log("notice", $id, "login result: " || $log-in || ", " || fn:serialize(sm:id()))

            (: put SAML token into browser session :)
            let $sesstok :=
                if ($log-in and xs:integer($auth/@code) ge 0) then
                    exsaml:set-saml-token($id, $auth/@nameid, $auth/@authndate)
                else ()

            let $debug := exsaml:debug($id, "finished exsaml:process-saml-response-post; auth: ", $auth)
            return $auth
        )
};

(:~
 : Usually, a SAML authentication response contains the URI where the user
 : initially wanted to go in the RelayState.
 : A forced landing page may be configured, overriding the user URL.
 : A default RelayState may be configured, if no user URL is provided.
 :)
declare %private function exsaml:determine-relay-state($id as xs:string, $rsin as xs:string) as xs:string {
    let $rsout :=
        (: if we accept IDP-initiated SAML *and* use a forced landing page :)
        if ($exsaml:idp-unsolicited and $exsaml:idp-force-rs ne "") then (
            let $debug := exsaml:debug($id, "forced Relay State: " || $exsaml:idp-force-rs)
            return
                $exsaml:idp-force-rs
        )
        (: otherwise accept relaystate from the SAML response :)
        else if ($rsin ne "") then (
            let $debug := exsaml:debug($id, "Relay State provided by SSO: " || $rsin)
            return
                $rsin
        ) else (
            let $debug := exsaml:debug($id, "no Relay State provided by SSO, using SP fallback relaystate: " || $exsaml:sp-fallback-rs)
            return
                $exsaml:sp-fallback-rs
        )
    let $debug := exsaml:debug($id, "final Relay State: " || $rsout)
    return $rsout
};

(: validate a SAML response message :)
declare %private function exsaml:validate-saml-response($resp as node()) as element(exsaml:funcret) {
    let $id := $resp/@InResponseTo
    let $debug := exsaml:debug($id, "validate-saml-response")

    let $as := $resp/saml:Assertion
    let $sig := $resp/ds:Signature
    let $result :=

        (: check SAML response status. there are ~20 failure codes, check
         : for success only, return errmsg in @data
         :)
        if ($resp/samlp:Status/samlp:StatusCode/@Value ne $exsaml:status-success) then
            <exsaml:funcret res="-3" msg="SAML authentication failed" data="{$resp/samlp:Status/samlp:StatusCode/@Value}"/>

        (: check that "Issuer" is the expected IDP.  Not stricty required by
           SAML specs, but adds extra protection against forged SAML responses. :)
        else if ($exsaml:idp-verify-issuer eq "true" and boolean($resp/saml:Issuer) and $resp/saml:Issuer ne $exsaml:idp-ent) then (
            let $msg := "SAML response from unexpected IDP: " || $resp/saml:Issuer
            return
                <exsaml:funcret res="-6" msg="{$msg}" data="{$resp/saml:Issuer}"/>
        )
        
        (: verify response signature if present :)
        else if (boolean($sig) and not(exsaml:verify-response-signature($id, $sig))) then
            <exsaml:funcret res="4" msg="failed to verify response signature" />

        (: must contain at least one assertion :)
        else if (empty($as)) then (
                <exsaml:funcret res="-5" msg="no assertions present" />
        )
            (: validate all assertions - only first by now :)
            else (
                exsaml:validate-saml-assertion($id, $as)
            )

    return $result
};

(: validate a SAML assertion :)
declare %private function exsaml:validate-saml-assertion($id as xs:string, $assertion as element(saml:Assertion) as element(exsaml:funcret) {
    if(empty($assertion))
    then (
        let $log := exsaml:log("notice", $id, "Error: Empty Assertion")
        return
            <exsaml:funcret res="-19" msg="no assertion present" />

    )
    else (
        let $debug := exsaml:debug($id, "validate-saml-assertion; assertion: ", $assertion)
        let $sig := $assertion/ds:Signature
        let $subj-confirm-data := $assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData
        let $conds := $assertion/saml:Conditions
        let $reqid := $subj-confirm-data/@InResponseTo

        let $result :=

            (: check that "Issuer" is the expected IDP.  Not stricty required by
               SAML specs, but adds extra protection against forged SAML responses. :)

            if ($exsaml:idp-verify-issuer eq "true"
                and boolean($assertion/saml:Issuer)
                and $assertion/saml:Issuer ne $exsaml:idp-ent)
            then (
                let $msg := "SAML assertion from unexpected IDP: " || $assertion/saml:Issuer
                return
                    <exsaml:funcret res="-18" msg="{$msg}" data="{$assertion/saml:Issuer}"/>
            )

            (: verify assertion signature if present :)
            else if (boolean($sig) and not(exsaml:verify-assertion-signature($id, $assertion))) then
                <exsaml:funcret res="4" msg="failed to verify assertion signature" />

            (: maybe verify SubjectConfirmation/@Method :)

            (: verify SubjectConfirmationData/@Recipient is SP URL ($sp-uri) :)
            else if ($subj-confirm-data/@Recipient ne $exsaml:sp-uri) then
                <exsaml:funcret res="-11" msg="assertion not for me" data="{$subj-confirm-data/@Recipient}"/>

            (: verify SubjectConfirmationData/@NotOnOrAfter is not later than now :)
            else if (xs:dateTime(fn:current-dateTime()) ge xs:dateTime($subj-confirm-data/@NotOnOrAfter)) then
                    <exsaml:funcret res="-12" msg="assertion no longer valid" data="{$subj-confirm-data/@NotOnOrAfter}"/>

            (: verify SubjectConfirmationData/@InResponseTo is present in the SAML response :)
            else if (not($reqid)) then (
                if ($exsaml:idp-unsolicited) then (
                    <exsaml:funcret res="1" msg="accept unsolicited SAML response"/>
                )
                else (
                    <exsaml:funcret res="-17" msg="reject unsolicited SAML response"/>
                )
            )

            (: else verify SubjectConfirmationData/@InResponseTo equal to orig AuthnRequest ID :)
            else if (not(exsaml:check-authnreqid($reqid))) then (
                    <exsaml:funcret res="-13" msg="did not send this SAML request" data="{$subj-confirm-data/@InResponseTo}"/>
            )

            (: verify assertions are valid in other respects - none yet :)

            (: verify Conditions/@NotBefore is not earlier than now :)
            else if (xs:dateTime(fn:current-dateTime()) lt xs:dateTime($conds/@NotBefore)) then (
                    <exsaml:funcret res="-14" msg="condition not yet valid" data="{$conds/@NotBefore}"/>
            )

            (: verify Conditions/@NotOnOrAfter is not later than now :)
            else if (xs:dateTime(fn:current-dateTime()) ge xs:dateTime($conds/@NotOnOrAfter)) then (
                    <exsaml:funcret res="-15" msg="condition no longer valid" data="{$conds/@NotOnOrAfter}"/>
            )

            (: verify Conditions/AudienceRestriction/Audience is myself ($sp-ent) :)
            else if ($conds/saml:AudienceRestriction/saml:Audience ne $exsaml:sp-ent) then
                    <exsaml:funcret res="-16" msg="audience not for me" data="{$conds/saml:AudienceRestriction/saml:Audience}"/>

            else
                <exsaml:funcret res="0" msg="ok" />

        return $result
    )
};

(: verify XML signature of a SAML response :)
declare %private function exsaml:verify-response-signature($id as xs:string, $resp as item()) as xs:boolean {
    let $debug := exsaml:debug($id, "verify-response-signature; response: ", $resp)
    let $res :=
        if ($exsaml:idp-validate-signatures eq "true") then (
            if (crypto:validate-signature($resp))
            then (
                let $debug := exsaml:debug($id, "response signature validated")
                return true()
            )
            else (
                let $log := exsaml:log("notice", $id, "failed to validate response signature")
                return false()
            )
        )
        else (
            let $log := exsaml:log("info", $id, "not verifying response signature")
            return true()
        )
    return $res
};

(: verify XML signature of a SAML assertion :)
declare %private function exsaml:verify-assertion-signature($id as xs:string, $assertion as item()) as xs:boolean {
    let $debug := exsaml:debug($id, "verify-assertion-signature; assertion: ", $assertion)
    let $res :=
        if ($exsaml:idp-validate-signatures eq "true") then (
            if (crypto:validate-signature($assertion))
            then (
                let $debug := exsaml:debug($id, "assertion signature validated")
                return true()
            )
            else (
                let $log := exsaml:log("notice", $id, "failed to validate assertion signature")
                return false()
            )
        )
        else (
            let $log := exsaml:log("info", $id, "not verifying assertion signature")
            return true()
        )
    return $res
};

(: This function is used to create the named DB user on the fly if the
   account does not exist yet.  Since we rely on SAML to assert that a
   certain username is valid, we have no list of usernames upfront, but
   create them on the fly.  This allows to store per-user preferences and
   settings. :)
declare %private function exsaml:ensure-saml-user($id as xs:string, $nameid as xs:string, $realm as xs:string) {
    let $allusers := doc($exsaml:sso-userdata)/sso-users/user/*[name() = $realm]
    let $userdata :=
        if ($allusers[@user eq $nameid]) then (
            $allusers[@user eq $nameid]
        ) else (
            $allusers[@user eq 'default-user']
        )
    let $user-exists := exsaml:suexec(sm:user-exists#1, [$nameid])

    return
        if (not($user-exists)) then (
            let $log := exsaml:log("notice", $id, "create new user account " || $nameid || ", group " || data($userdata/@group))
            let $pass := exsaml:create-user-password($nameid)
            return
                exsaml:suexec(sm:create-account#4, [$nameid, $pass, data($userdata/@group), data($userdata/other-groups/group)])
        ) else (
            (: user exists, ensure group membership :)
            let $usergroups := exsaml:suexec(sm:get-user-groups#1, [$nameid])
            for $g in data($userdata/other-groups/group)
            return
                if (not($g = $usergroups)) then (
                    let $log := exsaml:log("notice", $id, "add user " || $nameid || "to group " || $g)
                    return exsaml:suexec(sm:add-group-member#2, [$g, $nameid])
                ) else ()
        )
};

(: create user password as HMAC of username :)
declare %private function exsaml:create-user-password($nameid as xs:string) as xs:string {
    let $key  := $exsaml:hmac-key || ""
    let $alg  := $exsaml:hmac-alg || ""
    let $pass := crypto:hmac($nameid, $key, $alg, "hex")
    return $pass
};


(: ==== FUNCTIONS TO DEAL WITH REQUEST IDS ==== :)

(: store issued request ids in a collection :)
declare %private function exsaml:store-authnreqid($id as xs:string, $instant as xs:dateTime) {
    let $debug := exsaml:debug($id, "storing SAML request id: " || $id || ", date: " || $instant)
    return
        exsaml:suexec(exsaml:store-authnreqid-privileged#2, [$id, $instant])
};

declare %private function exsaml:store-authnreqid-privileged($id as xs:string, $instant as xs:dateTime) {
    let $collection := exsaml:ensure-authnreqid-collection()
    return
        xmldb:store($collection, $id, <reqid>{$instant}</reqid>)
};

declare %private function exsaml:ensure-authnreqid-collection() as xs:string {
    let $collection := $exsaml:saml-coll-reqid-base || '/' || $exsaml:saml-coll-reqid-name
    let $_ :=
        if (not(xmldb:collection-available($collection)))
        then (
            exsaml:log("info", "---", "creating collection " || $collection),
            xmldb:create-collection($exsaml:saml-coll-reqid-base, $exsaml:saml-coll-reqid-name),
	    sm:chmod(xs:anyURI($collection), "rwx------")
        )
        else ()
    return
        $collection
};

(: retrieve issued SAML request id and delete if answered :)
declare %private function exsaml:check-authnreqid($reqid as xs:string) as xs:string {
    let $debug := exsaml:debug($reqid, "verifying SAML request id")
    return
        exsaml:suexec(exsaml:check-authnreqid-privileged#1, [$reqid])
};

declare %private function exsaml:check-authnreqid-privileged($reqid as xs:string) as xs:string {
    if (exists(doc($exsaml:saml-coll-reqid||"/"||$reqid))
        and empty(xmldb:remove($exsaml:saml-coll-reqid, $reqid)))
    then $reqid
    else ""
};


(: ==== FUNCTIONS TO DEAL WITH TOKENS ==== :)

(:~
 : Check whether a SAML token exists and is valid.  Return boolean.
 : This is called from the controller(s) to check if access should be granted.
 :)
declare function exsaml:check-valid-saml-token() as xs:boolean {
    let $raw := session:get-attribute($exsaml:token-name)
    let $debug := exsaml:debug("--", "checking saml token, name: " || $exsaml:token-name || ", value: " || $raw)

    let $tokdata := fn:tokenize($raw, $exsaml:token-separator)
    return
        if (empty($raw) and exsaml:log("info", "--", "no token found")) then
            false()
        else if (not($tokdata[3] eq exsaml:hmac-tokval($tokdata[1] || $exsaml:token-separator || $tokdata[2]))
                and exsaml:log("info", "--", "token is invalid")) then
            false()
        else if (xs:dateTime(fn:current-dateTime()) gt xs:dateTime($tokdata[2])
                 and exsaml:log("info", "--", "token has expired")) then
            false()
        else
            true()
};

(:~
 : Invalidate a SAML token, by creating one with expire date in the past,
 : so that it will fail token expiration checks.
 : This is called from the controller(s) upon user logout.
 :)
declare function exsaml:invalidate-saml-token() as empty-sequence() {
    let $user := sm:id()/sm:id/sm:real/sm:username
    let $tok  := exsaml:build-string-token($user, xs:dateTime("1970-01-01T00:00:00"))
    let $hmac := exsaml:hmac-tokval($tok)
    let $log  := exsaml:log("info", "--", "invalidate saml token for: " || $user || ", hmac: " || $hmac)
    let $session-attr := session:set-attribute($exsaml:token-name, $tok || $exsaml:token-separator || $hmac)

    return $session-attr
};

(: return the HMAC of the string token passed in :)
declare %private function exsaml:hmac-tokval($tokval as xs:string) as xs:string {
    let $key  := $exsaml:hmac-key || ""
    let $alg  := $exsaml:hmac-alg || ""

    return crypto:hmac($tokval, $key, $alg, "hex")
};

(: build string token: join nameid and validto by $exsaml:token-separator :)
declare %private function exsaml:build-string-token($nameid as xs:string, $validto as xs:dateTime) as xs:string {
    $nameid || $exsaml:token-separator || $validto
};

(: build and HMAC token and stuff into browser session :)
declare %private function exsaml:set-saml-token($id as xs:string, $nameid as xs:string, $authndate as xs:string) as empty-sequence() {
    let $validto := xs:dateTime($authndate) + xs:dayTimeDuration("PT" || $exsaml:token-minutes || "M")
    let $tok := exsaml:build-string-token($nameid, $validto)
    let $debug := exsaml:debug($id, "set-saml-token; nameid: " || $nameid || ", validto: " || $validto)
    let $hmac := exsaml:hmac-tokval($tok)
    let $log  := exsaml:log("info", $id, "set saml token for: " || $nameid || ", authndate: " || $authndate || ", valid until: " || $validto || ", hmac: " || $hmac)
    return session:set-attribute($exsaml:token-name, $tok || $exsaml:token-separator || $hmac)
};


(: ==== FUNCTIONS TO FAKE A SAML IDP (testing only) ==== :)

(: process SAML AuthnRequest, return SAML Response via POST :)
declare function exsaml:process-saml-request() as element(html) {
    let $raw := request:get-parameter("SAMLRequest", "")
    (: let $debug := exsaml:debug("Fake IDP: process-saml-request; raw: " || $raw) :)
    let $uncomp := compression:inflate($raw, true())
    (: let $debug := exsaml:debug("Fake IDP: process-saml-request; uncomp: " || $uncomp) :)
    let $strg := util:base64-decode($uncomp)
    (: let $debug := exsaml:debug("Fake IDP: process-saml-request; strg: " || $strg) :)
    let $req := fn:parse-xml-fragment($strg)
    let $rs := request:get-parameter("RelayState", false())
    let $resp := exsaml:fake-idp-response($req/samlp:AuthnRequest, $rs)
    return $resp
};

(: fake SAML IDP response: build response and return via XHTML autosubmit form :)
declare %private function exsaml:fake-idp-response($req as node(), $rs as xs:string) as element(html) {
    (: let $debug := exsaml:debug("Fake IDP: fake-idp-response") :)
    let $resp := exsaml:build-saml-fakeresp($req)
    let $b64resp := util:base64-encode(fn:serialize($resp))

    return
        <html><head/>
            <body onload="document.forms.samlform.submit()">
                <noscript><p><strong>Note:</strong> Since your browser does not support Javascript, you must press the Submit button once to proceed.</p></noscript>
                <form id="samlform" method="post" action="{$exsaml:sp-uri}">
                    <input type="hidden" name="SAMLResponse" value="{$b64resp}" />
                    <input type="hidden" name="RelayState" value="{$rs}" />
                    <input type="submit" value="Submit" />
                </form>
            </body></html>
};

(: return a fake SAML response node :)
declare %private function exsaml:build-saml-fakeresp($req as node()) as element(samlp:Response) {
    let $reqid := $req/@ID
    let $status  :=
        if ($exsaml:fake-result eq "true")
        then $exsaml:status-success
        else $exsaml:status-badauth
    let $fakesig := "ABCDEF"
    let $now     := fn:current-dateTime()
    let $validto := $now + xs:dayTimeDuration("PT" || $exsaml:minutes-valid || "M")

    return
        <samlp:Response ID="{exsaml:gen-id()}" InResponseTo="{$reqid}" Version="{$exsaml:saml-version}"
                        IssueInstant="{$now}" Destination="{$exsaml:sp-uri}">
            <saml:Issuer>{$exsaml:idp-ent}</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="{$status}"/>
            </samlp:Status>
            <saml:Assertion ID="{exsaml:gen-id()}" Version="{$exsaml:saml-version}" IssueInstant="{$now}">
                <saml:Issuer>{$exsaml:idp-ent}</saml:Issuer>
                <ds:Signature>{$fakesig}</ds:Signature>
                <saml:Subject>
                    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">{$exsaml:fake-user}</saml:NameID>
                    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                        <saml:SubjectConfirmationData InResponseTo="{$reqid}" Recipient="{$exsaml:sp-uri}" NotOnOrAfter="{$validto}"/>
                    </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="{$now}" NotOnOrAfter="{$validto}">
                    <saml:AudienceRestriction>
                        <saml:Audience>{$exsaml:sp-ent}</saml:Audience>
                    </saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="{$now}" SessionIndex="{exsaml:gen-id()}">
                    <saml:AuthnContext>
                        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                    </saml:AuthnContext>
                </saml:AuthnStatement>
            </saml:Assertion>
        </samlp:Response>
};


(: ==== UTIL FUNCTIONS ==== :)

(: execute a function as privileged exsaml user, to call certain sm: functions :)
declare %private function exsaml:suexec($function as function(*), $args as array(*)) as item()*{
    system:as-user($exsaml:exsaml-user, $exsaml:exsaml-pass,
                   fn:apply($function, $args))
};

(: generate a SAML ID :)
(: which is xs:ID which is xsd:NCName which MUST NOT start with a number :)
declare %private function exsaml:gen-id() as xs:string {
    let $uuid := util:uuid()
    return "a" || $uuid
};

declare function exsaml:log($level as xs:string, $id as xs:string, $msg as xs:string) as xs:boolean {
    let $l := util:log($level, "exsaml: [" || $id || "] " || $msg)
    return true()
};

declare function exsaml:debug($id as xs:string, $msg as xs:string, $data as item()) as xs:boolean {
    let $l :=
        if ($exsaml:debug eq 'true')
        then (
 	    let $ser := fn:serialize($data)
            return util:log('info', "exsaml-debug: [" || $id || "] " || $msg || " " || $ser)
        ) else ()
    return true()
};

declare function exsaml:debug($id as xs:string, $msg as xs:string) as xs:boolean {
    let $l :=
        if ($exsaml:debug eq 'true')
        then (
            util:log('info', "exsaml-debug: [" || $id || "] " || $msg)
        ) else ()
    return true()
};
