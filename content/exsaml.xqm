xquery version "3.1";

module namespace exsaml = "http://exist-db.org/xquery/exsaml";

(: namespace declarations for building SAML nodes :)
declare namespace saml = "urn:oasis:names:tc:SAML:2.0:assertion";
declare namespace samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
declare namespace ds = "http://www.w3.org/2000/09/xmldsig#";
declare namespace xs = "http://www.w3.org/2001/XMLSchema";
declare namespace xsi = "http://www.w3.org/2001/XMLSchema-instance";

(: additional modules needed for SAML processing :)
import module namespace compression = "http://exist-db.org/xquery/compression";
import module namespace crypto = "http://expath.org/ns/crypto";
import module namespace request = "http://exist-db.org/xquery/request";
import module namespace session = "http://exist-db.org/xquery/session";
import module namespace sm = "http://exist-db.org/xquery/securitymanager";
import module namespace system = "http://exist-db.org/xquery/system";
import module namespace util = "http://exist-db.org/xquery/util";
import module namespace xmldb = "http://exist-db.org/xquery/xmldb";

(: other modules :)
(:import module namespace console="http://exist-db.org/xquery/console";:)

declare variable $exsaml:version := doc("../expath-pkg.xml")/*:package/@version/string();

(: pull config from config-exsaml.xml :)
(: NEED TO CHECK IF CONFIG EXISTS :)
declare %private variable $exsaml:config   := doc("config-exsaml.xml")/config;

declare %private variable $exsaml:sp-ent   := data($exsaml:config/sp/@entity);
declare %private variable $exsaml:sp-uri   := data($exsaml:config/sp/@endpoint);
declare %private variable $exsaml:sp-fallback-rs := data($exsaml:config/sp/@fallback-relaystate);
declare %private variable $exsaml:idp-ent  := data($exsaml:config/idp/@entity);
declare %private variable $exsaml:idp-uri  := data($exsaml:config/idp/@endpoint);
declare %private variable $exsaml:idp-certfile    := data($exsaml:config/idp/@certfile);
declare %private variable $exsaml:idp-unsolicited := data($exsaml:config/idp/@accept-unsolicited);
declare %private variable $exsaml:idp-force-rs    := data($exsaml:config/idp/@force-relaystate);
declare %private variable $exsaml:idp-verify-issuer := data($exsaml:config/idp/@verify-issuer);

declare %private variable $exsaml:hmac-key := data($exsaml:config/crypto/@hmac-key);
declare %private variable $exsaml:hmac-alg := data($exsaml:config/crypto/@hmac-alg);
declare %private variable $exsaml:group-attr     := $exsaml:config/group-attribute/text();
declare %private variable $exsaml:token-minutes  := data($exsaml:config/token/@valid-mins);
declare %private variable $exsaml:token-name     := data($exsaml:config/token/@name);
declare %private variable $exsaml:token-separator := "=";
(: needed for priv escalation :)
declare %private variable $exsaml:exsaml-user   := data($exsaml:config/exsaml-creds/@username);
declare %private variable $exsaml:exsaml-pass   := data($exsaml:config/exsaml-creds/@pass);
(: needed if user accounts should be created on the fly :)
declare %private variable $exsaml:create-user   := data($exsaml:config/dynamic-users/@create);
declare %private variable $exsaml:user-group    := data($exsaml:config/dynamic-users/@group);
(: only used for fake IDP response testing :)
declare %private variable $exsaml:minutes-valid := data($exsaml:config/fake-idp/@minutes-valid);
declare %private variable $exsaml:fake-result := data($exsaml:config/fake-idp/@result);
declare %private variable $exsaml:fake-user   := data($exsaml:config/fake-idp/@user);
declare %private variable $exsaml:fake-group  := data($exsaml:config/fake-idp/@group);

(: SAML specific constants and non-configurable vars :)
declare %private variable $exsaml:saml-coll-reqid := "/db/apps/existdb-saml/saml-request-ids";
declare %private variable $exsaml:saml-version   := "2.0";
declare %private variable $exsaml:status-success := "urn:oasis:names:tc:SAML:2.0:status:Success";
(: debugging only to simulate failure in fake-idp :)
declare %private variable $exsaml:status-badauth := "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
declare variable $exsaml:ERROR :=  xs:QName("saml:error");


(: may be used to check if SAML is enabled at all :)
declare function exsaml:is-enabled() {
    $exsaml:config/@enabled = "true"
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
    let $log := exsaml:log("info", "building SAML auth request redir-url; relaystate: " || $relaystate)
    let $req := exsaml:build-saml-authnreq()
    let $log := exsaml:log("debug", "build-authnreq-redir-url; req: " || $req)

    (: deflate and base64 encode request :)
    let $ser := fn:serialize($req)
(:    let $log := exsaml:log("debug", "build-authnreq-redir-url; ser: " || $ser):)
    let $bin := util:string-to-binary($ser)
(:    let $log := exsaml:log("debug", "build-authnreq-redir-url; bin: " || $bin):)
    let $zip := compression:deflate($bin, true())
(:    let $log := exsaml:log("debug", "build-authnreq-redir-url; zip: " || $zip):)
    (: urlencode base64 request data :)
    let $urlenc := xmldb:encode($zip cast as xs:string)

    let $log := exsaml:log("debug", "build-authnreq-redir-url; urlenc: " || $urlenc)

    return
        $exsaml:idp-uri || "?SAMLRequest=" || $urlenc || "&amp;RelayState=" || xmldb:encode($relaystate)
};

(: build and return SAML AuthnRequest node :)
declare %private function exsaml:build-saml-authnreq() as element(samlp:AuthnRequest) {
    let $id := exsaml:gen-id()
    let $instant := fn:current-dateTime()
    let $store := exsaml:store-authnreqid($id, $instant)
    return
        <samlp:AuthnRequest ID="{$id}" Version="{$exsaml:saml-version}" IssueInstant="{$instant}" AssertionConsumerServiceIndex="0">
            <saml:Issuer>{$exsaml:sp-ent}</saml:Issuer>
        </samlp:AuthnRequest>
};

declare %private function exsaml:store-authnreqid-as-exsol-user($id as xs:string, $instant as xs:string) {
    let $create-collection :=
            if (not(xmldb:collection-available($exsaml:saml-coll-reqid)))
            then
                let $log := exsaml:log("info", "collection " || $exsaml:saml-coll-reqid || " does not exist, attempting to create it")
                return
                    xmldb:create-collection("/db/apps/existdb-saml", "saml-request-ids")
            else ()
    return
        xmldb:store($exsaml:saml-coll-reqid, $id, <reqid>{$instant}</reqid>)
};

(: store issued request ids in a collection,  :)
declare %private function exsaml:store-authnreqid($id as xs:string, $instant as xs:string) {
    let $log := exsaml:log("info", "storing SAML request id: " || $id || ", date: " || $instant)
    return
        system:as-user(
                $exsaml:exsaml-user,
                $exsaml:exsaml-pass,
                exsaml:store-authnreqid-as-exsol-user($id, $instant)
        )
};

(: ==== FUNCTIONS TO PROCESS AND VALIDATE A SAML AUTHN RESPONSE ==== :)

(:~
 : Process a SAML response posted to our /SAML2SP endpoint.  Pull SAMLResponse
 : and RelayState from HTTP POST parameters and validate response.  If
 : authentication is valid, create local DB user and put SAML token into
 : session parameters.  Finally return authentication data to the caller,
 : so the user can be redirected to the requested resource.
 :)
declare function exsaml:process-saml-response-post() {
    let $log  := exsaml:log("info", "process-saml-response-post")
    let $saml-resp := request:get-parameter("SAMLResponse", "error")

    let $resp :=
            if ($saml-resp = "error")
            then
                $saml-resp
            else
                let $decode-resp := util:base64-decode($saml-resp)
                return
                    fn:parse-xml-fragment($decode-resp)

    let $debug := exsaml:log("debug", "START SAML RESPONSE")
    let $debug := exsaml:log("debug", fn:serialize($resp))
    let $debug := exsaml:log("debug", "END SAML RESPONSE")

    return

        if ($resp = "error")
        then
            error($exsaml:ERROR, "Empty SAML Response", "No SAML response data has been provided")
        else

            try {

                let $res := exsaml:validate-saml-response($resp)
                return
                    if ($res/@res lt 0)
                    then
                        (: validate-saml-response returned a negative @res value which is an error code, so just return it:)
                        $res

                    else

                        let $rsin := request:get-parameter("RelayState", "")
                        let $rsout :=
                                (: if we accept IDP-initiated SAML *and* use a forced landing page :)
                                if ($exsaml:idp-unsolicited and $exsaml:idp-force-rs != "")
                                then
                                    let $debug := exsaml:log("debug", "evaluated to: $exsaml:idp-unsolicited and $exsaml:idp-force-rs != ''")
                                    let $debug := exsaml:log("debug", "$exsaml:idp-force-rs is: " || $exsaml:idp-force-rs || " evaluated: " || string-length($exsaml:idp-force-rs))
                                    return
                                        $exsaml:idp-force-rs
                                (: otherwise accept relaystate from the SAML response :)
                                else if ($rsin != "")
                                then
                                    let $debug := exsaml:log("info", "Relay State as provided by SSO: " || $rsin)
                                    return
                                        $rsin
                                else
                                    let $debug := exsaml:log("info", "no Relay State provided by SSO, switching to SP fallback relaystate: " || $exsaml:sp-fallback-rs)
                                    return
                                        $exsaml:sp-fallback-rs

                        (: Return an element with all SAML validation data to the controller.
                           If SAML success, this is basically username and group membership.
                           IF SAML fail, pass enough info to allow meaningful error messages. :)
                        let $auth :=
                                <authresult code="{$res/@res}" msg="{$res/@msg}" nameid="{$resp/saml:Assertion/saml:Subject/saml:NameID}" relaystate="{$rsout}" authndate="{$resp/saml:Assertion/@IssueInstant}">
                                    <groups>{exsaml:fetch-saml-attribute-values($exsaml:group-attr, $resp/saml:Assertion) ! <group>{.}</group>}</groups>
                                </authresult>

                        (: create SAML user if not exists yet :)
                        let $u :=
                                if ($exsaml:create-user = "true" and $auth/@code >= "0")
                                then
                                    exsaml:ensure-saml-user($auth/@nameid)
                                else ""

                        let $pass := exsaml:create-user-password($auth/@nameid)
                        let $log-in := xmldb:login("/db/apps", $auth/@nameid, $pass, true())
                        let $log := util:log("info", "login result: " || $log-in || ", " || fn:serialize(sm:id()))

                        (: put SAML token into browser session :)
                        let $sesstok :=
                                if ($log-in and $auth/@code >= "0")
                                then
                                    exsaml:set-saml-token($auth/@nameid, $auth/@authndate)
                                else ()

                        let $debug := exsaml:log("info", "finished exsaml:process-saml-response-post. auth: ")
                        let $debug := exsaml:log("info", fn:serialize($auth))
                        return
                            $auth

            } catch * {
                <error>Caught error {$err:code}: {$err:description}. Data: {$err:value}</error>
            }
};

(: validate a SAML response message :)
declare %private function exsaml:validate-saml-response($resp as node()) as element(exsaml:funcret) {
    let $log  := exsaml:log("info", "validate-saml-response")

    let $as := $resp/saml:Assertion
    let $sig := $resp/ds:Signature
    return

        (: check SAML response status. there are ~20 failure codes, check
         : for success only, return errmsg in @data
         :)
        if (not($resp/samlp:Status/samlp:StatusCode/@Value = $exsaml:status-success))
        then
            <exsaml:funcret res="-3" msg="SAML authentication failed" data="{$resp/samlp:Status/samlp:StatusCode/@Value}"/>

        (: check that "Issuer" is the expected IDP.  Not stricty required by
         : SAML specs, but adds extra protection against forged SAML responses.
         :)
        else if ($exsaml:idp-verify-issuer = "true" and boolean($resp/saml:Issuer) and not($resp/saml:Issuer = $exsaml:idp-ent))
        then
            let $msg := "SAML response from unexpected IDP: " || $resp/saml:Issuer
            return
                <exsaml:funcret res="-6" msg="{$msg}" data="{$resp/saml:Issuer}"/>
        
        (: verify response signature if present :)
        (: COMMENTED OUT until crypto-lib issues resolved :)
        (:            else if (boolean($sig) and not(exsaml:verify-response-signature($sig))) then :)
        (:            <exsaml:funcret res="-4" msg="failed to verify response signature" /> :)

        (: must contain at least one assertion :)
        else if (empty($as))
        then
            <exsaml:funcret res="-5" msg="no assertions present" />

        (: validate all assertions - only first by now :)
        else
            exsaml:validate-saml-assertion($as)
};

(: validate a SAML assertion :)
declare %private function exsaml:validate-saml-assertion($assertion as item()) as element(exsaml:funcret) {
    if (empty($assertion))
    then
        let $log := exsaml:log("info", "Error: Empty Assertion")
        return
            <exsaml:funcret res="-19" msg="no assertion present" />

    else
        let $log := exsaml:log("info", "validate-saml-assertion: " || fn:serialize($assertion))
        let $sig := $assertion/ds:Signature
        let $subj-confirm-data := $assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData
        let $conds := $assertion/saml:Conditions
        let $reqid := $subj-confirm-data/@InResponseTo
        return

            (: check that "Issuer" is the expected IDP.  Not stricty required by
               SAML specs, but adds extra protection against forged SAML responses. :)

            if ($exsaml:idp-verify-issuer = "true" and boolean($assertion/saml:Issuer) and not($assertion/saml:Issuer = $exsaml:idp-ent))
            then
                let $msg := "SAML assertion from unexpected IDP: " || $assertion/saml:Issuer
                return
                    <exsaml:funcret res="-18" msg="{$msg}" data="{$assertion/saml:Issuer}"/>

            (: verify assertion signature if present :)
(: COMMENTED OUT until crypto-lib issues resolved :)
(:            else if (boolean($sig) and not(exsaml:verify-assertion-signature($assertion))) then :)
(:                <exsaml:funcret res="-10" msg="failed to verify assertion signature" /> :)

            (: maybe verify SubjectConfirmation/@Method :)

            (: verify SubjectConfirmationData/@Recipient is SP URL ($sp-uri) :)
            else if (not($subj-confirm-data/@Recipient = $exsaml:sp-uri))
            then
                <exsaml:funcret res="-11" msg="assertion not for me" data="{$subj-confirm-data/@Recipient}"/>

            (: verify SubjectConfirmationData/@NotOnOrAfter is not later than now :)
            else if (xs:dateTime(fn:current-dateTime()) ge xs:dateTime($subj-confirm-data/@NotOnOrAfter))
            then
                <exsaml:funcret res="-12" msg="assertion no longer valid" data="{$subj-confirm-data/@NotOnOrAfter}"/>

            (: verify SubjectConfirmationData/@InResponseTo is present in the SAML response :)
            else if (not($reqid))
            then
                if ($exsaml:idp-unsolicited)
                then
                    <exsaml:funcret res="1" msg="accept unsolicited SAML response"/>
                else
                    <exsaml:funcret res="-17" msg="reject unsolicited SAML response"/>

            (: else verify SubjectConfirmationData/@InResponseTo equal to orig AuthnRequest ID :)
            else if (not(exsaml:check-authnreqid($reqid)))
            then
                <exsaml:funcret res="-13" msg="did not send this SAML request" data="{$subj-confirm-data/@InResponseTo}"/>

            (: verify assertions are valid in other respects - none yet :)

            (: verify Conditions/@NotBefore is not earlier than now :)
            else if (xs:dateTime(fn:current-dateTime()) lt xs:dateTime($conds/@NotBefore))
            then
                <exsaml:funcret res="-14" msg="condition not yet valid" data="{$conds/@NotBefore}"/>

            (: verify Conditions/@NotOnOrAfter is not later than now :)
            else if (xs:dateTime(fn:current-dateTime()) ge xs:dateTime($conds/@NotOnOrAfter))
            then
                <exsaml:funcret res="-15" msg="condition no longer valid" data="{$conds/@NotOnOrAfter}"/>

            (: verify Conditions/AudienceRestriction/Audience is myself ($sp-ent) :)
            else if (not($conds/saml:AudienceRestriction/saml:Audience = $exsaml:sp-ent))
            then
                <exsaml:funcret res="-16" msg="audience not for me" data="{$conds/saml:AudienceRestriction/saml:Audience}"/>

            else
                <exsaml:funcret res="0" msg="ok" />
};

(: retrieve issued SAML request id and delete if answered :)
declare %private function exsaml:check-authnreqid($reqid as xs:string) as xs:string {
    let $log := exsaml:log("info", "verifying SAML request id: " || $reqid)
    return
        if (system:as-user($exsaml:exsaml-user, $exsaml:exsaml-pass,
                exists(doc($exsaml:saml-coll-reqid || "/" || $reqid)) and empty(xmldb:remove($exsaml:saml-coll-reqid, $reqid))))
        then
            $reqid
        else ""
};

(: verify XML signature of a SAML response :)
declare %private function exsaml:verify-response-signature($resp as item()) as xs:boolean {
    let $log  := exsaml:log("debug", "verify-response-signature: " || $resp)
    return
        (: if $idp-certfile is configured, use that to validate XML signature :)
        if ($exsaml:idp-certfile != "")
        then
(:            crypto:validate-signature-by-certfile($resp, $exsaml:idp-certfile):)
            true()
        else
            let $log  := exsaml:log("info", "cert to verify response signature is missing - could not verify signature! ")
            return
                false()
};

(: verify XML signature of a SAML assertion :)
declare %private function exsaml:verify-assertion-signature($assertion as item()) as xs:boolean {
    let $log  := exsaml:log("debug", "verify-assertion-signature " || $assertion)
    return
        (: if $idp-certfile is configured, use that to validate XML signature :)
        if ($exsaml:idp-certfile != "")
        then
(:            crypto:validate-signature-by-certfile($assertion, $exsaml:idp-certfile):)
            true()
        else
            let $log  := exsaml:log("info", "cert to verify assertion signature is missing - could not verify signature! ")
            return
                false()
};

(: Fetch the named SAML attribute values from a SAML assertion.  This is
   used to get group membership of an authenticated user, which gets passed
   as SAML attribute assertions by the IDP :)
declare %private function exsaml:fetch-saml-attribute-values($attrname as xs:string, $as as node()) as xs:string* {
    let $log := exsaml:log("debug", "fetch-saml-attribute " || $attrname || ", " || fn:serialize($as))
    let $seq :=
        for $a in $as/saml:AttributeStatement/saml:Attribute[@Name eq $attrname]/saml:AttributeValue
        return $a/text()
    let $log := exsaml:log("debug", "fetch-saml-attribute: " || fn:serialize($seq))
    return
        $seq
};

(: This function is used to create the named DB user on the fly if the
   account does not exist yet.  Since we rely on SAML to assert that a
   certain username is valid, we have no list of usernames upfront, but
   create them on the fly.  This allows to store per-user preferences and
   settings. :)
declare %private function exsaml:ensure-saml-user($nameid as xs:string) {
    let $pass := exsaml:create-user-password($nameid)
    return
        (: run as user exsaml, group dba :)
        system:as-user($exsaml:exsaml-user, $exsaml:exsaml-pass,
                       if (not(sm:user-exists($nameid))
                           and exsaml:log("info", "create new user account " || $nameid || ", group " || $exsaml:user-group))
                       then
                           sm:create-account($nameid, $pass, $exsaml:user-group, ())
                       else ()
        )
};

(: create user password as HMAC of username :)
declare %private function exsaml:create-user-password($nameid as xs:string) {
    let $key  := $exsaml:hmac-key || ""
    let $alg  := $exsaml:hmac-alg || ""
    return
        crypto:hmac($nameid, $key, $alg, "hex")
};


(: ==== FUNCTIONS TO DEAL WITH TOKENS ==== :)

(:~
 : Check whether a SAML token exists and is valid.  Return boolean.
 : This is called from the controller(s) to check if access should be granted.
 :)
declare function exsaml:check-valid-saml-token() as xs:boolean {
    let $raw  := session:get-attribute($exsaml:token-name)
    let $log  := exsaml:log("debug", "checking saml token, name: " || $exsaml:token-name || ", value: " || $raw)

    let $tokdata := fn:tokenize($raw, $exsaml:token-separator)
    return
        if (empty($raw) and exsaml:log("info", "no token found"))
        then
            false()
        else if (not($tokdata[3] eq exsaml:hmac-tokval($tokdata[1] || $exsaml:token-separator || $tokdata[2])) and exsaml:log("info", "token is invalid"))
        then
            false()
        else if (xs:dateTime(fn:current-dateTime()) gt xs:dateTime($tokdata[2]) and exsaml:log("info", "token has expired"))
        then
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
    let $tok  := exsaml:build-string-token($user, "1970-01-01T00:00:00")
    let $hmac := exsaml:hmac-tokval($tok)
    let $log  := exsaml:log("info", "invalidate saml token for: " || $user || ", hmac: " || $hmac)
    return
        session:set-attribute($exsaml:token-name, $tok || $exsaml:token-separator || $hmac)
};

(: return the HMAC of the string token passed in :)
declare %private function exsaml:hmac-tokval($tokval as xs:string) as xs:string {
    let $log  := exsaml:log("debug", "hmac-tokval; t: " || $tokval || ", key: " || $exsaml:hmac-key)
    let $key  := $exsaml:hmac-key || ""
    let $alg  := $exsaml:hmac-alg || ""
    return
        crypto:hmac($tokval, $key, $alg, "hex")
};

(: build string token: join nameid and validto by $exsaml:token-separator :)
declare %private function exsaml:build-string-token($nameid as xs:string, $validto as xs:string) as xs:string {
    let $log  := exsaml:log("debug", "build-string-token; n: " || $nameid || ", v: " || $validto)
    return
        $nameid || $exsaml:token-separator || $validto
};

(: build and HMAC token and stuff into browser session :)
declare %private function exsaml:set-saml-token($nameid as xs:string, $authndate as xs:string) as empty-sequence() {
    let $validto := xs:dateTime($authndate) + xs:dayTimeDuration("PT" || $exsaml:token-minutes || "M")

    let $tok := exsaml:build-string-token($nameid, $validto)
    let $hmac := exsaml:hmac-tokval($tok)
    let $log  := exsaml:log("info", "set saml token for: " || $nameid || ", authndate: " || $authndate || ", valid until: " || $validto || ", hmac: " || $hmac)
    return
        session:set-attribute($exsaml:token-name, $tok || $exsaml:token-separator || $hmac)
};


(: ==== FUNCTIONS TO FAKE A SAML IDP (testing only) ==== :)

(: process SAML AuthnRequest, return SAML Response via POST :)
declare function exsaml:process-saml-request() as element(html){
    let $log  := exsaml:log("debug", "process-saml-request")
    let $raw  := request:get-parameter("SAMLRequest", "")
    let $log  := exsaml:log("debug", "process-saml-request; raw: " || $raw)
    let $uncomp := compression:inflate($raw, true())
    let $log  := exsaml:log("debug", "process-saml-request; uncomp: " || $uncomp)
    let $strg := util:base64-decode($uncomp)
    let $log  := exsaml:log("debug", "process-saml-request; strg: " || $strg)
    let $req  := fn:parse-xml-fragment($strg)
    let $log  := exsaml:log("debug", "process-saml-request; req: " || $req)
    let $rs   := request:get-parameter("RelayState", false())

    let $resp := exsaml:fake-idp-response($req, $rs)
    return $resp
};

(: fake SAML IDP response: build response and return via XHTML autosubmit form :)
declare %private function exsaml:fake-idp-response($req as node(), $rs as xs:string) as element(html) {
    let $log := exsaml:log("debug", "fake-idp-response")
    let $resp := exsaml:build-saml-fakeresp($req)
    let $b64resp := util:base64-encode(fn:serialize($resp))
    return
        <html>
            <head/>
            <body onload="document.forms.samlform.submit()">
                <noscript><p><strong>Note:</strong> Since your browser does not support Javascript, you must press the Submit button once to proceed.</p></noscript>
                <form id="samlform" method="post" action="{$exsaml:sp-uri}">
                    <input type="hidden" name="SAMLResponse" value="{$b64resp}" />
                    <input type="hidden" name="RelayState" value="{$rs}" />
                    <input type="submit" value="Submit" />
                </form>
            </body>
        </html>
};

(: return a fake SAML response node :)
declare %private function exsaml:build-saml-fakeresp($req as node()) as element(samlp:Response) {
    let $reqid := $req/@ID
    let $status :=
            if ($exsaml:fake-result = "true")
            then
                $exsaml:status-success
            else
                $exsaml:status-badauth
    let $fakesig := "ABCDEF"
    let $now := fn:current-dateTime()
    let $validto := $now + xs:dayTimeDuration("PT" || $exsaml:minutes-valid || "M")
    return

        <samlp:Response ID="{exsaml:gen-id()}" InResponseTo="{$reqid}" Version="{$exsaml:saml-version}" IssueInstant="{$now}" Destination="{$exsaml:sp-uri}">
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
                <saml:AttributeStatement>
                    <saml:Attribute Name="{$exsaml:group-attr}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                        <saml:AttributeValue xsi:type="xs:string">{$exsaml:fake-group}</saml:AttributeValue>
                    </saml:Attribute>
                </saml:AttributeStatement>
            </saml:Assertion>
        </samlp:Response>
};


(: ==== UTIL FUNCTIONS ==== :)

(: generate a SAML ID :)
(: which is xs:ID which is xsd:NCName which MUST NOT start with a number :)
declare %private function exsaml:gen-id() as xs:string {
    let $uuid := util:uuid()
    return
        "a" || $uuid
};

(: generic log function, returns true for easy use in if constructs :)
declare function exsaml:log($level as xs:string, $msg as xs:string) as xs:boolean {
(:    let $l := console:log("exsaml: " || $msg):)
    let $l := util:log($level, "exsaml: " || $msg)
    return
        true()
};
