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

(: other modules :)
(:import module namespace console="http://exist-db.org/xquery/console";:)

declare variable $exsaml:version := doc("../expath-pkg.xml")/*:package/@version/string();

(: START of configuration Map keys :)
declare %private variable $exsaml:key-enabled := "enabled";
declare %private variable $exsaml:key-sp-ent := "sp-ent";
declare %private variable $exsaml:key-sp-uri := "sp-uri";
declare %private variable $exsaml:key-sp-assertion-consumer-service-index := "sp-assertion-consumer-service-index";
declare %private variable $exsaml:key-sp-fallback-rs := "sp-fallback-rs";
declare %private variable $exsaml:key-idp-ent := "idp-ent";
declare %private variable $exsaml:key-idp-uri := "idp-uri";
declare %private variable $exsaml:key-idp-certfile := "idp-certfile";
declare %private variable $exsaml:key-idp-unsolicited := "idp-unsolicited";
declare %private variable $exsaml:key-idp-force-rs := "idp-force-rs";
declare %private variable $exsaml:key-idp-verify-issuer := "idp-verify-issuer";
declare %private variable $exsaml:key-hmac-key := "hmac-key";
declare %private variable $exsaml:key-hmac-alg := "hmac-alg";
declare %private variable $exsaml:key-group-attr := "group-attr";
declare %private variable $exsaml:key-token-minutes := "token-minutes";
declare %private variable $exsaml:key-token-name := "token-name";
declare %private variable $exsaml:key-token-separator := "token-separator";
declare %private variable $exsaml:key-exsaml-user := "exsaml-user";
declare %private variable $exsaml:key-exsaml-pass := "exsaml-pass";
declare %private variable $exsaml:key-create-user := "create-user";
declare %private variable $exsaml:key-user-group := "user-group";
declare %private variable $exsaml:key-minutes-valid := "minutes-valid";
declare %private variable $exsaml:key-fake-result := "fake-result";
declare %private variable $exsaml:key-fake-user := "fake-user";
declare %private variable $exsaml:key-fake-group := "fake-group";
(: END of configuration Map keys :)

(: SAML specific constants and non-configurable vars :)
declare %private variable $exsaml:saml-coll-reqid := "/db/apps/existdb-saml/saml-request-ids";
declare %private variable $exsaml:saml-version   := "2.0";
declare %private variable $exsaml:status-success := "urn:oasis:names:tc:SAML:2.0:status:Success";
(: debugging only to simulate failure in fake-idp :)
declare %private variable $exsaml:status-badauth := "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
declare variable $exsaml:ERROR :=  xs:QName("saml:error");

(:~
 : Parse an XML configuration for the exsaml module into a Map.
 :
 : @param $doc the XML document to parse the configuration from.
 :
 : @return an XDM map containing the configuration for the exsaml module.
 :)
declare function exsaml:parse-xml-config($doc as document-node(element(config))) as map(xs:string, item()*) {
    let $config := $doc/config
    return
        map {
            $exsaml:key-enabled: $config/@enabled eq "true",
            $exsaml:key-sp-ent: data($config/sp/@entity),
            $exsaml:key-sp-uri: data($config/sp/@endpoint),
            $exsaml:key-sp-assertion-consumer-service-index: $config/sp/@assertion-consumer-service-index ! xs:integer(.),
            $exsaml:key-sp-fallback-rs: data($config/sp/@fallback-relaystate),
            $exsaml:key-idp-ent: data($config/idp/@entity),
            $exsaml:key-idp-uri: data($config/idp/@endpoint),
            $exsaml:key-idp-certfile: data($config/idp/@certfile),
            $exsaml:key-idp-unsolicited: data($config/idp/@accept-unsolicited),
            $exsaml:key-idp-force-rs: $config/idp/@force-relaystate eq "true",
            $exsaml:key-idp-verify-issuer: data($config/idp/@verify-issuer),
            $exsaml:key-hmac-key: data($config/crypto/@hmac-key),
            $exsaml:key-hmac-alg: data($config/crypto/@hmac-alg),
            $exsaml:key-group-attr: $config/group-attribute/text(),
            $exsaml:key-token-minutes: data($config/token/@valid-mins),
            $exsaml:key-token-name: data($config/token/@name),
            $exsaml:key-token-separator: "=",
            $exsaml:key-exsaml-user: data($config/exsaml-creds/@username),
            $exsaml:key-exsaml-pass: data($config/exsaml-creds/@pass),
            $exsaml:key-create-user: data($config/dynamic-users/@create),
            $exsaml:key-user-group: data($config/dynamic-users/@group),
            $exsaml:key-minutes-valid: data($config/fake-idp/@minutes-valid),
            $exsaml:key-fake-result: data($config/fake-idp/@result),
            $exsaml:key-fake-user: data($config/fake-idp/@user),
            $exsaml:key-fake-group: data($config/fake-idp/@group)
        }
};

(:~
 : May be used to check if SAML is enabled at all
 :
 : @param $config the exsaml module configuration.
 :
 : @return true if SAML is enabled, false otherwise.
 :)
declare function exsaml:is-enabled($config as map(xs:string, item()*)) {
    $config($exsaml:key-enabled)
};

(:~
 : Dump current config data.
 :
 : @param $config the exsaml module configuration.
 :)
declare function exsaml:info($config as map(xs:string, item()*)) as map(xs:string, item()*) {
    map {
      'version': $exsaml:version,
      'config': $config
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
 : @param $config the exsaml module configuration.
 :)
declare function exsaml:build-authnreq-redir-url($relaystate as xs:string, $config as map(xs:string, item()*)) {
    let $log := exsaml:log("info", "building SAML auth request redir-url; relaystate: " || $relaystate)
    let $req := exsaml:build-saml-authnreq($config)
    let $log := exsaml:log("debug", "build-authnreq-redir-url; req: " || $req)

    (: deflate and base64 encode request :)
    let $ser := fn:serialize($req)
(:    let $log := exsaml:log("debug", "build-authnreq-redir-url; ser: " || $ser):)
    let $bin := util:string-to-binary($ser)
(:    let $log := exsaml:log("debug", "build-authnreq-redir-url; bin: " || $bin):)
    let $zip := compression:deflate($bin, true())
(:    let $log := exsaml:log("debug", "build-authnreq-redir-url; zip: " || $zip):)
    (: urlencode base64 request data :)
    let $urlenc := xmldb:encode($zip)

    let $log := exsaml:log("debug", "build-authnreq-redir-url; urlenc: " || $urlenc)

    return
        $config($exsaml:key-idp-uri) || "?SAMLRequest=" || $urlenc || "&amp;RelayState=" || xmldb:encode($relaystate)
};

(:~
 : Build and return SAML AuthnRequest node.
 :
 : @param $config the exsaml module configuration.
 :)
declare %private function exsaml:build-saml-authnreq($config as map(xs:string, item()*)) {
    let $id := exsaml:gen-id($config)
    let $instant := fn:current-dateTime()
    let $store := exsaml:store-authnreqid($id, $instant, $config)
    let $req := element { "samlp:AuthnRequest" } {
        attribute ID { $id },
        attribute Version { $exsaml:saml-version },
        attribute IssueInstant { $instant },
        attribute AssertionConsumerServiceIndex { "0" },
        element { "saml:Issuer" } { $config($exsaml:key-sp-ent) }
    }
    return $req
};

declare %private function exsaml:store-authnreqid-as-exsol-user($id as xs:string, $instant as xs:string) {
      let $create-collection := 
        if (        
            not(xmldb:collection-available($exsaml:saml-coll-reqid))
        )
        then (
            let $log := exsaml:log("info", "collection " || $exsaml:saml-coll-reqid || " does not exist, attempting to create it")
            return
                xmldb:create-collection("/db/apps/existdb-saml", "saml-request-ids")
        )
        else ()
    return
        xmldb:store($exsaml:saml-coll-reqid, $id, <reqid>{$instant}</reqid>)
  
};

(:~
 : Store issued request ids in a collection.
 :
 : @param $id The SAML Request ID.
 : @param $instant the instant.
 : @param $config the exsaml module configuration.
 :)
declare %private function exsaml:store-authnreqid($id as xs:string, $instant as xs:dateTime, $config as map(xs:string, item()*)) {
    let $log := exsaml:log("info", "storing SAML request id: " || $id || ", date: " || $instant)
    return
        system:as-user(
                        $config($exsaml:key-exsaml-user),
                        $config($exsaml:key-exsaml-pass),
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
 :
 : @param $config the exsaml module configuration.
 :)
declare function exsaml:process-saml-response-post($config as map(xs:string, item()*)) {
    let $log  := exsaml:log("info", "process-saml-response-post")
    let $saml-resp := request:get-parameter("SAMLResponse", "error")

    let $resp := if($saml-resp = "error")
                    then ($saml-resp)
                    else (
                        let $decode-resp := util:base64-decode($saml-resp)
                        return
                            fn:parse-xml-fragment($decode-resp)
                    )

    let $debug := exsaml:log("debug", "START SAML RESPONSE ")
    let $debug := exsaml:log("debug", $resp)
    let $debug := exsaml:log("debug", "END SAML RESPONSE ")

    return
        if($resp = "error")
            then (
                error($exsaml:ERROR, "Empty SAML Response", "No SAML response data has been provided")
            )
            else (
                try {
    let $res  := exsaml:validate-saml-response($resp, $config)
                    return
                        if($res/@res < 0)
                            then (
                                $res
                            )
                            else (
    let $rsin := request:get-parameter("RelayState", "")
    let $rsout :=
        (: if we accept IDP-initiated SAML *and* use a forced landing page :)
        if ($config($exsaml:key-idp-unsolicited) and $config($exsaml:key-idp-force-rs)) then (
            let $debug := exsaml:log("debug", "evaluated to: $config($exsaml:key-idp-unsolicited) and $config($exsaml:key-idp-force-rs) = 'true'")
            let $debug := exsaml:log("debug", $config($exsaml:key-idp-force-rs) is: " || $config($exsaml:key-idp-force-rs) || " evaluated: " || string-length($config($exsaml:key-idp-force-rs)))
            return
                $config($exsaml:key-idp-force-rs)
        )
        (: otherwise accept relaystate from the SAML response :)
        else if ($rsin != "") then (
            let $debug := exsaml:log("info", "Relay State as provided by SSO: " || $rsin)
            return $rsin
        ) else (
            let $debug := exsaml:log("info", "no Relay State provided by SSO, switching to SP fallback relaystate: " || $config($exsaml:key-sp-fallback-rs))
            return 
                $config($exsaml:key-sp-fallback-rs)
        )

    (: Return an element with all SAML validation data to the controller.
       If SAML success, this is basically username and group membership.
       IF SAML fail, pass enough info to allow meaningful error messages. :)
    let $auth := element { "authresult" } {
        attribute code   { $res/@res },
        attribute msg    { $res/@msg },
        attribute nameid { $resp/saml:Assertion/saml:Subject/saml:NameID },
        attribute relaystate { $rsout },
        attribute authndate  { $resp/saml:Assertion/@IssueInstant },
        element { "groups" } {
            for $i in exsaml:fetch-saml-attribute-values($config($exsaml:key-group-attr), $resp/saml:Assertion)
            return element { "group" } { $i }
        }
    }
    (: create SAML user if not exists yet :)
    let $u :=
        if ($config($exsaml:key-create-user) = "true" and $auth/@code >= "0") then
            exsaml:ensure-saml-user($auth/@nameid, $config)
        else ""

    let $pass := exsaml:create-user-password($auth/@nameid, $config)
    let $log-in := xmldb:login("/db/apps", $auth/@nameid, $pass, true())
    let $log := util:log("info", "login result: " || $log-in || ", " || fn:serialize(sm:id()))

    (: put SAML token into browser session :)
    let $sesstok :=
        if ($log-in and $auth/@code >= "0") then
            exsaml:set-saml-token($auth/@nameid, $auth/@authndate, $config)
        else ()

                                let $debug := exsaml:log("info", "finished exsaml:process-saml-response-post. auth: ")
                                let $debug := exsaml:log("info", fn:serialize($auth))
    return $auth
                        )
                }  catch * {
                        <error>Caught error {$err:code}: {$err:description}. Data: {$err:value}</error>
                }
            )
};

(:~
 : Validate a SAML response message.
 :
 : @param $resp the XML document containing the SAML Response.
 : @param $config the exsaml module configuration.
 :
 : @return an element indicating the result of the validation.
 :)
declare %private function exsaml:validate-saml-response($resp as node(), $config as map(xs:string, item()*)) {
    let $log  := exsaml:log("info", "validate-saml-response")

    let $as := $resp/saml:Assertion
    let $sig := $resp/ds:Signature
    let $result :=

    (: check SAML response status. there are ~20 failure codes, check
     : for success only, return errmsg in @data
     :)
        if (not($resp/samlp:Status/samlp:StatusCode/@Value = $exsaml:status-success)) then
            <exsaml:funcret res="-3" msg="SAML authentication failed" data="{$resp/samlp:Status/samlp:StatusCode/@Value}"/>

        (: check that "Issuer" is the expected IDP.  Not stricty required by
           SAML specs, but adds extra protection against forged SAML responses. :)
        else if ($config($exsaml:key-idp-verify-issuer) = "true" and boolean($resp/saml:Issuer) and not($resp/saml:Issuer = $config($exsaml:key-idp-ent))) then (
            let $msg := "SAML response from unexpected IDP: " || $resp/saml:Issuer
            return
                <exsaml:funcret res="-6" msg="{$msg}" data="{$resp/saml:Issuer}"/>
        )
        
        (: verify response signature if present :)
(: COMMENTED OUT until crypto-lib issues resolved :)
(:        else if (boolean($sig) and not(exsaml:verify-response-signature($sig, $config))) then :)
(:            <exsaml:funcret res="-4" msg="failed to verify response signature" /> :)

        (: must contain at least one assertion :)
        else if (empty($as)) then (
                <exsaml:funcret res="-5" msg="no assertions present" />
        )
            (: validate all assertions - only first by now :)
            else (
                exsaml:validate-saml-assertion($as, $config)
            )

    return $result
};

(:~
 : Validate a SAML assertion.
 :
 : @param $assertion The SAML assertion to validate.
 : @param $config the exsaml module configuration.
 :
 : @return an element indicating the result of the validation.
 :)
declare %private function exsaml:validate-saml-assertion($assertion as item(), $config as map(xs:string, item()*)) {
    if(empty($assertion))
    then (
        let $log := exsaml:log("info", "Error: Empty Assertion")
        return
            <exsaml:funcret res="-19" msg="no assertion present" />

    )
    else (
        let $log := exsaml:log("info", "validate-saml-assertion: " || fn:serialize($assertion))
        let $sig := $assertion/ds:Signature
        let $subj-confirm-data := $assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData
        let $conds := $assertion/saml:Conditions
        let $reqid := $subj-confirm-data/@InResponseTo

        let $result :=

            (: check that "Issuer" is the expected IDP.  Not stricty required by
               SAML specs, but adds extra protection against forged SAML responses. :)

            if ($config($exsaml:key-idp-verify-issuer) = "true" and boolean($assertion/saml:Issuer) and not($assertion/saml:Issuer = $config($exsaml:key-idp-ent))) then (
                let $msg := "SAML assertion from unexpected IDP: " || $assertion/saml:Issuer
                return
                    <exsaml:funcret res="-18" msg="{$msg}" data="{$assertion/saml:Issuer}"/>
            )

            (: verify assertion signature if present :)
(: COMMENTED OUT until crypto-lib issues resolved :)
(:            else if (boolean($sig) and not(exsaml:verify-assertion-signature($assertion, $config))) then :)
(:                <exsaml:funcret res="-10" msg="failed to verify assertion signature" /> :)

            (: maybe verify SubjectConfirmation/@Method :)

            (: verify SubjectConfirmationData/@Recipient is SP URL ($sp-uri) :)
            else if (not($subj-confirm-data/@Recipient = $config($exsaml:key-sp-uri)))
            then
                <exsaml:funcret res="-11" msg="assertion not for me" data="{$subj-confirm-data/@Recipient}"/>

            (: verify SubjectConfirmationData/@NotOnOrAfter is not later than now :)
            else if (xs:dateTime(fn:current-dateTime()) >= xs:dateTime($subj-confirm-data/@NotOnOrAfter)) then
                    <exsaml:funcret res="-12" msg="assertion no longer valid" data="{$subj-confirm-data/@NotOnOrAfter}"/>

            (: verify SubjectConfirmationData/@InResponseTo is present in the SAML response :)
            else if (not($reqid)) then (
                if ($config($exsaml:key-idp-unsolicited)) then (
                    <exsaml:funcret res="1" msg="accept unsolicited SAML response"/>
                )
                else (
                    <exsaml:funcret res="-17" msg="reject unsolicited SAML response"/>
                )
            )

            (: else verify SubjectConfirmationData/@InResponseTo equal to orig AuthnRequest ID :)
            else if (not(exsaml:check-authnreqid($reqid, $config))) then (
                    <exsaml:funcret res="-13" msg="did not send this SAML request" data="{$subj-confirm-data/@InResponseTo}"/>
            )

            (: verify assertions are valid in other respects - none yet :)

            (: verify Conditions/@NotBefore is not earlier than now :)
            else if (xs:dateTime(fn:current-dateTime()) < xs:dateTime($conds/@NotBefore)) then (
                    <exsaml:funcret res="-14" msg="condition not yet valid" data="{$conds/@NotBefore}"/>
            )

            (: verify Conditions/@NotOnOrAfter is not later than now :)
            else if (xs:dateTime(fn:current-dateTime()) >= xs:dateTime($conds/@NotOnOrAfter)) then (
                    <exsaml:funcret res="-15" msg="condition no longer valid" data="{$conds/@NotOnOrAfter}"/>
            )

            (: verify Conditions/AudienceRestriction/Audience is myself ($sp-ent) :)
            else if (not($conds/saml:AudienceRestriction/saml:Audience = $config($exsaml:key-sp-ent))) then
                    <exsaml:funcret res="-16" msg="audience not for me" data="{$conds/saml:AudienceRestriction/saml:Audience}"/>

            else
                <exsaml:funcret res="0" msg="ok" />

        return $result
    )
};

(:~
 : Retrieve issued SAML request id and delete if answered.
 :
 : @param $reqid the SAML Request ID.
 : @param $config the exsaml module configuration.
 :
 : @param true if the SAML Request ID is valid, false otherwise. 
 :)
declare %private function exsaml:check-authnreqid($reqid as xs:string, $config as map(xs:string, item()*)) {
    let $log := exsaml:log("info", "verifying SAML request id: " || $reqid)
    return
        if (system:as-user($config($exsaml:key-exsaml-user), $config($exsaml:key-exsaml-pass),
                exists(doc($exsaml:saml-coll-reqid||"/"||$reqid)) and empty(xmldb:remove($exsaml:saml-coll-reqid, $reqid)))) then
            $reqid
        else ""
};

(:~
 : Verify XML signature of a SAML response.
 :
 : @param $resp the SAML response.
 : @param $config the exsaml module configuration.
 :)
declare %private function exsaml:verify-response-signature($resp as item(), $config as map(xs:string, item()*)) {
    let $log  := exsaml:log("debug", "verify-response-signature: " || $resp)
    let $res :=
        (: if $idp-certfile is configured, use that to validate XML signature :)
        if (exists($config($exsaml:key-idp-certfile))) then (
(:            crypto:validate-signature-by-certfile($resp, $config($exsaml:key-idp-certfile)):)
        )
        else (
            let $log  := exsaml:log("info", "cert to verify response signature is missing - could not verify signature! ")
            return
                false()
        )
    return $res
};

(:~
 : Verify XML signature of a SAML assertion.
 :
 : @param $assertion The SAML assertion to validate the signature of.
 : @param $config the exsaml module configuration.
 :
 : @return true of the signature is valid, false otherwise.
 :)
declare %private function exsaml:verify-assertion-signature($assertion as item(), $config as map(xs:string, item()*)) {
    let $log  := exsaml:log("debug", "verify-assertion-signature " || $assertion)
    let $res :=
        (: if $idp-certfile is configured, use that to validate XML signature :)
        if (exists($config($exsaml:key-idp-certfile))) then (
(:            crypto:validate-signature-by-certfile($assertion, $config($exsaml:key-idp-certfile)):)
        )
        else (
            let $log  := exsaml:log("info", "cert to verify assertion signature is missing - could not verify signature! ")
            return
                false()
        )
    return $res
};

(: Fetch the named SAML attribute values from a SAML assertion.  This is
   used to get group membership of an authenticated user, which gets passed
   as SAML attribute assertions by the IDP :)
declare %private function exsaml:fetch-saml-attribute-values($attrname as xs:string, $as as node()) {
    let $log := exsaml:log("debug", "fetch-saml-attribute " || $attrname || ", " || fn:serialize($as))
    let $seq :=
        for $a in $as/saml:AttributeStatement/saml:Attribute[@Name=$attrname]/saml:AttributeValue
        return $a/text()
    let $log := exsaml:log("debug", "fetch-saml-attribute: " || fn:serialize($seq))
    return $seq
};

(:~
 : This function is used to create the named DB user on the fly if the
 : account does not exist yet.  Since we rely on SAML to assert that a
 : certain username is valid, we have no list of usernames upfront, but
 : create them on the fly.  This allows to store per-user preferences and
 : settings.
 :
 : @param $nameid the name for the user account.
 : @param $config the exsaml module configuration.
 :)
declare %private function exsaml:ensure-saml-user($nameid as xs:string, $config as map(xs:string, item()*)) {
    let $pass := exsaml:create-user-password($nameid, $config)
    return
        (: run as user exsaml, group dba :)
        system:as-user($config($exsaml:key-exsaml-user), $config($exsaml:key-exsaml-pass),
                       if (not(sm:user-exists($nameid))
                           and exsaml:log("info", "create new user account " || $nameid || ", group " || $exsaml:user-group)) then
                           sm:create-account($nameid, $pass, $config($exsaml:key-user-group), ())
                       else ())
};

(: create user password as HMAC of username :)
declare %private function exsaml:create-user-password($nameid as xs:string, $config as map(xs:string, item()*)) {
    let $key  := $config($exsaml:key-hmac-key) || ""
    let $alg  := $config($exsaml:key-hmac-alg) || ""
    let $pass := crypto:hmac($nameid, $key, $alg, "hex")
    return $pass
};


(: ==== FUNCTIONS TO DEAL WITH TOKENS ==== :)

(:~
 : Check whether a SAML token exists and is valid.  Return boolean.
 : This is called from the controller(s) to check if access should be granted.
 :
 : @param $config the exsaml module configuration.
 :)
declare function exsaml:check-valid-saml-token($config as map(xs:string, item()*)) {
    let $raw  := session:get-attribute($config($exsaml:key-token-name))
    let $log  := exsaml:log("debug", "checking saml token, name: " || $exsaml:token-name || ", value: " || $raw)

    let $tokdata := fn:tokenize($raw, $config($exsaml:key-token-separator))
    return
        if (empty($raw) and exsaml:log("info", "no token found")) then
            false()
        else if (not($tokdata[3] eq exsaml:hmac-tokval($tokdata[1] || $config($exsaml:key-token-separator) || $tokdata[2], $config))
                and exsaml:log("info", "token is invalid")) then
            false()
        else if (xs:dateTime(fn:current-dateTime()) gt xs:dateTime($tokdata[2])
                 and exsaml:log("info", "token has expired")) then
            false()
        else
            true()
};

(:~
 : Invalidate a SAML token, by creating one with expire date in the past,
 : so that it will fail token expiration checks.
 : This is called from the controller(s) upon user logout.
 :
 : @param $config the exsaml module configuration.
 :)
declare function exsaml:invalidate-saml-token($config as map(xs:string, item()*)) {
    let $user := sm:id()/sm:id/sm:real/sm:username
    let $tok  := exsaml:build-string-token($user, "1970-01-01T00:00:00", $config)
    let $hmac := exsaml:hmac-tokval($tok, $config)
    let $log  := exsaml:log("info", "invalidate saml token for: " || $user || ", hmac: " || $hmac)
    let $session-attr := session:set-attribute($config($exsaml:key-token-name), $tok || $config($exsaml:key-token-separator) || $hmac)

    return $session-attr
};

(:~ Return the HMAC of the string token passed in.
 :
 : @param $tokval the token.
 : @param $config the exsaml module configuration.
 :
 : @return the HMAC.
 :)
declare %private function exsaml:hmac-tokval($tokval as xs:string, $config as map(xs:string, item()*)) as xs:string {
    let $log  := exsaml:log("debug", "hmac-tokval; t: " || $tokval || ", key: " || $config($exsaml:key-hmac-key))
    let $key  := $config($exsaml:key-hmac-key) || ""
    let $alg  := $config($exsaml:key-hmac-alg) || ""
    return
        crypto:hmac($tokval, $key, $alg, "hex")
};

(:~
 : Build string token: join nameid and validto by $config($exsaml:key-token-separator).
 :
 : @param $nameid the user name.
 : @param $validto the expiry date in ISO format.
 : @param $config the exsaml module configuration.
 :
 : @return the token.
 :)
declare %private function exsaml:build-string-token($nameid as xs:string, $validto as xs:string, $config as map(xs:string, item()*)) as xs:string {
    let $log  := exsaml:log("debug", "build-string-token; n: " || $nameid || ", v: " || $validto)
    return $nameid || $config($exsaml:key-token-separator) || $validto
};

(:~
 : Build and HMAC token and stuff into browser session.
 : 
 : @param $nameid the user name.
 : @param $authndate the auth date.
 : @param $config the exsaml module configuration.
 :)
declare %private function exsaml:set-saml-token($nameid as xs:string, $authndate as xs:string, $config as map(xs:string, item()*)) {
    let $validto := xs:dateTime($authndate) + xs:dayTimeDuration("PT" || $config($exsaml:key-token-minutes) || "M")

    let $tok := exsaml:build-string-token($nameid, $validto, $config)
    let $hmac := exsaml:hmac-tokval($tok, $config)
    let $log  := exsaml:log("info", "set saml token for: " || $nameid || ", authndate: " || $authndate || ", valid until: " || $validto || ", hmac: " || $hmac)
    return session:set-attribute($config($exsaml:key-token-name), $tok || $config($exsaml:key-token-separator) || $hmac)
};


(: ==== FUNCTIONS TO FAKE A SAML IDP (testing only) ==== :)

(: process SAML AuthnRequest, return SAML Response via POST :)
declare function exsaml:process-saml-request($config as map(xs:string, item()*)) {
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

    let $resp := exsaml:fake-idp-response($req, $rs, $config)
    return $resp
};

(: fake SAML IDP response: build response and return via XHTML autosubmit form :)
declare %private function exsaml:fake-idp-response($req as node(), $rs as xs:string, $config as map(xs:string, item()*)) {
    let $log := exsaml:log("debug", "fake-idp-response")
    let $resp := exsaml:build-saml-fakeresp($req, $config)
    let $b64resp := util:base64-encode(fn:serialize($resp))

    return
        <html><head/>
            <body onload="document.forms.samlform.submit()">
                <noscript><p><strong>Note:</strong> Since your browser does not support Javascript, you must press the Submit button once to proceed.</p></noscript>
                <form id="samlform" method="post" action="{$config($exsaml:key-sp-uri)}">
                    <input type="hidden" name="SAMLResponse" value="{$b64resp}" />
                    <input type="hidden" name="RelayState" value="{$rs}" />
                    <input type="submit" value="Submit" />
                </form>
            </body></html>
};

(: return a fake SAML response node :)
declare %private function exsaml:build-saml-fakeresp($req as node(), $config as map(xs:string, item()*)) {
    let $reqid := $req/@ID
    let $status  :=
        if($config($exsaml:key-fake-result) = "true") then $exsaml:status-success
        else $exsaml:status-badauth
    let $fakesig := "ABCDEF"
    let $now     := fn:current-dateTime()
    let $validto := $now + xs:dayTimeDuration("PT" || $config($exsaml:key-minutes-valid) || "M")
    let $resp    :=  element { "samlp:Response" } {
        attribute ID { exsaml:gen-id() },
        attribute InResponseTo { $reqid },
        attribute Version { $exsaml:saml-version },
        attribute IssueInstant { $now },
        attribute Destination { $config($exsaml:key-sp-uri) },
        element { "saml:Issuer" } { $config($exsaml:key-idp-ent) },
        element { "samlp:Status" } {
            element { "samlp:StatusCode" } {
                attribute Value { $status }
            }
        },
        element { "saml:Assertion" } {
            attribute ID { exsaml:gen-id() },
            attribute Version { $exsaml:saml-version },
            attribute IssueInstant { $now },
            element { "saml:Issuer" } { $exsaml:idp-ent },
            element { "ds:Signature" } { $fakesig },
            element { "saml:Subject" } {
                element { "saml:NameID" } {
                    attribute Format { "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" },
                    $config($exsaml:key-fake-user)
                },
                element { "saml:SubjectConfirmation" } {
                    attribute Method { "urn:oasis:names:tc:SAML:2.0:cm:bearer" },
                    element { "saml:SubjectConfirmationData"} {
                        attribute InResponseTo { $reqid },
                        attribute Recipient { $config($exsaml:key-sp-uri) },
                        attribute NotOnOrAfter { $validto }
                    }
                }
            },
            element { "saml:Conditions" } {
                attribute NotBefore { $now },
                attribute NotOnOrAfter { $validto },
                element { "saml:AudienceRestriction" } {
                    element { "saml:Audience" } { $config($exsaml:key-sp-ent) }
                }
            },
            element { "saml:AuthnStatement" } {
                attribute AuthnInstant { $now },
                attribute SessionIndex { exsaml:gen-id() },
                element { "saml:AuthnContext" } {
                    element { "saml:AuthnContextClassRef" } { "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" }
                }
            },
            element { "saml:AttributeStatement" } {
                element { "saml:Attribute" } {
                    attribute Name { $config($exsaml:key-group-attr) },
                    attribute NameFormat { "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" },
                    element { "saml:AttributeValue" } {
                        attribute xsi:type { "xs:string" },
                        $config($exsaml:key-fake-group)
                    }
                }
            }
        }
    }

    return $resp
};


(: ==== UTIL FUNCTIONS ==== :)

(: generate a SAML ID :)
(: which is xs:ID which is xsd:NCName which MUST NOT start with a number :)
declare %private function exsaml:gen-id() {
    let $uuid := util:uuid()
    return "a" || $uuid
};

(: generic log function, returns true for easy use in if constructs :)
declare function exsaml:log($level as xs:string, $msg as xs:string) {
(:    let $l := console:log("exsaml: " || $msg):)
    let $l := util:log($level, "exsaml: " || $msg)
    return true()
};
