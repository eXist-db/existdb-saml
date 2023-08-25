xquery version "3.1";

import module namespace scheduler="http://exist-db.org/xquery/scheduler";

declare variable $local:job-name := "clean-up-sso-reqids";
declare variable $local:cron := "0 0 11 * * ? *";

declare function local:start-job() {
    scheduler:schedule-xquery-cron-job("/db/system/repo/existdb-saml/content/clean-reqids.xql", $local:cron, $local:job-name)
};

declare function local:show-job() {
    let $jobs := scheduler:get-scheduled-jobs()
     return
         $jobs//scheduler:job[@name=$local:job-name]
};

declare function local:stop-job() {
    scheduler:delete-scheduled-job($local:job-name)
};


(:
local:stop-job()
local:start-job()
local:show-job()
:)
<result>
    {local:show-job()}
</result>
