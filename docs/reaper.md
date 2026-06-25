# TTL reaper — why EventBridge, not a scheduled GitHub workflow

GitHub disables `schedule:` workflows after 60 days of repo inactivity. A reaper
is a safety backstop precisely for periods of inactivity, so it must NOT depend
on GitHub's scheduler. We run it as **EventBridge Scheduler (rate 1 hour) →
Lambda**, which queries the Resource Groups Tagging API for resources tagged
`project=ident-fed-demo` with `expires-at` in the past and runs `cloud-nuke`
scoped to that tag. pr-teardown destroys on PR close; this reaper catches
orphans (cancelled runs, failed destroys). Infracost guardrail keeps cost ~$0.
