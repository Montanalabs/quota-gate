#! VULNERABLE quota-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant provision

let raw = fetch<web>
using provision { privileged { provision(raw) } }  # tainted -> tool: REJECTED
