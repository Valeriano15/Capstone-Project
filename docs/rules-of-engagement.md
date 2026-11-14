# Rules of engagement

Read this before any active testing. This project is lab software for authorized targets only.
It is not for scanning systems you do not own or do not have written permission to test. This
document does not authorize testing of any external system.

## Before active testing, write down

- Ownership and permission for every target.
- The exact targets and the approved procedures.
- The allowed time window.
- Prohibited actions.
- Stop conditions.
- Cleanup steps.
- How evidence is handled and stored.

## Operating rules

1. Discovery itself must stay within the approved target and test scope.
2. The backend checks authorization. A checkbox in the interface is not a control.
3. Approval binds the target, the module, and the parameters. Changed parameters need renewed
   approval.
4. Unapproved tests stay unexecuted and are visibly marked as not tested.
5. A timeout, an unsupported check, or a failed action is not proof that a system is secure.
6. The reporting model cannot authorize or launch tests.
7. Report revisions keep their link to the underlying evidence.

## Stop conditions

Stop and reassess if any of these happen:

- Unexpected network reachability.
- Activity outside the approved scope.
- Target instability.
- An approval that no longer matches the test being run.
- Any uncertainty about authorization.

## Out of scope for the whole project

- Testing unrelated public systems.
- Unrestricted autonomous exploitation or attack chaining.
- Persistence, credential harvesting, evasion, destructive tests, or denial of service.
- Writing new exploits.
- Training or fine-tuning a language model.

## Lab isolation

- Keep vulnerable targets off public and production networks. Private addressing alone does not
  guarantee isolation.
- Record image versions, snapshot names, tool versions, and reset steps.
- If external reference or model access is needed, isolate it from the targets and restrict it
  to approved use.

## Data handling

- Do not commit secrets, API keys, private tokens, course PDFs, or raw evidence from real
  systems to the repository.
- Commit only sanitized fixtures and measurements suitable for sharing.
- Keep restricted raw evidence in an access-controlled location outside the public repository.

Use NIST SP 800-115 as the methodological reference for assessment planning, testing, findings
analysis, and mitigation.
