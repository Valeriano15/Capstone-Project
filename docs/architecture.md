# Architecture

This page describes the proposed components, how data flows, and the trust boundaries that keep
the system safe. Every choice here is a proposal until the team agrees and the instructor
approves the scope.

## End-to-end flow

```
Select a lab target
   |
   v
Scope check (backend enforced)   --rejected-->  log and stop
   |
   v
Nmap discovery  ->  parse XML  ->  match candidate vulnerabilities
   |
   v
Human approval of a specific test   --not approved-->  record as not tested
   |
   v
Reviewed Metasploit validation (RPC)
   |
   v
Evidence store (raw output + interpreted finding)
   |
   v
Fixed-template report   and   AI-assisted draft
   |
   v
Human review  ->  export
```

## Proposed technology choices

| Layer | Choice | Role |
| --- | --- | --- |
| Core language | Python | Parsing, validation rules, workflow, reporting |
| Backend | FastAPI | Application API and control enforcement |
| Interface | Streamlit, or React if a teammate already knows it | Target selection, approvals, evidence, review |
| Discovery | Nmap XML output | Structured host, port, and service inventory |
| Validation | Metasploit Framework RPC | The curated test set |
| Application data | SQLite to start | Projects, approvals, jobs, findings, reports |
| Raw evidence | Restricted local files | Original outputs linked to records |
| Vulnerability references | Curated records first, API enrichment later | Applicability, descriptions, severity context |
| AI | One approved model | Evidence-grounded report drafting only |
| Exports | Fixed HTML or PDF templates | Consistent reports |
| Tests | pytest plus controlled lab tests | Behavior and regression checks |

Pick one interface. Do not build both Streamlit and React. Run long jobs in a separate worker so
the interface stays responsive and jobs can be cancelled. Keep any Metasploit-managed database
separate from the application metadata.

## Trust boundaries

| Component | Holds | Never does |
| --- | --- | --- |
| Interface | Submits requests | Holds testing credentials |
| Backend controller | Enforces scope and approvals | Routes lab traffic to production networks |
| Testing worker | Runs only reviewed procedures in the lab | Runs anything unapproved |
| Evidence store | Preserves raw output and derived findings | Edits history |
| AI adapter | Receives sanitized reporting inputs | Authorizes or runs tests |
| Exporter | Renders escaped, reviewed content | Trusts raw untrusted text |

Bind the Metasploit RPC service privately and require authentication. Never expose it publicly.

## Three kinds of status, kept separate

| Category | Examples | Why it matters |
| --- | --- | --- |
| Job state | queued, running, completed, failed, cancelled | A completed job can still be inconclusive |
| Finding interpretation | suspected, confirmed, not observed, inconclusive, not tested | Failure to confirm is not safety |
| Report state | draft, reviewed, approved | A polished AI draft is not approved |

Always keep the original Metasploit result next to the interpretation. Results such as Detected,
Appears, Vulnerable, Unknown, and Unsupported have different meanings.

## AI reporting contract

- Inputs: validated findings, sanitized evidence excerpts, approved references, known
  limitations, and the report template.
- Outputs: structured draft fields, evidence and reference IDs for substantive claims, and
  explicit uncertainty where support is missing.
- Checks: validate the output schema, reject unknown finding or reference IDs, keep locked
  factual fields unchanged, flag unsupported claims, and require human review before export.
- Fallback: if the model is unavailable, keep the evidence and produce the fixed-template report.

Deterministic fields such as target, test result, sourced CVSS metadata, and timestamps come
from application records, not from the model.

## Prompt-injection defense

Service banners, scan output, web pages, and imported text are untrusted. Text inside them must
never become instructions to the controller or the model. Use bounded input, separate
instructions from evidence, validate output, escape displayed text, and keep the model outside
the execution path. Prompt wording alone is not a security boundary.
