---
name: scan-report
description: Generate a detailed security report and slide presentation from Metasploit MCP scan results, enriched with live threat intelligence. Use whenever the user asks for a report, write-up, or presentation of scan findings.
---

# Scan report & presentation

## Goal

After a scan completes (or on demand from the Metasploit database), produce
two artifacts in `reports/<YYYY-MM-DD_HHMM>/` next to `server.py`:

1. `report.md` — the detailed findings report
2. `slides.html` — a self-contained presentation (plain HTML/CSS + minimal
   JavaScript, no CDN, works offline)

## Step 1 — Collect scan evidence

- `msf_scan_results(uuid)` for the most recent scan (poll until not running).
- `msf_db_hosts`, `msf_db_services`, `msf_db_vulns` for the recorded picture.
- Keep the raw outputs for the appendix.

## Step 2 — Fill gaps: service + version fingerprinting

CVE lookup needs versions, not just ports. If `msf_db_services` shows empty
`name`/`info` fields, run in-scope fingerprinting modules first and then
re-read the database:

- `scanner/portscan/tcp` — open port inventory
- `scanner/ssh/ssh_version` — SSH banner/version
- `scanner/http/http_version` — web server fingerprint
- `scanner/smb/smb_version` — SMB/Windows fingerprint

Do not guess versions. If a fingerprint is inconclusive, report the port as
"unidentified service" and say so.

## Step 3 — Threat-intelligence enrichment

For each service/version finding:

1. `msf_cve_lookup("<service> <version>")` — e.g. `msf_cve_lookup("openssh 8.9p1")`
   or `msf_cve_lookup("CVE-2021-44228")`. Prefer several precise queries over
   one broad one. Stay within `limit` ~5 per query.
2. For CVEs flagged in `kev` (actively exploited) or with CVSS >= 7.0, run
   `msf_exploit_availability("CVE-...")` to check for public Metasploit
   exploit modules.
3. Note the `attck` mappings per finding (techniques, threat actors, and
   software tied to the CVE — each with its citation).
4. If feeds are stale (`sources.kev.catalog_date` older than a day), run
   `msf_refresh_intel(include_attack=False)` — and once per engagement run it
   with ATT&CK enabled so technique mappings are available.

## Step 4 — Assess severity

Priority order per finding:

1. KEV actively-exploited (highest)
2. Public exploit module exists
3. CVSS base score (Critical 9.0+, High 7.0+, Medium 4.0+, Low)

## Step 5 — Write report.md

Sections, in order:

1. **Executive summary** — scope, targets, top risks in 3–5 bullets.
2. **Methodology** — modules run, intelligence sources with dates
   (KEV catalog date, ATT&CK download date, NVD lookup date).
3. **Findings overview** — table:
   `Severity | Host:Port | Service/Version | CVE | CVSS | KEV | Public exploit`
4. **Detailed findings** — one subsection per finding: description, evidence
   (banner/scan output excerpt), CVE details, ATT&CK mapping, references
   (URLs from the CVE record and technique pages).
5. **Remediation & defense** — per finding: patch/upgrade path, configuration
   hardening, network controls, detection (log sources, IDS rules), and the
   CISA KEV `required_action` verbatim when present.
6. **Appendix** — trimmed raw tool outputs.

## Step 6 — Write slides.html

Self-contained slide deck (CSS page-sized sections + arrow-key/click
navigation, no external assets). 8–12 slides:

1. Title (engagement name, date, prepared by Claude + Metasploit MCP)
2. Scope & methodology
3. Findings overview table
4–8. Top findings (one slide each: port, service, CVE, CVSS, KEV badge,
   exploit availability, one-line remediation)
9. Remediation priorities (ordered list)
10. Summary / next steps

## Rules

- Every claim cites its source: scan evidence, an NVD CVE record, a KEV
  entry, an ATT&CK technique, or a Metasploit module name. No invented CVEs,
  versions, or scores.
- Clearly flag when a public exploit exists, but never run exploit modules —
  this server cannot, and the engagement is scan/assessment only.
- Quote CISA KEV `required_action` text verbatim when present.
- Write for an operator who will act on the report: concrete commands and
  steps, not vague advice.
