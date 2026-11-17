<p align="center">
  <img src="docs/assets/logo.svg" alt="AI-Assisted Pentest and Reporting" width="520">
</p>

<h1 align="center">AI-Assisted Automated Penetration Testing and Security Report Generation Using Metasploit</h1>

<p align="center">
  <b>CYB 691 Cybersecurity Capstone</b> &nbsp;|&nbsp; Pace University, Seidenberg School &nbsp;|&nbsp; Fall 2026 &nbsp;|&nbsp; Group 1
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-in%20development-0ea5e9">
  <img src="https://img.shields.io/badge/python-3.14-2dd4bf">
  <img src="https://img.shields.io/badge/lab%20use%20only-authorized%20targets-f59e0b">
  <img src="https://img.shields.io/badge/human%20in%20the%20loop-required-334155">
</p>

---

## What this project is

A private, human-supervised lab application that assists selected phases of an authorized
penetration test and then helps draft the security report. The workflow is:

```
Authorized target  ->  Scope check  ->  Discovery scan  ->  Candidate match
      ->  Human approval  ->  Reviewed Metasploit validation  ->  Evidence store
      ->  Threat-intel enrichment  ->  AI-assisted report draft  ->  Human review and export
```

The AI component only drafts reporting text from stored evidence and public
threat-intelligence feeds. It has no authority to launch tests, change factual
fields, or invent findings. A person approves every test and reviews every
report before export.

The research question we are answering:

> Does a human-supervised, AI-assisted Metasploit workflow reduce assessment and reporting
> effort while maintaining evidence accuracy in a controlled lab?

To answer it we compare three conditions on the same evidence: fully manual, automated with a
fixed template and no AI, and automated with an AI-assisted draft.

## Why it matters

An assessment usually spans separate discovery tools, vulnerability references, validation
steps, scattered evidence files, and a hand-written report. This project tests whether a
bounded integration of those steps saves operator effort without losing traceability or
accuracy, and whether an AI drafting step adds anything measurable on top of plain automation.

## Scope and safety rules

This is lab software for authorized targets only. It is not a tool for scanning systems you do
not own or have written permission to test.

- The backend enforces scope. A checkbox in the interface is never enough.
- Approval binds a specific target, module, and parameters. Changed parameters need re-approval.
- Unapproved tests stay unexecuted and are shown as not tested.
- A timeout or a failed check is not proof that a system is secure.
- The reporting model cannot authorize or run anything.
- No persistence, credential harvesting, evasion, destructive tests, or denial of service.

See [docs/rules-of-engagement.md](docs/rules-of-engagement.md) before any active testing.

## Repository layout

```
Capstone-Project/
├─ README.md                 you are here
├─ server.py                 FastMCP tool server entry point
├─ msf_client.py             msfrpcd RPC layer + scan-only scope enforcement
├─ intel_client.py           NVD / CISA KEV / MITRE ATT&CK lookups (read-only)
├─ tests/                    unit + mock-msfrpcd integration tests
├─ .claude/skills/scan-report/
│  └─ SKILL.md               report.md + slides.html generation workflow
├─ capstone/                 early stub (inner package named `mcp`; see roadmap)
└─ docs/                     team materials, start here if you just cloned this
   ├─ onboarding.md          read-me-first guide for new team members
   ├─ architecture.md        components, data flow, and trust boundaries
   ├─ roadmap.md             condensed build plan and milestones
   ├─ roles.md               who owns what
   ├─ references.md          standards, tool docs, and reading list
   ├─ glossary.md            shared vocabulary
   └─ assets/                logo and images
```

Note on the stub: the code in `capstone/` is an early stub and does not run yet because
its inner package is named `mcp`, which collides with the official `mcp` SDK that the server
depends on. The fix and the full plan are tracked in [docs/roadmap.md](docs/roadmap.md).
The working prototype lives at the repository root (`server.py`, `msf_client.py`,
`intel_client.py`).

## Quick start for team members

1. Read [docs/onboarding.md](docs/onboarding.md). It is a complete brief on the course, the
   project, the rules, and what is expected.
2. Skim [docs/architecture.md](docs/architecture.md) so the component names make sense.
3. Check [docs/roles.md](docs/roles.md) for your area and your backup reviewer.
4. Keep [docs/references.md](docs/references.md) open while you build.

---

# Metasploit MCP Server (scan/assessment only)

A FastMCP server that lets Claude drive a **remote Metasploit Framework** host
through its `msfrpcd` RPC API. It is deliberately limited to **auxiliary
scanning and information-gathering modules** — no exploits, payloads,
post-exploitation, or sessions.

```
Claude Code  --stdio-->  server.py  --msgpack/HTTPS-->  msfrpcd on lab host
                          |
                          +-- msf_client.py    (scope enforcement, RPC client)
                          +-- intel_client.py  (NVD/KEV/ATT&CK, public feeds)
```

## Safety model

The MCP layer enforces four controls in code:

1. **Auxiliary modules only.** `module_name` is normalized and checked; exploit,
   payload, post, encoder, and session APIs are never exposed.
2. **Module prefix allowlist.** Default scope is `scanner/`, `gather/`, and
   `analyze/`. `dos/` and `fuzzers/` are always refused.
3. **Target allowlist required for execution.** `msf_run_module` refuses to
   start unless `MSF_ALLOWED_TARGETS` is set, and every `RHOSTS`/`RHOST` token
   must fall inside it.
4. **Database tools are read-only.** No DB writes are exposed.

> `msfrpcd` itself is a full Metasploit control channel. Anyone who has its
> password can run exploits, regardless of what this MCP server exposes. Treat
> the RPC endpoint as sensitive: strong password, lab-only binding, firewall
> rules, and never expose port 55553 to the internet.

## 1. Prepare the remote Metasploit host

On the Kali/Parrot lab host:

```bash
# One-time database setup (optional but recommended; scanners report into it)
sudo msfdb init

# Start the RPC daemon. SSL is ON by default; do NOT pass -S (that disables it).
# Bind to the lab interface rather than 0.0.0.0 when possible.
sudo msfrpcd -P 'use-a-long-random-password' -U msf -a 192.168.56.10 -p 55553
```

Notes:

- `-a 0.0.0.0` listens on every interface. Only use it if the lab firewall
  restricts port 55553 to your Windows host.
- Do not use `-j`; `pymetasploit3` speaks the standard MessagePack RPC, not
  JSON-RPC.
- Do not use `-n` if you want results available through the database tools.
- Verify it is listening: `ss -ltnp | grep 55553`.
- Example firewall rule (adjust source to your Windows host):
  `sudo ufw allow from 192.168.56.1 to any port 55553 proto tcp`

The Windows host must be able to reach that address and port (an SSH tunnel
works too, e.g. `ssh -N -L 55553:127.0.0.1:55553 user@lab-host`).

## 2. Configure the MCP server environment

All configuration comes from environment variables:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MSF_HOST` | yes | — | Remote msfrpcd host/IP |
| `MSF_PORT` | no | `55553` | RPC port |
| `MSF_USERNAME` | no | `msf` | RPC username |
| `MSF_PASSWORD` | yes | — | RPC password |
| `MSF_SSL` | no | `true` | TLS to msfrpcd (matches msfrpcd default) |
| `MSF_ALLOWED_TARGETS` | for execution | — | Comma-separated IPs/CIDRs/hostnames. Execution is locked when unset. |
| `MSF_ALLOWED_MODULE_PREFIXES` | no | `scanner/,gather/,analyze/` | Comma-separated auxiliary prefixes allowed to run |
| `MSF_NVD_API_KEY` | no | — | Free NVD API key (raises rate limit ~5→~50 req/30 s) |
| `MSF_INTEL_CACHE_DIR` | no | `intel_cache/` next to the code | Where threat-intel responses are cached |

`MSF_ALLOWED_TARGETS` accepts:

- exact IPs — `192.168.56.10`
- CIDRs — `192.168.56.0/24` (a target CIDR must be fully inside an allowed CIDR)
- Metasploit ranges — `192.168.56.10-20` (both endpoints must be inside the scope)
- exact hostnames — `target.lab.example` (hostname matching is exact only)

## 3. Register the server with Claude Code

Copy `.mcp.json.example` to `.mcp.json` in this directory, fill in the host,
password, and target scope, then start Claude Code from the project directory
and approve the project MCP server.

Equivalent CLI registration:

```bash
claude mcp add metasploit -e MSF_HOST=192.168.56.10 -e MSF_PASSWORD=your-rpc-password -e MSF_ALLOWED_TARGETS=192.168.56.0/24 -- "C:\Users\valna\Desktop\capstone\mcp\.venv\Scripts\python.exe" "C:\Users\valna\Desktop\capstone\server.py"
```

Use `/mcp` inside Claude Code to confirm the server is connected. `.mcp.json`
contains a plaintext password — it is gitignored; keep it that way.

## 4. Tools exposed to Claude

| Tool | Purpose |
|---|---|
| `msf_status` | Connection, version, DB status, job count, and enforced scope |
| `msf_search_auxiliary` | Search in-scope auxiliary modules |
| `msf_module_info` | Description, references, and options for one module |
| `msf_run_module` | Start an in-scope auxiliary module as a job |
| `msf_scan_results` | Poll the result tracker for a job UUID |
| `msf_list_jobs` | List running jobs |
| `msf_stop_job` | Stop a job by numeric ID |
| `msf_db_hosts` / `msf_db_services` / `msf_db_vulns` | Read-only database views |
| `msf_cve_lookup` | NVD + CISA KEV + MITRE ATT&CK enrichment for a CVE or keyword |
| `msf_exploit_availability` | Read-only: which Metasploit modules exist for a CVE |
| `msf_refresh_intel` | Re-download the KEV and ATT&CK feeds |

Example prompts:

- "Check the Metasploit connection and tell me what scope is enforced."
- "Search for SMB version scanners."
- "Run `scanner/smb/smb_version` against 192.168.56.10 with 4 threads."
- "Poll the scan results until it finishes, then list the hosts Metasploit recorded."
- "What threat intelligence is there for openssh 9.2p1?"
- "Does Metasploit have an exploit module for CVE-2021-44228?"
- "Write me a scan report with a presentation." (uses the `scan-report` skill)

Typical flow: `msf_status` → `msf_search_auxiliary` → `msf_module_info` →
`msf_run_module` → `msf_scan_results` (poll) → `msf_db_hosts`/`msf_db_services`
→ `msf_cve_lookup` per finding → `msf_exploit_availability` for the worst CVEs
→ `scan-report` skill writes `report.md` + `slides.html`.

`msf_scan_results` returns the result tracker in full, without pagination. Keep
demo scans small (a `/24` or narrower) and use the DB tools for larger
assessments so a large result does not flood Claude's context.

## 5. Threat intelligence & reporting

The three threat-intel tools are read-only and only talk to public feeds —
they never touch the scan target:

| Source | Data | Refresh |
|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE details, CVSS score/severity, weaknesses, references | per-query cache, 7 days |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | actively-exploited status, remediation due dates, ransomware use | 24 hours |
| [MITRE ATT&CK](https://attack.mitre.org/) | software + technique mappings for CVEs | 7 days |

- Responses are cached under `intel_cache/` (gitignored); set
  `MSF_INTEL_CACHE_DIR` to relocate it.
- NVD rate limits without an API key are ~5 requests/30 s (the client
  throttles automatically). A free key from nvd.nist.gov in
  `MSF_NVD_API_KEY` raises this to ~50.
- The ATT&CK bundle is ~200 MB and is only downloaded when
  `msf_refresh_intel` runs (or on first lookup after a week). Skip it with
  `include_attack=False`; enrichment degrades gracefully without it.
- `msf_exploit_availability` searches Metasploit module metadata read-only.
  Exploit modules are listed for awareness only — the server never runs them.

The `scan-report` project skill turns findings into
`reports/<timestamp>/report.md` (detailed report) and `slides.html`
(self-contained presentation). It also instructs the model to run version
fingerprinting scanners first (`scanner/portscan/tcp`,
`scanner/ssh/ssh_version`, `scanner/http/http_version`,
`scanner/smb/smb_version`) so CVE lookups have real versions to match.

## 6. Testing

The suite includes scope-control unit tests, threat-intel unit tests, and a
full mock-RPC integration test that exercises the real `pymetasploit3`
HTTP/msgpack client and the MCP tool layer — no Metasploit host required:

```powershell
cd C:\Users\valna\Desktop\Capstone-Project
C:\Users\valna\Desktop\capstone\mcp\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Run the server manually to see startup errors (stdio protocol output is on
stdout, so it will appear to hang when run interactively):

```powershell
$env:MSF_HOST="192.168.56.10"
$env:MSF_PASSWORD="your-rpc-password"
$env:MSF_ALLOWED_TARGETS="192.168.56.0/24"
mcp\.venv\Scripts\python.exe server.py
```

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `MSF_HOST is not set` / `MSF_PASSWORD is not set` | Environment not passed to the MCP process; check `.mcp.json` |
| `Cannot reach msfrpcd` | Wrong IP/port, msfrpcd not running, bound to localhost, or firewall/tunnel down |
| `connection/authentication failed` | Wrong password/username, or SSL mismatch (`MSF_SSL=false` only when msfrpcd was started with `-S`) |
| `Module ... is outside the scan/assessment scope` | Module prefix not allowed; adjust `MSF_ALLOWED_MODULE_PREFIXES` intentionally |
| `Execution is locked because MSF_ALLOWED_TARGETS is not set` | Set the lab scope explicitly |
| `Target(s) outside MSF_ALLOWED_TARGETS` | Requested target is not in the declared scope |
| `Missing required option(s)` | Call `msf_module_info` and supply the listed required options |
| `Results not found for module instance` | Job has not produced a tracker entry yet; poll again or check `msf_list_jobs` |
| DB tools return an empty database | Run `msfdb init` and start msfrpcd without `-n` |
| `NVD request failed (HTTP 403)` | NVD rate limit hit; wait, add `MSF_NVD_API_KEY`, or narrow queries |

## 8. Files

- `server.py` — FastMCP entry point and tool definitions
- `msf_client.py` — RPC connection, scope enforcement, formatting
- `intel_client.py` — NVD/KEV/ATT&CK lookups with on-disk cache
- `.claude/skills/scan-report/SKILL.md` — report + presentation workflow
- `tests/` — unit tests and mock-msfrpcd integration tests
- `.mcp.json.example` — Claude Code configuration template
- `mcp/` — Python project/venv (`fastmcp`, `pymetasploit3`, `msgpack`)

The original starter tools (`get_system_info`, `fetch_url`, `list_files`,
`read_file`) are still registered for demonstration purposes. They are unrelated
to the Metasploit scope controls; remove them if the capstone should expose only
the assessment tools.

## 9. Limitations / next steps

- No exploit, payload, post-exploitation, or session control by design.
- Scan completion is polled manually; there is no blocking "wait until done" tool.
- `msf_scan_results` is not paginated (see the note above).
- HTTP calls to msfrpcd have a 5-second TCP preflight but no per-request timeout;
  a flaky network can still make a call slow.
- Possible next steps: an authorization-profile file (scope per engagement),
  structured logging/dashboard, a `wait_for_job` tool, or OAuth/identity in front
  of the MCP server.

---

## Team

Group 1, four members:

| Member | Primary area |
| --- | --- |
| Liliya Daroshka | AI reporting, grounding controls, report-quality evaluation |
| Shivam Saluja | Lab setup, Metasploit integration, test-case ground truth |
| Valeriano Bardhi | Interface, approvals and evidence views, export |
| Vijaysingh Mahendrasingh Puwar | Backend, workflow coordination, authorization, integration |

Areas are a starting split and should be confirmed by the team. Everyone contributes to the
literature review, testing, writing, and the presentation.

## Key dates

| Milestone | Date |
| --- | --- |
| Topic chosen | 16 Sep 2026 |
| Progress reports | 29 Oct and 12 Nov 2026 |
| Draft for feedback | 19 Nov 2026 |
| Final report and live demo | 17 Dec 2026 |

The final demo must run live and offline on a laptop in the classroom. Build toward that.
Note: the threat-intel tools need internet access; for the offline demo, pre-populate
`intel_cache/` on the demo machine beforehand.

## References

A full annotated list is in [docs/references.md](docs/references.md). The core set:

- NIST SP 800-115, technical guide to information security testing and assessment.
- Metasploit Framework documentation and RPC API, Rapid7.
- Nmap XML output format.
- NVD vulnerability APIs and the CVE program.
- FIRST CVSS v4.0 user guide.
- OWASP guidance on prompt injection and web security testing.
- FastAPI, Streamlit, and pytest documentation.

## License and use

For coursework and authorized lab use only. Do not commit secrets, API keys, course PDFs, or
raw evidence from real systems. Commit only sanitized fixtures and measurements.
