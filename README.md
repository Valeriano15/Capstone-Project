# Metasploit MCP Server (scan/assessment only)

A FastMCP server that lets Claude drive a **remote Metasploit Framework** host
through its `msfrpcd` RPC API. It is deliberately limited to **auxiliary
scanning and information-gathering modules** — no exploits, payloads,
post-exploitation, or sessions.

```
Claude Code  --stdio-->  server.py  --msgpack/HTTPS-->  msfrpcd on lab host
                          |
                          +-- msf_client.py   (scope enforcement, RPC client)
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

On the Kali/Ubuntu lab host:

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

The Windows host must be able to reach that address and port. If the VM uses
NAT, use the forwarded port and bind `msfrpcd` accordingly, or switch the VM to
a host-only/bridged adapter.

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

`MSF_ALLOWED_TARGETS` accepts:

- exact IPs — `192.168.56.10`
- CIDRs — `192.168.56.0/24` (a target CIDR must be fully inside an allowed CIDR)
- Metasploit ranges — `192.168.56.10-20` (both endpoints must be inside the scope)
- exact hostnames — `target.lab.example` (hostname matching is exact only)

## 3. Register the server with Claude Code

Copy `.mcp.json.example` to `.mcp.json` in this directory, fill in the host,
password, and target scope, then start Claude Code from `capstone/` and approve
the project MCP server.

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

Example prompts:

- "Check the Metasploit connection and tell me what scope is enforced."
- "Search for SMB version scanners."
- "Show me the options for `scanner/smb/smb_version`."
- "Run `scanner/smb/smb_version` against 192.168.56.10 with 4 threads."
- "Poll the scan results until it finishes, then list the hosts Metasploit recorded."
- "List the running jobs and stop job 0."

Typical flow: `msf_status` → `msf_search_auxiliary` → `msf_module_info` →
`msf_run_module` → `msf_scan_results` (poll) → `msf_db_hosts`/`msf_db_services`.

`msf_scan_results` returns the result tracker in full, without pagination. Keep
demo scans small (a `/24` or narrower) and use the DB tools for larger
assessments so a large result does not flood Claude's context.

## 5. Testing

The suite includes scope-control unit tests and a full mock-RPC integration
test that exercises the real `pymetasploit3` HTTP/msgpack client and the MCP
tool layer — no Metasploit host required:

```powershell
cd C:\Users\valna\Desktop\capstone
mcp\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Run the server manually to see startup errors (stdio protocol output is on
stdout, so it will appear to hang when run interactively):

```powershell
$env:MSF_HOST="192.168.56.10"
$env:MSF_PASSWORD="your-rpc-password"
$env:MSF_ALLOWED_TARGETS="192.168.56.0/24"
mcp\.venv\Scripts\python.exe server.py
```

## 6. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `MSF_HOST is not set` / `MSF_PASSWORD is not set` | Environment not passed to the MCP process; check `.mcp.json` |
| `Cannot reach msfrpcd` | Wrong IP/port, msfrpcd not running, bound to localhost, or firewall |
| `connection/authentication failed` | Wrong password/username, or SSL mismatch (`MSF_SSL=false` only when msfrpcd was started with `-S`) |
| `Module ... is outside the scan/assessment scope` | Module prefix not allowed; adjust `MSF_ALLOWED_MODULE_PREFIXES` intentionally |
| `Execution is locked because MSF_ALLOWED_TARGETS is not set` | Set the lab scope explicitly |
| `Target(s) outside MSF_ALLOWED_TARGETS` | Requested target is not in the declared scope |
| `Missing required option(s)` | Call `msf_module_info` and supply the listed required options |
| `Results not found for module instance` | Job has not produced a tracker entry yet; poll again or check `msf_list_jobs` |
| DB tools return an empty database | Run `msfdb init` and start msfrpcd without `-n` |

## 7. Files

- `server.py` — FastMCP entry point and tool definitions
- `msf_client.py` — RPC connection, scope enforcement, formatting
- `tests/test_msf_client.py` — unit tests for the scope controls
- `.mcp.json.example` — Claude Code configuration template
- `mcp/` — Python project/venv (`fastmcp`, `pymetasploit3`, `msgpack`)

The original starter tools (`get_system_info`, `fetch_url`, `list_files`,
`read_file`) are still registered for demonstration purposes. They are unrelated
to the Metasploit scope controls; remove them if the capstone should expose only
the assessment tools.

## 8. Limitations / next steps

- No exploit, payload, post-exploitation, or session control by design.
- Scan completion is polled manually; there is no blocking "wait until done" tool.
- `msf_scan_results` is not paginated (see the note above).
- HTTP calls to msfrpcd have a 5-second TCP preflight but no per-request timeout;
  a flaky network can still make a call slow.
- Possible next steps: add an authorization-profile file (scope per engagement),
  structured logging/dashboard, a `wait_for_job` tool, or OAuth/identity in front
  of the MCP server.
