"""FastMCP server exposing a scan-only subset of Metasploit over msfrpcd.

Claude talks to this process over stdio; this process talks to a remote
Metasploit RPC daemon (msfrpcd).  No exploit, payload, post-exploitation, or
session APIs are exposed.

See README.md for the remote msfrpcd setup and Claude Code configuration.
"""

import json
import os
import platform
import urllib.error
import urllib.request
from typing import Any

from fastmcp import FastMCP

import intel_client as intel
import msf_client as msf

mcp = FastMCP("Metasploit Assessment Server")


# ---------------------------------------------------------------------------
# Metasploit (scan / assessment only)
# ---------------------------------------------------------------------------


@mcp.tool()
def msf_status() -> dict[str, Any]:
    """Check the Metasploit connection and show the enforced scope.

    Reports the msfrpcd version, database status, running job count, the
    allowed module prefixes, and the target allowlist. This tool is read-only
    and never runs a scan. Use it first when diagnosing connection problems.
    """
    return msf.status()


@mcp.tool()
def msf_search_auxiliary(
    query: str,
    limit: int = 15,
    include_details: bool = True,
) -> dict[str, Any]:
    """Search Metasploit auxiliary modules usable for scanning and assessment.

    Only modules under the allowed prefixes (scanner/, gather/, analyze/ by
    default) are returned. Exploit, payload, post, DoS, and fuzzer modules are
    excluded. Matching module names and descriptions are returned; use
    msf_module_info for the full option list of one module.

    Example queries: "smb version", "ssh", "http", "portscan".
    """
    return msf.search_auxiliary(query, limit=limit, include_details=include_details)


@mcp.tool()
def msf_module_info(
    module_name: str,
    include_advanced: bool = False,
) -> dict[str, Any]:
    """Show metadata and option definitions for one auxiliary module.

    module_name may be written as "auxiliary/scanner/smb/smb_version" or
    "scanner/smb/smb_version". The response includes required options, their
    types, defaults, and whether the module is inside the executable scope.
    """
    return msf.auxiliary_info(module_name, include_advanced=include_advanced)


@mcp.tool()
def msf_run_module(
    module_name: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start an allowed auxiliary scanner as a Metasploit job.

    Only auxiliary modules under scanner/, gather/, or analyze/ can run, and
    only when MSF_ALLOWED_TARGETS is configured. Provide module options as an
    object, for example {"RHOSTS": "192.168.56.10", "THREADS": 4}. Every
    RHOSTS/RHOST token is checked against the target allowlist before the job
    starts.

    Returns job_id and uuid. Poll msf_scan_results(uuid) for results, or use
    msf_list_jobs / msf_stop_job to manage running scans.
    """
    return msf.run_auxiliary(module_name, options=options)


@mcp.tool()
def msf_scan_results(uuid: str) -> dict[str, Any]:
    """Read the result tracker for a scan job started by msf_run_module.

    status is typically "ready", "running", "completed", or "errored". When
    completed, result contains the data the module collected. Poll until the
    status is no longer running.
    """
    return msf.scan_results(uuid)


@mcp.tool()
def msf_list_jobs() -> dict[str, Any]:
    """List Metasploit jobs currently running on the remote host."""
    return msf.list_jobs()


@mcp.tool()
def msf_stop_job(job_id: int) -> dict[str, Any]:
    """Stop a running Metasploit job by its numeric job ID."""
    return msf.stop_job(job_id)


@mcp.tool()
def msf_db_hosts(workspace: str = "default", limit: int = 50) -> dict[str, Any]:
    """List hosts recorded in the Metasploit database (read-only).

    Requires msfrpcd to be connected to the MSF database and its workspace to
    exist. Useful after scanner modules have reported results.
    """
    return msf.db_records("hosts", workspace=workspace, limit=limit)


@mcp.tool()
def msf_db_services(workspace: str = "default", limit: int = 50) -> dict[str, Any]:
    """List services recorded in the Metasploit database (read-only)."""
    return msf.db_records("services", workspace=workspace, limit=limit)


@mcp.tool()
def msf_db_vulns(workspace: str = "default", limit: int = 50) -> dict[str, Any]:
    """List vulnerabilities recorded in the Metasploit database (read-only)."""
    return msf.db_records("vulns", workspace=workspace, limit=limit)


# ---------------------------------------------------------------------------
# Threat intelligence (read-only, public feeds only)
# ---------------------------------------------------------------------------


@mcp.tool()
def msf_cve_lookup(query: str, limit: int = 5) -> dict[str, Any]:
    """Look up current threat intelligence for a CVE ID or a keyword.

    Accepts a CVE ID such as "CVE-2021-44228" or a service/version keyword
    such as "openssh 9.2p1" or "apache tomcat 9.0". For each finding this
    returns the NVD description, CVSS base score/severity, weaknesses,
    references, CISA KEV status (actively exploited in the wild, with
    remediation due dates), and MITRE ATT&CK mappings (techniques, threat
    actors, and software tied to the CVE, with citations).

    Data comes from public feeds (NVD, CISA KEV, MITRE ATT&CK) and is cached
    locally. Use msf_refresh_intel to force a feed refresh. Never touches
    the scan target. Use msf_exploit_availability afterwards to check
    whether public Metasploit modules exist for the CVEs found.
    """
    return intel.cve_lookup(query, limit=limit)


@mcp.tool()
def msf_exploit_availability(cve: str) -> dict[str, Any]:
    """Check whether Metasploit has modules for a CVE (read-only).

    Searches module metadata for exploit and auxiliary modules that
    reference the CVE. This is an intelligence lookup only: exploit modules
    are listed for awareness (and marked runnable_in_scope when an
    in-scope auxiliary scanner exists) but this server never runs them.
    """
    return msf.exploit_availability(cve)


@mcp.tool()
def msf_refresh_intel(include_attack: bool = True) -> dict[str, Any]:
    """Re-download the CISA KEV and MITRE ATT&CK intelligence feeds.

    Returns the status of each feed refresh (ok/error), the catalog date,
    and record counts. Call this before writing a report if the cached
    feeds are older than a day (KEV) or a week (ATT&CK). The ATT&CK
    bundle is large (~200 MB); skip it with include_attack=False.
    """
    return intel.refresh_intel(include_attack=include_attack)


# ---------------------------------------------------------------------------
# General-purpose demo tools (kept from the original starter server)
# ---------------------------------------------------------------------------


@mcp.tool()
def get_system_info() -> str:
    """Retrieve basic system information and OS details of the MCP host."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "current_directory": os.getcwd(),
    }
    return json.dumps(info, indent=2)


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch the text content of a URL. Useful for reading web pages or APIs."""
    try:
        # Add a user-agent to prevent basic bot blocking
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (MCP-Agent; +http://example.com)"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode("utf-8")
            # Truncate to prevent overwhelming the AI's context window
            if len(html) > 5000:
                return html[:5000] + "\n...[CONTENT TRUNCATED]..."
            return html
    except urllib.error.URLError as e:
        return f"Failed to fetch URL: {e.reason}"
    except Exception as e:
        return f"An error occurred: {str(e)}"


@mcp.tool()
def list_files(directory: str = ".") -> list[str]:
    """List all files and folders in the specified directory."""
    try:
        target_path = os.path.abspath(directory)
        if not os.path.exists(target_path):
            return [f"Error: Directory '{directory}' does not exist."]
        return os.listdir(target_path)
    except PermissionError:
        return ["Error: Permission denied."]
    except Exception as e:
        return [f"Error reading directory: {str(e)}"]


@mcp.tool()
def read_file(filepath: str) -> str:
    """Read the contents of a specific text file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            # Truncate if the file is massive
            if len(content) > 10000:
                return content[:10000] + "\n...[TRUNCATED]"
            return content
    except FileNotFoundError:
        return "Error: File not found."
    except UnicodeDecodeError:
        return "Error: File appears to be a binary, not a readable text file."
    except Exception as e:
        return f"Error reading file: {str(e)}"


if __name__ == "__main__":
    # Starts the server using standard input/output (stdio)
    mcp.run()
