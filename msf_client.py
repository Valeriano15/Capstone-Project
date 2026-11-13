"""Scan-only client layer for Metasploit's msfrpcd RPC API.

This module deliberately exposes no exploit, post-exploitation, payload, or
session functionality.  The only executable module type is ``auxiliary``, and
execution is limited to an allowlist of assessment-oriented module prefixes and
an explicit target allowlist configured by the operator.

Configuration is read from the environment:

    MSF_HOST                   remote msfrpcd host (required)
    MSF_PORT                   RPC port (default 55553)
    MSF_USERNAME               RPC username (default "msf")
    MSF_PASSWORD               RPC password (required)
    MSF_SSL                    "true"/"false" (default true; msfrpcd uses SSL)
    MSF_ALLOWED_TARGETS        comma-separated IPs/CIDRs/hostnames allowed as targets
    MSF_ALLOWED_MODULE_PREFIXES
                               comma-separated auxiliary module prefixes
                               (default "scanner/,gather/,analyze/")
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError, MsfRpcMethod, Workspace

logger = logging.getLogger("metasploit_mcp")

DEFAULT_PORT = 55553
DEFAULT_USERNAME = "msf"

# Modules that are useful for scanning/assessment.  Anything else (exploits,
# post modules, servers, spoofers) is refused by run_auxiliary().
DEFAULT_MODULE_PREFIXES = ("scanner/", "gather/", "analyze/")

# Destructive even though they live under auxiliary/.  Always refused.
ALWAYS_BLOCKED_PREFIXES = ("dos/", "fuzzers/")

# Refuse pathological target sets rather than silently skipping validation.
MAX_TARGET_CHECKS = 4096


class MsfToolError(RuntimeError):
    """An error whose message is safe and useful to show to the MCP client."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class MsfConfig:
    host: str
    port: int
    username: str
    password: str
    ssl: bool
    allowed_targets: tuple[str, ...]

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}"


@lru_cache(maxsize=1)
def get_config() -> MsfConfig:
    """Read and validate configuration from the environment."""
    host = os.environ.get("MSF_HOST", "").strip()
    password = os.environ.get("MSF_PASSWORD", "")

    if not host:
        raise MsfToolError(
            "MSF_HOST is not set. Set it to the host running msfrpcd "
            "(e.g. MSF_HOST=192.168.56.10)."
        )
    if not password:
        raise MsfToolError(
            "MSF_PASSWORD is not set. Set it to the msfrpcd RPC password."
        )

    try:
        port = int(os.environ.get("MSF_PORT", str(DEFAULT_PORT)))
    except ValueError as exc:
        raise MsfToolError("MSF_PORT must be an integer.") from exc

    if not 1 <= port <= 65535:
        raise MsfToolError("MSF_PORT must be between 1 and 65535.")

    raw_targets = os.environ.get("MSF_ALLOWED_TARGETS", "")
    allowed_targets = tuple(
        target.strip() for target in raw_targets.split(",") if target.strip()
    )

    return MsfConfig(
        host=host,
        port=port,
        username=os.environ.get("MSF_USERNAME", DEFAULT_USERNAME).strip()
        or DEFAULT_USERNAME,
        password=password,
        ssl=_env_bool("MSF_SSL", True),
        allowed_targets=allowed_targets,
    )


def get_allowed_module_prefixes() -> tuple[str, ...]:
    raw = os.environ.get("MSF_ALLOWED_MODULE_PREFIXES", "").strip()
    if not raw:
        return DEFAULT_MODULE_PREFIXES
    prefixes = []
    for item in raw.split(","):
        prefix = item.strip().strip("/").lower()
        if prefix.startswith("auxiliary/"):
            prefix = prefix[len("auxiliary/") :]
        if prefix:
            prefixes.append(prefix + "/")
    return tuple(prefixes) or DEFAULT_MODULE_PREFIXES


# ---------------------------------------------------------------------------
# RPC connection handling
# ---------------------------------------------------------------------------

_client_lock = threading.RLock()
_client: MsfRpcClient | None = None


def _reset_client() -> None:
    global _client
    with _client_lock:
        _client = None


def _get_client() -> MsfRpcClient:
    """Return a cached authenticated RPC client, creating it on first use."""
    global _client

    cfg = get_config()
    with _client_lock:
        if _client is not None:
            return _client

        # Fail fast with a useful message instead of letting requests hang on
        # an unreachable host.
        try:
            with socket.create_connection((cfg.host, cfg.port), timeout=5):
                pass
        except OSError as exc:
            raise MsfToolError(
                f"Cannot reach msfrpcd at {cfg.host}:{cfg.port}: {exc}. "
                "Check that msfrpcd is running, bound to an interface reachable "
                "from this machine, and not blocked by a firewall."
            ) from exc

        try:
            _client = MsfRpcClient(
                cfg.password,
                server=cfg.host,
                port=cfg.port,
                username=cfg.username,
                ssl=cfg.ssl,
            )
        except Exception as exc:  # pymetasploit3 raises several exception types
            raise MsfToolError(
                f"msfrpcd connection/authentication failed for {cfg.endpoint}: {exc}"
            ) from exc

        return _client


def _rpc(operation):
    """Run an RPC operation under a lock and reset the client on failure."""
    with _client_lock:
        client = _get_client()
        try:
            return operation(client)
        except MsfToolError:
            raise
        except Exception as exc:
            logger.exception("Metasploit RPC operation failed")
            _reset_client()
            raise MsfToolError(f"Metasploit RPC call failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------


def _strip_auxiliary_prefix(module_name: str) -> str:
    name = (module_name or "").strip().strip("/")
    if name.startswith("auxiliary/"):
        name = name[len("auxiliary/") :]
    return name


def require_auxiliary_name(module_name: str) -> str:
    """Normalize a module name and reject obviously invalid values."""
    name = _strip_auxiliary_prefix(module_name)
    if not name:
        raise MsfToolError("module_name is required.")
    if "\\" in name or ".." in name:
        raise MsfToolError(f"Invalid module name: {module_name!r}")
    return name


def is_module_allowed(module_name: str) -> bool:
    """Whether a normalized auxiliary module is inside the assessment scope."""
    name = _strip_auxiliary_prefix(module_name)
    if any(name.startswith(prefix) for prefix in ALWAYS_BLOCKED_PREFIXES):
        return False
    return any(name.startswith(prefix) for prefix in get_allowed_module_prefixes())


def _ip_in_any(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allowed: tuple[str, ...],
) -> bool:
    for entry in allowed:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if addr.version == network.version and addr in network:
            return True
    return False


def _split_range(
    target: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ipaddress.IPv4Address | ipaddress.IPv6Address] | None:
    """Parse ``10.0.0.10-20`` or ``10.0.0.10-10.0.0.20`` style ranges."""
    if "-" not in target:
        return None

    start_text, end_text = target.split("-", 1)
    start_text = start_text.strip()
    end_text = end_text.strip()

    try:
        start = ipaddress.ip_address(start_text)
    except ValueError:
        return None

    # Metasploit accepts the short form 192.168.56.10-20.
    if "." in start_text and end_text.isdigit():
        end_text = start_text.rsplit(".", 1)[0] + "." + end_text

    try:
        end = ipaddress.ip_address(end_text)
    except ValueError:
        return None

    if start.version != end.version or int(start) > int(end):
        return None
    return start, end


def target_within_allowlist(target: str, allowed: tuple[str, ...]) -> bool:
    """Return True if a single RHOSTS token is inside the operator allowlist.

    Supports plain IPs, CIDR networks, Metasploit IP ranges, and exact
    hostnames.  CIDR targets must be fully contained in an allowed network; a
    range is accepted only when both endpoints are inside allowed networks.
    """
    target = (target or "").strip().strip("[]")
    if not target:
        return False

    allowed_lower = {entry.lower() for entry in allowed}

    # Exact hostname or exact address match.
    if target.lower() in allowed_lower:
        return True

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        for entry in allowed:
            try:
                allowed_network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if (
                network.version == allowed_network.version
                and network.subnet_of(allowed_network)
            ):
                return True
        return False

    if "-" in target:
        parsed = _split_range(target)
        if parsed is None:
            return False
        start, end = parsed
        return _ip_in_any(start, allowed) and _ip_in_any(end, allowed)

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        # A hostname that was not an exact allowlist match.
        return False
    return _ip_in_any(address, allowed)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _short(value: Any, length: int = 300) -> Any:
    if not isinstance(value, str):
        return value
    text = " ".join(value.split())
    if len(text) <= length:
        return text
    return text[: length - 3].rstrip() + "..."


def _module_targets(module) -> list[str]:
    """Extract target tokens from a module's RHOSTS/RHOST options."""
    option_names = set(module.options)
    targets: list[str] = []

    for key in ("RHOSTS", "RHOST"):
        if key not in option_names:
            continue
        value = module[key]
        if isinstance(value, str):
            targets.extend(token for token in re.split(r"[,\s]+", value.strip()) if token)
        elif isinstance(value, (list, tuple)):
            targets.extend(str(token) for token in value if str(token).strip())

    # Preserve order while removing duplicates.  Reject oversized sets instead
    # of truncating: truncation would let unvalidated targets reach Metasploit.
    unique = list(dict.fromkeys(targets))
    if len(unique) > MAX_TARGET_CHECKS:
        raise MsfToolError(
            f"Refusing to run: RHOSTS contains {len(unique)} targets, above the "
            f"limit of {MAX_TARGET_CHECKS}. Narrow the target scope."
        )
    return unique


# ---------------------------------------------------------------------------
# Read-only assessment operations
# ---------------------------------------------------------------------------


def status() -> dict[str, Any]:
    """Return connection, version, database, and scope information."""
    cfg = get_config()

    def operation(client: MsfRpcClient):
        version = client.core.version
        jobs = client.jobs.list
        try:
            db = client.db.status
        except Exception as exc:
            db = {"connected": False, "error": str(exc)}
        return version, jobs, db

    version, jobs, db = _rpc(operation)

    return {
        "connected": True,
        "endpoint": cfg.endpoint,
        "username": cfg.username,
        "version": version.get("version") if isinstance(version, dict) else None,
        "ruby": version.get("ruby") if isinstance(version, dict) else None,
        "api": version.get("api") if isinstance(version, dict) else None,
        "jobs_running": len(jobs) if isinstance(jobs, dict) else None,
        "database": db,
        "scope": {
            "module_type": "auxiliary only",
            "allowed_module_prefixes": list(get_allowed_module_prefixes()),
            "always_blocked_prefixes": list(ALWAYS_BLOCKED_PREFIXES),
            "target_allowlist": list(cfg.allowed_targets) or None,
            "execution_locked": not bool(cfg.allowed_targets),
        },
    }


def search_auxiliary(
    query: str,
    limit: int = 15,
    include_details: bool = True,
) -> dict[str, Any]:
    """Search runnable auxiliary modules by keyword."""
    if not isinstance(query, str) or not query.strip():
        raise MsfToolError("query must be a non-empty search string.")

    # The server owns the module-type filter; drop any caller-supplied type:
    # tokens so a query like "smb type:exploit" cannot conflict with it.
    keyword_query = re.sub(r"(?i)\btype:\S+", "", query).strip()
    if not keyword_query:
        raise MsfToolError("query must include a keyword other than a type: filter.")

    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise MsfToolError("limit must be an integer.") from exc
    limit = max(1, min(limit, 50))

    search_term = f"{keyword_query} type:auxiliary"
    prefixes = get_allowed_module_prefixes()

    def operation(client: MsfRpcClient):
        raw = client.modules.search(search_term)
        if isinstance(raw, dict):
            raw = raw.get("modules", [])
        if not isinstance(raw, list):
            raise MsfToolError(
                f"Unexpected module.search response: {type(raw).__name__}"
            )

        matches: list[dict[str, Any]] = []
        skipped_out_of_scope = 0

        for entry in raw:
            if isinstance(entry, dict):
                module_type = entry.get("type")
                fullname = entry.get("fullname") or entry.get("name") or ""
                rank = entry.get("rank")
                disclosure = entry.get("disclosuredate")
            elif isinstance(entry, str):
                module_type = None
                fullname = entry
                rank = None
                disclosure = None
            else:
                continue

            if module_type not in (None, "auxiliary"):
                continue

            module_name = _strip_auxiliary_prefix(fullname)
            if not module_name:
                continue
            if not is_module_allowed(module_name):
                skipped_out_of_scope += 1
                continue

            matches.append(
                {
                    "module": module_name,
                    "rank": rank,
                    "disclosure_date": disclosure,
                }
            )

        total = len(matches)
        selected = matches[:limit]

        if include_details:
            for item in selected:
                try:
                    info = client.call(
                        MsfRpcMethod.ModuleInfo, ["auxiliary", item["module"]]
                    )
                    item["name"] = info.get("name")
                    item["description"] = _short(info.get("description"))
                    item["rank"] = item.get("rank") or info.get("rank")
                    item["disclosure_date"] = (
                        item.get("disclosure_date") or info.get("disclosure_date")
                    )
                    item["platform"] = info.get("platform")
                except Exception:
                    logger.exception(
                        "module.info failed for %s", item["module"]
                    )
                    item["description"] = None

        return {
            "query": query.strip(),
            "search_term": search_term,
            "total_matches": total,
            "returned": len(selected),
            "skipped_out_of_scope": skipped_out_of_scope,
            "allowed_module_prefixes": list(prefixes),
            "modules": selected,
        }

    return _rpc(operation)


def auxiliary_info(
    module_name: str,
    include_advanced: bool = False,
) -> dict[str, Any]:
    """Return module metadata and options for an auxiliary module."""
    name = require_auxiliary_name(module_name)

    def operation(client: MsfRpcClient):
        info = client.call(MsfRpcMethod.ModuleInfo, ["auxiliary", name])
        module = client.modules.use("auxiliary", name)

        options: list[dict[str, Any]] = []
        for option_name in module.options:
            meta = module.optioninfo(option_name) or {}
            if meta.get("advanced") and not include_advanced:
                continue
            entry: dict[str, Any] = {
                "name": option_name,
                "type": meta.get("type"),
                "required": bool(meta.get("required")),
                "advanced": bool(meta.get("advanced")),
                "default": meta.get("default"),
                "description": _short(meta.get("description"), 240),
            }
            if meta.get("enums"):
                entry["enums"] = meta["enums"]
            options.append(entry)

        options.sort(key=lambda entry: (not entry["required"], entry["name"]))

        references = info.get("references") or []
        authors = info.get("authors") or []

        return {
            "module": name,
            "name": info.get("name"),
            "description": info.get("description"),
            "rank": info.get("rank"),
            "disclosure_date": info.get("disclosure_date"),
            "platform": info.get("platform"),
            "arch": info.get("arch"),
            "privileged": info.get("privileged"),
            "authors": authors[:10] if isinstance(authors, list) else authors,
            "references": references[:15] if isinstance(references, list) else references,
            "actions": info.get("actions"),
            "in_scope": is_module_allowed(name),
            "allowed_module_prefixes": list(get_allowed_module_prefixes()),
            "options": options,
        }

    return _rpc(operation)


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------


def run_auxiliary(
    module_name: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start an auxiliary assessment module as a Metasploit job."""
    cfg = get_config()
    name = require_auxiliary_name(module_name)

    if not is_module_allowed(name):
        raise MsfToolError(
            f"Module '{name}' is outside the scan/assessment scope. "
            f"Allowed prefixes: {', '.join(get_allowed_module_prefixes())}. "
            f"Always blocked: {', '.join(ALWAYS_BLOCKED_PREFIXES)}."
        )

    if not cfg.allowed_targets:
        raise MsfToolError(
            "Execution is locked because MSF_ALLOWED_TARGETS is not set. "
            "Set it to the lab scope before running scans, for example "
            "MSF_ALLOWED_TARGETS=192.168.56.0/24."
        )

    if options is not None and not isinstance(options, dict):
        raise MsfToolError("options must be an object mapping option names to values.")
    provided = options or {}

    def operation(client: MsfRpcClient):
        module = client.modules.use("auxiliary", name)

        for key, value in provided.items():
            try:
                module[key] = value
            except KeyError as exc:
                raise MsfToolError(
                    f"Unknown module option '{key}'. Available options: "
                    + ", ".join(sorted(module.options))
                ) from exc
            except (ValueError, TypeError) as exc:
                raise MsfToolError(f"Invalid value for option '{key}': {exc}") from exc

        missing = []
        for option_name in module.required:
            value = module[option_name]
            if (
                value is None
                or (isinstance(value, str) and not value.strip())
                or value == []
            ):
                missing.append(option_name)
        if missing:
            raise MsfToolError(
                "Missing required option(s): " + ", ".join(sorted(missing))
            )

        targets = _module_targets(module)
        disallowed = [
            target
            for target in targets
            if not target_within_allowlist(target, cfg.allowed_targets)
        ]
        if disallowed:
            shown = ", ".join(disallowed[:10])
            suffix = " ..." if len(disallowed) > 10 else ""
            raise MsfToolError(
                f"Target(s) outside MSF_ALLOWED_TARGETS ({', '.join(cfg.allowed_targets)}): "
                f"{shown}{suffix}"
            )

        result = module.execute()
        return result, targets

    result, targets = _rpc(operation)

    if not isinstance(result, dict) or not result.get("uuid"):
        raise MsfToolError(f"Module did not start as a job: {result!r}")

    uuid = result["uuid"]
    return {
        "module": name,
        "job_id": result.get("job_id"),
        "uuid": uuid,
        "targets": targets,
        "status": "started",
        "next": (
            f"Call msf_scan_results with uuid '{uuid}' to read results once the "
            "job finishes; use msf_list_jobs to see running jobs."
        ),
    }


def scan_results(uuid: str) -> dict[str, Any]:
    """Read the current result tracker for a scan job UUID."""
    uid = (uuid or "").strip()
    if not uid:
        raise MsfToolError("uuid is required (returned by msf_run_module).")

    def operation(client: MsfRpcClient):
        return client.modules.results(uid)

    raw = _rpc(operation)
    return {
        "uuid": uid,
        "status": raw.get("status") if isinstance(raw, dict) else None,
        "result": raw,
    }


def list_jobs() -> dict[str, Any]:
    """List Metasploit jobs currently running on the remote host."""
    jobs = _rpc(lambda client: client.jobs.list)
    return {
        "count": len(jobs) if isinstance(jobs, dict) else 0,
        "jobs": jobs,
    }


def stop_job(job_id: int) -> dict[str, Any]:
    """Stop a running Metasploit job by numeric job ID."""
    job_text = str(job_id).strip()
    if not job_text.isdigit():
        raise MsfToolError("job_id must be an integer.")

    # pymetasploit3 raises on an invalid job and discards the success payload.
    _rpc(lambda client: client.jobs.stop(job_text))
    return {"job_id": int(job_text), "stopped": True}


# ---------------------------------------------------------------------------
# Read-only database helpers
# ---------------------------------------------------------------------------


def db_records(
    kind: str,
    workspace: str = "default",
    limit: int = 50,
) -> dict[str, Any]:
    """Read hosts, services, or vulnerabilities from the MSF database."""
    if kind not in {"hosts", "services", "vulns"}:
        raise MsfToolError("kind must be one of: hosts, services, vulns.")

    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise MsfToolError("limit must be an integer.") from exc
    limit = max(1, min(limit, 500))

    workspace = (workspace or "default").strip() or "default"

    def operation(client: MsfRpcClient):
        workspaces = client.db.workspaces.list
        if workspace not in workspaces:
            available = ", ".join(workspaces) if workspaces else "(none)"
            raise MsfToolError(
                f"Workspace '{workspace}' not found. Available workspaces: {available}"
            )
        ws = Workspace(client, workspace)
        records = getattr(ws, kind).list
        return records

    records = _rpc(operation)

    if isinstance(records, dict):
        records = list(records.values())
    if not isinstance(records, list):
        raise MsfToolError(f"Unexpected database response: {type(records).__name__}")

    total = len(records)
    return {
        "workspace": workspace,
        "kind": kind,
        "total": total,
        "returned": min(total, limit),
        "records": records[:limit],
        "hint": (
            "If the database is empty, run 'msfdb init' on the Metasploit host "
            "and start msfrpcd without -n so auxiliary scanners report results."
        )
        if total == 0
        else None,
    }


__all__ = [
    "MsfConfig",
    "MsfToolError",
    "ALWAYS_BLOCKED_PREFIXES",
    "DEFAULT_MODULE_PREFIXES",
    "auxiliary_info",
    "db_records",
    "get_allowed_module_prefixes",
    "get_config",
    "is_module_allowed",
    "list_jobs",
    "require_auxiliary_name",
    "run_auxiliary",
    "scan_results",
    "search_auxiliary",
    "status",
    "stop_job",
    "target_within_allowlist",
]
