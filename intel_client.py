"""Read-only threat-intelligence lookups for the Metasploit MCP server.

Enriches scan findings with public, current data so the model can write
reports and presentations grounded in live threat intelligence:

  - NVD            CVE details, CVSS base score/severity, weaknesses
  - CISA KEV       actively exploited status + remediation due dates
  - MITRE ATT&CK   software/technique mappings for CVEs

Everything is cached on disk (default ``intel_cache/`` next to this file,
override with ``MSF_INTEL_CACHE_DIR``). Nothing here touches the scan
target; all requests go to public intelligence feeds.

Optional ``MSF_NVD_API_KEY`` raises the NVD rate limit from ~5 to ~50
requests per 30 seconds (free key from nvd.nist.gov).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

try:  # certifi ships with fastmcp's dependencies; fall back to system trust
    import certifi
except ImportError:  # pragma: no cover
    certifi = None

logger = logging.getLogger("metasploit_mcp")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

NVD_CACHE_TTL = 7 * 24 * 3600
KEV_CACHE_TTL = 24 * 3600
ATTACK_CACHE_TTL = 7 * 24 * 3600

USER_AGENT = "msf-mcp-intel/1.0 (capstone; educational)"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class IntelError(RuntimeError):
    """An error whose message is safe and useful to show to the MCP client."""


# ---------------------------------------------------------------------------
# HTTP + cache plumbing
# ---------------------------------------------------------------------------


def _cache_dir() -> str:
    return os.environ.get(
        "MSF_INTEL_CACHE_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "intel_cache"),
    )


def _nvd_api_key() -> str:
    return os.environ.get("MSF_NVD_API_KEY", "").strip()


_nvd_lock = threading.Lock()
_last_nvd_call = 0.0


def _http_get(url: str, timeout: float = 30.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    # Prefer certifi's bundle: some Windows machines have stale intermediates
    # in the OS store that reject otherwise-valid chains (e.g. NVD).
    context = None
    if certifi is not None:
        context = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
        return response.read()


def _throttle_nvd() -> None:
    """Respect the NVD API rate limit (5 req/30s anonymous, 50 with a key)."""
    global _last_nvd_call
    interval = 0.8 if _nvd_api_key() else 6.2
    with _nvd_lock:
        wait = interval - (time.monotonic() - _last_nvd_call)
        if wait > 0:
            time.sleep(wait)
        _last_nvd_call = time.monotonic()


def _cache_path(key: str) -> str:
    os.makedirs(_cache_dir(), exist_ok=True)
    return os.path.join(_cache_dir(), key + ".json")


def _cache_read(key: str, ttl: float) -> Any | None:
    path = _cache_path(key)
    try:
        if time.time() - os.path.getmtime(path) > ttl:
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _cache_write(key: str, payload: Any) -> None:
    path = _cache_path(key)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------


def _kev_data(force: bool = False) -> dict[str, Any]:
    """Download (or load from cache) the CISA KEV catalog."""
    key = "kev"
    if not force:
        cached = _cache_read(key, KEV_CACHE_TTL)
        if cached:
            return cached
    try:
        raw = _http_get(KEV_URL, timeout=30)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        stale = _cache_read(key, 365 * 24 * 3600)
        if stale is not None:
            logger.warning("KEV download failed; using stale cache: %s", exc)
            return stale
        raise IntelError(f"Could not download the CISA KEV catalog: {exc}") from exc
    _cache_write(key, data)
    return data


def _load_kev_index() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Return ({CVE: entry}, meta); degrades gracefully when unreachable."""
    try:
        data = _kev_data()
    except Exception as exc:  # noqa: BLE001 - degrade instead of failing the tool
        logger.exception("KEV load failed")
        return {}, {"available": False, "error": str(exc)}
    by_cve: dict[str, dict[str, Any]] = {}
    for entry in data.get("vulnerabilities") or []:
        cve_id = (entry.get("cveID") or "").upper()
        if CVE_RE.fullmatch(cve_id):
            by_cve[cve_id] = entry
    return by_cve, {
        "available": True,
        "catalog_date": data.get("dateReleased"),
        "count": len(by_cve),
    }


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------


def _technique_info(obj: dict[str, Any]) -> dict[str, Any]:
    info: dict[str, Any] = {"id": None, "name": obj.get("name"), "url": None}
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            info["id"] = ref.get("external_id")
            info["url"] = ref.get("url")
    return info


def _merge_technique(
    bucket: list[dict[str, Any]], technique: dict[str, Any]
) -> None:
    """Append a technique, deduping by ATT&CK ID and merging enrichment."""
    technique_id = technique.get("id")
    for existing in bucket:
        if technique_id and existing.get("id") == technique_id:
            if not existing.get("source") and technique.get("source"):
                existing["source"] = technique["source"]
            if not existing.get("citation") and technique.get("citation"):
                existing["citation"] = technique["citation"]
            return
    bucket.append(technique)


def _build_attack_index(bundle: dict[str, Any]) -> dict[str, Any]:
    """Slim the STIX bundle down to CVE -> techniques/software/actors.

    ATT&CK does not store structured CVE links on software objects; CVEs
    appear in the citations (external_references) of techniques, software,
    actors, and their relationships. We scan those citations and keep the
    objects that mention each CVE, with the citation for traceability.
    """
    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
    by_id = {o.get("id"): o for o in objects if isinstance(o, dict) and o.get("id")}

    cve_to_techniques: dict[str, list[dict[str, Any]]] = {}
    cve_to_software: dict[str, list[str]] = {}
    cve_to_actors: dict[str, list[str]] = {}

    software_count = 0
    technique_count = 0

    def actor_label(obj: dict[str, Any]) -> str:
        name = obj.get("name") or obj.get("id")
        ext_id = next(
            (
                ref.get("external_id")
                for ref in obj.get("external_references") or []
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            ),
            None,
        )
        return f"{name} ({ext_id})" if ext_id else name

    def note(obj: dict[str, Any], cve_id: str, citation: str) -> None:
        otype = obj.get("type")
        if otype == "attack-pattern":
            technique = _technique_info(obj)
            technique["citation"] = citation
            bucket = cve_to_techniques.setdefault(cve_id, [])
            _merge_technique(bucket, technique)
        elif otype in ("malware", "tool"):
            name = obj.get("name") or obj.get("id")
            bucket = cve_to_software.setdefault(cve_id, [])
            if name not in bucket:
                bucket.append(name)
        elif otype in ("intrusion-set", "campaign"):
            label = actor_label(obj)
            bucket = cve_to_actors.setdefault(cve_id, [])
            if label not in bucket:
                bucket.append(label)
        elif otype == "relationship" and obj.get("relationship_type") in (
            "uses",
            "exploits",
        ):
            source_obj = by_id.get(obj.get("source_ref"))
            target_obj = by_id.get(obj.get("target_ref"))
            if isinstance(target_obj, dict) and target_obj.get("type") == "attack-pattern":
                technique = _technique_info(target_obj)
                technique["citation"] = citation
                if isinstance(source_obj, dict):
                    technique["source"] = {
                        "type": source_obj.get("type"),
                        "name": source_obj.get("name") or source_obj.get("id"),
                    }
                _merge_technique(
                    cve_to_techniques.setdefault(cve_id, []), technique
                )
            if isinstance(source_obj, dict):
                if source_obj.get("type") in ("intrusion-set", "campaign"):
                    label = actor_label(source_obj)
                    bucket = cve_to_actors.setdefault(cve_id, [])
                    if label not in bucket:
                        bucket.append(label)
                elif source_obj.get("type") in ("malware", "tool"):
                    name = source_obj.get("name") or source_obj.get("id")
                    bucket = cve_to_software.setdefault(cve_id, [])
                    if name not in bucket:
                        bucket.append(name)

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "attack-pattern":
            technique_count += 1
        elif obj.get("type") in ("malware", "tool"):
            software_count += 1
        for ref in obj.get("external_references") or []:
            if not isinstance(ref, dict):
                continue
            text = " ".join(
                str(ref.get(key) or "")
                for key in ("source_name", "external_id", "description", "url")
            )
            citation = ref.get("source_name") or ref.get("url") or ""
            for cve_id in dict.fromkeys(
                match.upper() for match in CVE_RE.findall(text)
            ):
                note(obj, cve_id, citation)

    return {
        "format_version": 2,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "software_objects": software_count,
        "technique_objects": technique_count,
        "cve_to_techniques": cve_to_techniques,
        "cve_to_software": cve_to_software,
        "cve_to_actors": cve_to_actors,
    }


def _attack_index(force: bool = False) -> dict[str, Any]:
    """Load (or build) the slim ATT&CK index, downloading the bundle if needed."""
    key = "attack-index"
    if not force:
        cached = _cache_read(key, ATTACK_CACHE_TTL)
        if cached and cached.get("format_version") == 2:
            return cached

    raw_path = _cache_path("attack-raw")
    try:
        if (
            force
            or not os.path.exists(raw_path)
            or time.time() - os.path.getmtime(raw_path) > ATTACK_CACHE_TTL
        ):
            raw = _http_get(ATTACK_URL, timeout=600)
            with open(raw_path + ".tmp", "wb") as fh:
                fh.write(raw)
            os.replace(raw_path + ".tmp", raw_path)
        with open(raw_path, "rb") as fh:
            bundle = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        stale = _cache_read(key, 365 * 24 * 3600)
        if stale and stale.get("format_version") == 2:
            logger.warning("ATT&CK download failed; using stale index: %s", exc)
            return stale
        raise IntelError(
            f"Could not download the MITRE ATT&CK data: {exc}"
        ) from exc

    index = _build_attack_index(bundle)
    _cache_write(key, index)
    return index


def _load_attack_index() -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if os.environ.get("MSF_INTEL_ATTACK", "1") in {"0", "false", "no"}:
        return None, {"available": False, "disabled": True}
    try:
        index = _attack_index()
    except Exception as exc:  # noqa: BLE001
        logger.exception("ATT&CK load failed")
        return None, {"available": False, "error": str(exc)}
    return index, {
        "available": True,
        "software_objects": index.get("software_objects"),
        "technique_objects": index.get("technique_objects"),
        "downloaded_at": index.get("downloaded_at"),
    }


def _attack_for_cve(cve_id: str, index: dict[str, Any]) -> dict[str, Any] | None:
    techniques = (index.get("cve_to_techniques") or {}).get(cve_id) or []
    software = (index.get("cve_to_software") or {}).get(cve_id) or []
    actors = (index.get("cve_to_actors") or {}).get(cve_id) or []
    if not (techniques or software or actors):
        return None
    return {
        "techniques": techniques[:10],
        "software": software[:10],
        "actors": actors[:10],
    }


# ---------------------------------------------------------------------------
# NVD (CVE details + CVSS)
# ---------------------------------------------------------------------------


def _nvd_request(url: str) -> dict[str, Any] | None:
    _throttle_nvd()
    key = _nvd_api_key()
    if key:
        url += ("&" if "?" in url else "?") + "apiKey=" + urllib.parse.quote(key)
    cache_key = "nvd-" + hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]

    cached = _cache_read(cache_key, NVD_CACHE_TTL)
    if cached is not None:
        if cached.get("nvd_not_found"):
            return None
        return cached

    try:
        raw = _http_get(url, timeout=30)
        data = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            _cache_write(cache_key, {"nvd_not_found": True})
            return None
        raise IntelError(
            f"NVD request failed (HTTP {exc.code}): {exc.reason}"
        ) from exc
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise IntelError(f"NVD request failed: {exc}") from exc

    _cache_write(cache_key, data)
    return data


def _cve_by_id(cve_id: str) -> dict[str, Any] | None:
    url = NVD_BASE + "?cveId=" + urllib.parse.quote(cve_id)
    data = _nvd_request(url)
    if not data:
        return None
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve")
    return cve if isinstance(cve, dict) else None


def _nvd_keyword(keyword: str, limit: int) -> list[dict[str, Any]]:
    url = (
        NVD_BASE
        + "?keywordSearch="
        + urllib.parse.quote(keyword)
        + "&resultsPerPage=200"
    )
    data = _nvd_request(url)
    if not data:
        return []
    cves = [
        v.get("cve")
        for v in (data.get("vulnerabilities") or [])
        if isinstance(v, dict) and isinstance(v.get("cve"), dict)
    ]
    cves.sort(key=lambda c: c.get("published") or "", reverse=True)
    return cves[:limit]


def _first_en(values: Any) -> str | None:
    if not isinstance(values, list):
        return None
    for entry in values:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            return entry.get("value")
    return None


def _weaknesses(raw: Any) -> list[str]:
    cwes: list[str] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        for desc in entry.get("description") or []:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                value = desc.get("value")
                if value and value not in cwes:
                    cwes.append(value)
    return cwes[:5]


def _cvss(metrics: Any) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        return {"version": None, "base_score": None, "severity": None, "vector": None}
    for group in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(group) or []
        primary = [e for e in entries if e.get("type") == "Primary"]
        for entry in (primary or entries):
            data = entry.get("cvssData") or {}
            if data.get("baseScore") is None and data.get("baseSeverity") is None:
                continue
            return {
                "version": data.get("version"),
                "base_score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
    return {"version": None, "base_score": None, "severity": None, "vector": None}


def _finding_from_cve(
    cve: dict[str, Any],
    kev_by_cve: dict[str, dict[str, Any]],
    attack_index: dict[str, Any] | None,
) -> dict[str, Any]:
    cve_id = cve.get("id")
    finding: dict[str, Any] = {
        "cve_id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": _first_en(cve.get("descriptions")),
        "weaknesses": _weaknesses(cve.get("weaknesses")),
        "references": [
            r.get("url")
            for r in (cve.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ][:10],
        "cvss": _cvss(cve.get("metrics")),
        "kev": None,
        "attck": None,
    }
    if cve_id in kev_by_cve:
        entry = kev_by_cve[cve_id]
        finding["kev"] = {
            "actively_exploited": True,
            "date_added": entry.get("dateAdded"),
            "due_date": entry.get("dueDate"),
            "vendor_project": entry.get("vendorProject"),
            "product": entry.get("product"),
            "vulnerability_name": entry.get("vulnerabilityName"),
            "required_action": entry.get("requiredAction"),
            "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse"),
        }
    if attack_index is not None:
        mapping = _attack_for_cve(cve_id, attack_index)
        if mapping:
            finding["attck"] = mapping
    return finding


# ---------------------------------------------------------------------------
# Public API used by the MCP tools
# ---------------------------------------------------------------------------


def cve_lookup(query: str, limit: int = 5) -> dict[str, Any]:
    """Enrich a CVE ID or a keyword (service + version) with NVD/KEV/ATT&CK."""
    q = (query or "").strip()
    if not q:
        raise IntelError(
            "query is required: a CVE ID (e.g. 'CVE-2021-44228') or a keyword "
            "like 'openssh 9.2p1'."
        )
    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise IntelError("limit must be an integer.") from exc
    limit = max(1, min(limit, 25))

    kev_by_cve, kev_meta = _load_kev_index()
    attack_index, attack_meta = _load_attack_index()

    ids = CVE_RE.findall(q)
    not_found: list[str] = []
    if ids:
        findings = []
        for cve_id in dict.fromkeys(cve_id.upper() for cve_id in ids):
            if len(findings) >= limit:
                break
            cve = _cve_by_id(cve_id)
            if cve is None:
                not_found.append(cve_id)
                continue
            findings.append(_finding_from_cve(cve, kev_by_cve, attack_index))
        mode = "cve_ids"
    else:
        findings = [
            _finding_from_cve(cve, kev_by_cve, attack_index)
            for cve in _nvd_keyword(q, limit)
        ]
        mode = "keyword"

    return {
        "query": q,
        "mode": mode,
        "returned": len(findings),
        "not_found": not_found,
        "sources": {
            "nvd": {"available": True, "api_key_set": bool(_nvd_api_key())},
            "kev": kev_meta,
            "attck": attack_meta,
        },
        "findings": findings,
        "hint": (
            "Findings flagged in 'kev' are actively exploited in the wild. "
            "Use msf_exploit_availability on the CVE IDs with the highest CVSS "
            "or KEV status to check for public exploit modules."
        ),
    }


def refresh_intel(include_attack: bool = True) -> dict[str, Any]:
    """Force a re-download of the KEV catalog and (optionally) ATT&CK."""
    result: dict[str, Any] = {"cache_dir": _cache_dir()}

    try:
        data = _kev_data(force=True)
        result["kev"] = {
            "status": "ok",
            "count": data.get("count"),
            "catalog_date": data.get("dateReleased"),
            "title": data.get("title"),
        }
    except Exception as exc:  # noqa: BLE001 - report per-feed instead of raising
        result["kev"] = {"status": "error", "error": str(exc)}

    if include_attack and os.environ.get("MSF_INTEL_ATTACK", "1") not in {
        "0",
        "false",
        "no",
    }:
        try:
            index = _attack_index(force=True)
            result["attck"] = {
                "status": "ok",
                "software_objects": index.get("software_objects"),
                "technique_objects": index.get("technique_objects"),
                "downloaded_at": index.get("downloaded_at"),
            }
        except Exception as exc:  # noqa: BLE001
            result["attck"] = {"status": "error", "error": str(exc)}

    return result


__all__ = [
    "IntelError",
    "cve_lookup",
    "refresh_intel",
]
