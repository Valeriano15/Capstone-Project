"""Unit tests for intel_client (offline, with mocked HTTP + temp cache)."""

import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

import intel_client as intel


KEV_FIXTURE = {
    "title": "CISA Catalog",
    "catalogVersion": "2024.01.01",
    "dateReleased": "2024-01-01T00:00:00.000Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "dateAdded": "2021-12-10",
            "shortDescription": "RCE in log4j.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        }
    ],
}

NVD_FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2024-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Log4j RCE."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            },
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-502"}],
                    }
                ],
                "references": [{"url": "https://example.invalid/1"}],
            }
        }
    ]
}

ATTACK_FIXTURE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--2",
            "name": "Exploit Public-Facing Application",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1190",
                    "url": "https://attack.mitre.org/techniques/T1190",
                },
                {
                    "source_name": "Microsoft Log4j Dec 2021",
                    "url": "https://example.invalid/guidance-for-cve-2021-44228",
                },
            ],
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--3",
            "name": "Magic Hound",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "G0059",
                    "url": "https://attack.mitre.org/groups/G0059",
                }
            ],
        },
        {
            "type": "malware",
            "id": "malware--1",
            "name": "PowerLess Trojan",
            "external_references": [
                {
                    "source_name": "Cybereason",
                    "description": "Dropper tied to CVE-2021-44228 exploitation.",
                    "url": "https://example.invalid/powerless",
                }
            ],
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--3",
            "target_ref": "attack-pattern--2",
            "external_references": [
                {
                    "source_name": "Check Point APT35",
                    "description": "APT35 exploits the Log4j vulnerability (CVE-2021-44228).",
                    "url": "https://example.invalid/apt35-log4j",
                }
            ],
        },
    ],
}


class IntelClientTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        env = mock.patch.dict(
            os.environ,
            {"MSF_INTEL_CACHE_DIR": self.tmpdir, "MSF_NVD_API_KEY": ""},
            clear=False,
        )
        env.start()
        self.addCleanup(env.stop)
        throttle = mock.patch.object(intel, "_throttle_nvd")
        throttle.start()
        self.addCleanup(throttle.stop)

    def _mock_http(self, routes):
        """routes: dict url-substring -> bytes (or Exception)."""
        calls = {"count": 0}

        def fake_http_get(url, timeout=30.0):
            calls["count"] += 1
            for key, payload in routes.items():
                if key in url:
                    if isinstance(payload, Exception):
                        raise payload
                    if isinstance(payload, str):
                        return payload.encode("utf-8")
                    return json.dumps(payload).encode("utf-8")
            raise AssertionError(f"unexpected URL in test: {url}")

        patcher = mock.patch.object(intel, "_http_get", side_effect=fake_http_get)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def test_cve_id_lookup_enriches_with_kev_and_attck(self):
        self._mock_http(
            {
                "cisa.gov": KEV_FIXTURE,
                "mitre/cti": ATTACK_FIXTURE,
                "services.nvd.nist.gov": NVD_FIXTURE,
            }
        )
        result = intel.cve_lookup("CVE-2021-44228")

        self.assertEqual(result["mode"], "cve_ids")
        self.assertEqual(result["returned"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["cve_id"], "CVE-2021-44228")
        self.assertEqual(finding["description"], "Log4j RCE.")
        self.assertEqual(finding["cvss"]["base_score"], 10.0)
        self.assertEqual(finding["cvss"]["severity"], "CRITICAL")
        self.assertEqual(finding["weaknesses"], ["CWE-502"])
        self.assertTrue(finding["kev"]["actively_exploited"])
        self.assertEqual(
            finding["kev"]["required_action"], "Apply updates per vendor instructions."
        )
        self.assertEqual(finding["attck"]["techniques"][0]["id"], "T1190")
        self.assertEqual(finding["attck"]["actors"], ["Magic Hound (G0059)"])
        self.assertEqual(finding["attck"]["software"], ["PowerLess Trojan"])
        self.assertTrue(result["sources"]["kev"]["available"])
        self.assertTrue(result["sources"]["attck"]["available"])

    def test_keyword_lookup_sorts_by_published_desc_and_limits(self):
        nvd = {
            "vulnerabilities": [
                {"cve": {"id": f"CVE-2020-000{i}", "published": f"2020-01-0{i}"}}
                for i in range(1, 4)
            ]
        }
        self._mock_http(
            {
                "cisa.gov": KEV_FIXTURE,
                "mitre/cti": ATTACK_FIXTURE,
                "services.nvd.nist.gov": nvd,
            }
        )
        result = intel.cve_lookup("openssh 9.2", limit=2)
        self.assertEqual(result["mode"], "keyword")
        self.assertEqual(
            [f["cve_id"] for f in result["findings"]],
            ["CVE-2020-0003", "CVE-2020-0002"],
        )

    def test_unknown_cve_reported_in_not_found(self):
        def fake_http_get(url, timeout=30.0):
            if "cisa.gov" in url:
                return json.dumps(KEV_FIXTURE).encode("utf-8")
            if "mitre/cti" in url:
                return json.dumps(ATTACK_FIXTURE).encode("utf-8")
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        with mock.patch.object(intel, "_http_get", side_effect=fake_http_get):
            result = intel.cve_lookup("CVE-1999-0001")
        self.assertEqual(result["returned"], 0)
        self.assertEqual(result["not_found"], ["CVE-1999-0001"])

    def test_feeds_offline_degrades_gracefully(self):
        def fake_http_get(url, timeout=30.0):
            if "services.nvd.nist.gov" in url:
                return json.dumps(NVD_FIXTURE).encode("utf-8")
            raise urllib.error.URLError("offline")

        with mock.patch.object(intel, "_http_get", side_effect=fake_http_get):
            result = intel.cve_lookup("CVE-2021-44228")
        self.assertEqual(result["returned"], 1)
        self.assertIsNone(result["findings"][0]["kev"])
        self.assertIsNone(result["findings"][0]["attck"])
        self.assertFalse(result["sources"]["kev"]["available"])
        self.assertFalse(result["sources"]["attck"]["available"])

    def test_nvd_responses_are_cached(self):
        calls = self._mock_http(
            {
                "cisa.gov": KEV_FIXTURE,
                "mitre/cti": ATTACK_FIXTURE,
                "services.nvd.nist.gov": NVD_FIXTURE,
            }
        )
        intel.cve_lookup("CVE-2021-44228")
        first_count = calls["count"]
        intel.cve_lookup("CVE-2021-44228")
        self.assertEqual(calls["count"], first_count)  # everything came from cache

    def test_refresh_intel_reports_feed_status(self):
        self._mock_http({"cisa.gov": KEV_FIXTURE, "mitre/cti": ATTACK_FIXTURE})
        result = intel.refresh_intel()
        self.assertEqual(result["kev"]["status"], "ok")
        self.assertEqual(result["kev"]["count"], 1)
        self.assertEqual(result["attck"]["status"], "ok")
        self.assertEqual(result["attck"]["software_objects"], 1)

    def test_refresh_intel_without_attack_skips_download(self):
        calls = self._mock_http({"cisa.gov": KEV_FIXTURE})
        result = intel.refresh_intel(include_attack=False)
        self.assertEqual(result["kev"]["status"], "ok")
        self.assertNotIn("attck", result)

    def test_build_attack_index_maps_cve_to_techniques(self):
        index = intel._build_attack_index(ATTACK_FIXTURE)
        techniques = index["cve_to_techniques"]["CVE-2021-44228"]
        self.assertEqual([t["id"] for t in techniques], ["T1190"])
        # The technique is found both via its own citation and the relationship.
        self.assertIn("Microsoft Log4j Dec 2021", [t["citation"] for t in techniques])
        self.assertEqual(index["cve_to_software"]["CVE-2021-44228"], ["PowerLess Trojan"])
        self.assertEqual(index["cve_to_actors"]["CVE-2021-44228"], ["Magic Hound (G0059)"])
        self.assertEqual(index["format_version"], 2)

    def test_attack_can_be_disabled_via_env(self):
        with mock.patch.dict(os.environ, {"MSF_INTEL_ATTACK": "0"}):
            self._mock_http(
                {"cisa.gov": KEV_FIXTURE, "services.nvd.nist.gov": NVD_FIXTURE}
            )
            result = intel.cve_lookup("CVE-2021-44228")
        self.assertEqual(result["returned"], 1)
        self.assertIsNone(result["findings"][0]["attck"])
        self.assertEqual(result["sources"]["attck"], {"available": False, "disabled": True})

    def test_invalid_query_raises(self):
        with self.assertRaises(intel.IntelError):
            intel.cve_lookup("   ")


if __name__ == "__main__":
    unittest.main()
