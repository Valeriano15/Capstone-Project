"""Unit tests for the scan-only Metasploit client's scope controls.

Run from the capstone directory:

    mcp\\.venv\\Scripts\\python.exe -m unittest discover -s tests -v
"""

import os
import unittest
from unittest import mock

import msf_client as msf


class FakeModule:
    def __init__(self, values):
        self.options = ["RHOSTS", "THREADS", "RPORT"]
        self.required = ["RHOSTS"]
        self._values = values
        self.executed = False

    def __getitem__(self, key):
        return self._values.get(key)

    def __setitem__(self, key, value):
        if key not in self.options:
            raise KeyError(f"Invalid option '{key}'.")
        self._values[key] = value

    def execute(self):
        self.executed = True
        return {"job_id": 3, "uuid": "uuid-123"}


class FakeModules:
    def __init__(self, module):
        self._module = module

    def use(self, module_type, module_name):
        return self._module


class FakeClient:
    def __init__(self, module):
        self.modules = FakeModules(module)


class AllowlistTests(unittest.TestCase):
    allowed = (
        "192.168.56.0/24",
        "10.10.0.0/16",
        "172.16.5.5",
        "lab-host.example",
    )

    def test_plain_ip_inside(self):
        self.assertTrue(msf.target_within_allowlist("192.168.56.10", self.allowed))

    def test_plain_ip_outside(self):
        self.assertFalse(msf.target_within_allowlist("192.168.57.10", self.allowed))

    def test_exact_ip_allowlist_entry(self):
        self.assertTrue(msf.target_within_allowlist("172.16.5.5", self.allowed))

    def test_subnet_inside(self):
        self.assertTrue(
            msf.target_within_allowlist("192.168.56.0/28", self.allowed)
        )

    def test_subnet_broader_than_allowlist(self):
        self.assertFalse(
            msf.target_within_allowlist("192.168.0.0/16", self.allowed)
        )

    def test_short_range_inside(self):
        self.assertTrue(
            msf.target_within_allowlist("192.168.56.10-20", self.allowed)
        )

    def test_long_range_inside(self):
        self.assertTrue(
            msf.target_within_allowlist("192.168.56.10-192.168.56.20", self.allowed)
        )

    def test_range_crossing_boundary(self):
        self.assertFalse(
            msf.target_within_allowlist(
                "192.168.56.250-192.168.57.10", self.allowed
            )
        )

    def test_hostname_exact_match(self):
        self.assertTrue(msf.target_within_allowlist("lab-host.example", self.allowed))

    def test_hostname_not_listed(self):
        self.assertFalse(msf.target_within_allowlist("evil.example", self.allowed))

    def test_empty_target(self):
        self.assertFalse(msf.target_within_allowlist("", self.allowed))


class ScopeTests(unittest.TestCase):
    def test_auxiliary_prefix_is_stripped(self):
        self.assertEqual(
            msf.require_auxiliary_name("auxiliary/scanner/smb/smb_version"),
            "scanner/smb/smb_version",
        )

    def test_scanner_allowed(self):
        self.assertTrue(msf.is_module_allowed("scanner/smb/smb_version"))

    def test_gather_allowed(self):
        self.assertTrue(msf.is_module_allowed("gather/shodan_search"))

    def test_exploit_blocked(self):
        self.assertFalse(msf.is_module_allowed("windows/smb/ms17_010_eternalblue"))

    def test_dos_blocked_even_with_auxiliary_prefix(self):
        self.assertFalse(msf.is_module_allowed("auxiliary/dos/tcp/synflood"))

    def test_fuzzers_blocked(self):
        self.assertFalse(msf.is_module_allowed("fuzzers/http/http_form_field"))


class RunModuleTests(unittest.TestCase):
    def setUp(self):
        msf.get_config.cache_clear()
        self.module = FakeModule({"RHOSTS": "192.168.56.10", "THREADS": 1, "RPORT": 445})
        self.client = FakeClient(self.module)
        self.patcher = mock.patch.object(
            msf, "_get_client", return_value=self.client
        )
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        msf.get_config.cache_clear()

    def _env(self, **overrides):
        values = {
            "MSF_HOST": "192.168.56.1",
            "MSF_PASSWORD": "test-password",
            "MSF_ALLOWED_TARGETS": "192.168.56.0/24",
        }
        values.update(overrides)
        return mock.patch.dict(os.environ, values, clear=False)

    def test_runs_allowed_scanner(self):
        with self._env():
            result = msf.run_auxiliary(
                "scanner/smb/smb_version", {"THREADS": 4}
            )
        self.assertEqual(result["uuid"], "uuid-123")
        self.assertEqual(result["job_id"], 3)
        self.assertTrue(self.module.executed)

    def test_rejects_target_outside_allowlist(self):
        with self._env():
            with self.assertRaises(msf.MsfToolError):
                msf.run_auxiliary(
                    "scanner/smb/smb_version", {"RHOSTS": "192.168.57.10"}
                )
        self.assertFalse(self.module.executed)

    def test_requires_allowlist_configuration(self):
        with self._env(MSF_ALLOWED_TARGETS=""):
            with self.assertRaises(msf.MsfToolError):
                msf.run_auxiliary("scanner/smb/smb_version")
        self.assertFalse(self.module.executed)

    def test_rejects_dos_module(self):
        with self._env():
            with self.assertRaises(msf.MsfToolError):
                msf.run_auxiliary("dos/tcp/synflood")
        self.assertFalse(self.module.executed)

    def test_rejects_missing_required_option(self):
        with self._env():
            with self.assertRaises(msf.MsfToolError):
                msf.run_auxiliary(
                    "scanner/smb/smb_version", {"RHOSTS": ""}
                )
        self.assertFalse(self.module.executed)

    def test_rejects_unknown_option(self):
        with self._env():
            with self.assertRaises(msf.MsfToolError):
                msf.run_auxiliary(
                    "scanner/smb/smb_version", {"NOT_AN_OPTION": "x"}
                )
        self.assertFalse(self.module.executed)

    def test_rejects_excessive_target_count(self):
        targets = ",".join(
            f"10.{i // 65025}.{(i // 255) % 255}.{i % 255}"
            for i in range(msf.MAX_TARGET_CHECKS + 1)
        )
        with self._env():
            with self.assertRaisesRegex(msf.MsfToolError, "above the limit"):
                msf.run_auxiliary(
                    "scanner/smb/smb_version", {"RHOSTS": targets}
                )
        self.assertFalse(self.module.executed)


class WorkspaceNamesTests(unittest.TestCase):
    def test_list_of_workspace_dicts(self):
        # Real msfrpcd shape: {'workspaces': [{'name': 'default', ...}, ...]}
        self.assertEqual(
            msf._workspace_names([{"name": "default"}, {"name": "lab"}]),
            ["default", "lab"],
        )

    def test_list_of_name_strings(self):
        # Older mock shape tolerated for robustness.
        self.assertEqual(
            msf._workspace_names(["default", "lab"]), ["default", "lab"]
        )

    def test_dict_mapping_names_to_objects(self):
        self.assertEqual(
            msf._workspace_names({"default": object(), "lab": object()}),
            ["default", "lab"],
        )

    def test_empty_and_invalid_shapes(self):
        self.assertEqual(msf._workspace_names(None), [])
        self.assertEqual(msf._workspace_names([]), [])
        self.assertEqual(msf._workspace_names([{"id": 1}, 3, "", " "]), [])


if __name__ == "__main__":
    unittest.main()
