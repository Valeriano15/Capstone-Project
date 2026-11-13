"""End-to-end tests against a mock msfrpcd MessagePack RPC server.

This exercises the real pymetasploit3 client, HTTP transport, msgpack framing,
and the MCP client layer without requiring a Metasploit host.

    mcp\\.venv\\Scripts\\python.exe -m unittest discover -s tests -v
"""

import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import msgpack

import msf_client as msf


MODULE_INFO = {
    "name": "SMB Version Detection",
    "description": "Fingerprint the SMB service on the target host.",
    "rank": "normal",
    "disclosure_date": "2011-01-01",
    "platform": "windows",
    "arch": "x86",
    "privileged": False,
    "authors": ["Metasploit"],
    "references": ["https://example.invalid/smb"],
}

MODULE_OPTIONS = {
    "RHOSTS": {
        "type": "address",
        "required": True,
        "advanced": False,
        "evasion": False,
        "description": "The target host(s).",
        "default": "",
    },
    "RPORT": {
        "type": "port",
        "required": True,
        "advanced": False,
        "evasion": False,
        "description": "The SMB port.",
        "default": 445,
    },
    "THREADS": {
        "type": "integer",
        "required": False,
        "advanced": True,
        "evasion": False,
        "description": "Number of concurrent threads.",
        "default": 1,
    },
}

SEARCH_RESULTS = [
    {
        "type": "auxiliary",
        "name": "scanner/smb/smb_version",
        "fullname": "auxiliary/scanner/smb/smb_version",
        "rank": "normal",
        "disclosuredate": "2011-01-01",
    },
    {
        "type": "auxiliary",
        "name": "dos/smb/smb_flood",
        "fullname": "auxiliary/dos/smb/smb_flood",
        "rank": "normal",
        "disclosuredate": "2011-01-01",
    },
    {
        "type": "exploit",
        "name": "windows/smb/ms17_010_eternalblue",
        "fullname": "exploit/windows/smb/ms17_010_eternalblue",
        "rank": "great",
        "disclosuredate": "2017-03-14",
    },
]


class MockRpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = msgpack.unpackb(self.rfile.read(length), strict_map_key=False)
        response = self.server.dispatch(request)
        payload = msgpack.packb(response)
        self.send_response(200)
        self.send_header("Content-Type", "binary/message-pack")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class MockMsfrpcd(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), MockRpcHandler)
        self.password = "test-password"
        self.last_search = None
        self.last_execute_options = None
        self.stopped_jobs = []
        self.execute_calls = 0
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    def dispatch(self, request):
        method = request[0]
        token = request[1] if len(request) > 1 else None

        if method == "auth.login":
            username, password = request[1], request[2]
            if username != "msf" or password != self.password:
                return {"result": "failure"}
            return {"result": "success", "token": "initial-token"}

        if token is None:
            return {"error": "missing token"}

        if method == "auth.token.add":
            return {"result": "success"}
        if method == "core.version":
            return {"version": "6.4.0-mock", "ruby": "3.3.0", "api": "1.0"}
        if method == "job.list":
            return {"0": "Auxiliary: scanner/smb/smb_version"}
        if method == "job.stop":
            self.stopped_jobs.append(request[2])
            return {"result": "success"}
        if method == "db.status":
            return {"driver": "postgresql", "db": "msf"}
        if method == "db.workspaces":
            return {"workspaces": ["default"]}
        if method == "db.hosts":
            return {
                "hosts": [
                    {
                        "address": "192.168.56.10",
                        "name": "lab-target",
                        "state": "alive",
                    }
                ]
            }
        if method == "db.services":
            return {
                "services": [
                    {"host": "192.168.56.10", "port": 445, "proto": "tcp", "name": "smb"}
                ]
            }
        if method == "db.vulns":
            return {
                "vulns": [
                    {"host": "192.168.56.10", "name": "mock-vuln", "info": "test"}
                ]
            }
        if method == "module.search":
            self.last_search = request[2]
            return SEARCH_RESULTS
        if method == "module.info":
            return MODULE_INFO
        if method == "module.options":
            return MODULE_OPTIONS
        if method == "module.execute":
            self.last_execute_options = request[4]
            self.execute_calls += 1
            return {"job_id": 0, "uuid": "mock-uuid-1"}
        if method == "module.results":
            return {
                "status": "completed",
                "result": {
                    "services": [
                        {
                            "host": "192.168.56.10",
                            "port": 445,
                            "name": "smb",
                            "info": "Windows Server 2019",
                        }
                    ]
                },
            }
        return {"error": f"unhandled method {method}"}


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockMsfrpcd()
        cls.env = mock.patch.dict(
            os.environ,
            {
                "MSF_HOST": "127.0.0.1",
                "MSF_PORT": str(cls.server.port),
                "MSF_USERNAME": "msf",
                "MSF_PASSWORD": "test-password",
                "MSF_SSL": "false",
                "MSF_ALLOWED_TARGETS": "192.168.56.0/24",
                "MSF_ALLOWED_MODULE_PREFIXES": "scanner/,gather/,analyze/",
            },
            clear=False,
        )
        cls.env.start()
        msf.get_config.cache_clear()
        msf._reset_client()

    @classmethod
    def tearDownClass(cls):
        msf._reset_client()
        cls.env.stop()
        msf.get_config.cache_clear()
        cls.server.shutdown()
        cls.server.server_close()

    def test_status_uses_real_rpc_transport(self):
        result = msf.status()
        self.assertTrue(result["connected"])
        self.assertEqual(result["version"], "6.4.0-mock")
        self.assertEqual(result["database"]["driver"], "postgresql")
        self.assertEqual(
            result["scope"]["target_allowlist"], ["192.168.56.0/24"]
        )
        self.assertFalse(result["scope"]["execution_locked"])

    def test_search_filters_scope_and_adds_type_filter(self):
        result = msf.search_auxiliary("smb", limit=10)
        self.assertIn("type:auxiliary", self.server.last_search)
        self.assertEqual(result["total_matches"], 1)
        self.assertEqual(result["skipped_out_of_scope"], 1)
        self.assertEqual(result["modules"][0]["module"], "scanner/smb/smb_version")
        self.assertIn("SMB", result["modules"][0]["description"])

    def test_search_strips_caller_type_filter(self):
        msf.search_auxiliary("smb type:exploit", limit=5)
        self.assertEqual(self.server.last_search, "smb type:auxiliary")

    def test_module_info(self):
        result = msf.auxiliary_info("auxiliary/scanner/smb/smb_version")
        self.assertTrue(result["in_scope"])
        names = {option["name"] for option in result["options"]}
        self.assertIn("RHOSTS", names)
        # Advanced options are excluded by default.
        self.assertNotIn("THREADS", names)
        rhosts = next(o for o in result["options"] if o["name"] == "RHOSTS")
        self.assertTrue(rhosts["required"])

    def test_run_module_passes_options_and_returns_job(self):
        result = msf.run_auxiliary(
            "scanner/smb/smb_version",
            {"RHOSTS": "192.168.56.10", "THREADS": 4},
        )
        self.assertEqual(result["uuid"], "mock-uuid-1")
        self.assertEqual(result["job_id"], 0)
        self.assertEqual(result["targets"], ["192.168.56.10"])
        self.assertEqual(self.server.last_execute_options["RHOSTS"], "192.168.56.10")
        self.assertEqual(self.server.last_execute_options["THREADS"], 4)

    def test_results_jobs_and_stop(self):
        results = msf.scan_results("mock-uuid-1")
        self.assertEqual(results["status"], "completed")
        self.assertIn("services", results["result"]["result"])

        jobs = msf.list_jobs()
        self.assertEqual(jobs["count"], 1)

        stopped = msf.stop_job(0)
        self.assertTrue(stopped["stopped"])
        self.assertIn("0", self.server.stopped_jobs)

    def test_db_reads(self):
        hosts = msf.db_records("hosts")
        self.assertEqual(hosts["total"], 1)
        self.assertEqual(hosts["records"][0]["address"], "192.168.56.10")

        services = msf.db_records("services")
        self.assertEqual(services["records"][0]["port"], 445)

        vulns = msf.db_records("vulns")
        self.assertEqual(vulns["records"][0]["name"], "mock-vuln")

    def test_run_rejects_out_of_scope_target_over_real_transport(self):
        with self.assertRaises(msf.MsfToolError):
            msf.run_auxiliary(
                "scanner/smb/smb_version", {"RHOSTS": "10.0.0.5"}
            )

    def test_mcp_tool_roundtrip(self):
        import asyncio
        import json

        from fastmcp import Client

        import server

        async def run():
            async with Client(server.mcp) as client:
                result = await client.call_tool(
                    "msf_search_auxiliary", {"query": "smb", "limit": 5}
                )
                self.assertEqual(len(result), 1)
                payload = json.loads(result[0].text)
                self.assertEqual(payload["total_matches"], 1)
                self.assertEqual(
                    payload["modules"][0]["module"], "scanner/smb/smb_version"
                )

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
