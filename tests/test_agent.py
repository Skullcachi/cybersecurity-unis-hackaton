import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_KEYS = {
    "cve_id",
    "affected_software",
    "vulnerable_versions",
    "iocs",
    "is_system_vulnerable",
    "affected_hosts",
    "threat_detected_in_logs",
    "detected_log_evidence",
    "mitre_attack",
    "remediation_script",
}
ADDED_KEYS = {
    "severity",
    "findings",
    "corrections",
    "signoff",
    "cve_note",
    "alerts",
    "attack_patterns",
    "kill_chain",
    "honeypot",
}


def load_inputs():
    inventory = json.loads((ROOT / "inventory.json").read_text(encoding="utf-8"))
    logs = (ROOT / "system_logs.txt").read_text(encoding="utf-8")
    scenarios = json.loads((ROOT / "scenarios.json").read_text(encoding="utf-8"))
    advisories = {item["label"]: item["advisory"] for item in scenarios}
    return inventory, logs, advisories


def section(script: str, hostname: str) -> str:
    marker = f"host={hostname} "
    for part in script.split("#####"):
        if marker in part:
            return part
    raise AssertionError(hostname)


class ScenarioHuntTests(unittest.TestCase):
    def test_nginx_zero_day_marks_web_host_and_scanner_ioc(self):
        from agent import run_hunt

        inventory, logs, advisories = load_inputs()
        report = run_hunt(advisories["Nginx Zero-Day"], inventory, logs)
        json.dumps(report)

        self.assertTrue(REPORT_KEYS <= set(report))
        self.assertTrue(ADDED_KEYS <= set(report))
        self.assertEqual(report["cve_id"], "CVE-2026-21443")
        self.assertTrue(report["is_system_vulnerable"])
        self.assertEqual(report["affected_hosts"], ["web-nginx-01"])
        self.assertIn("203.0.113.50", report["iocs"])
        self.assertTrue(report["threat_detected_in_logs"])
        self.assertTrue(
            any("203.0.113.50" in line for line in report["detected_log_evidence"])
        )
        self.assertEqual(report["mitre_attack"]["technique_id"], "T1190")
        self.assertEqual(report["mitre_attack"]["mitre_mitigation_id"], "M1051")
        self.assertIn("1.26.2", report["remediation_script"])
        self.assertIn("OpenEMR", report["cve_note"])
        self.assertFalse(report["honeypot"]["engaged"])

    def test_php_cgi_marks_app_host_and_source_ip(self):
        from agent import run_hunt

        inventory, logs, advisories = load_inputs()
        report = run_hunt(
            advisories["PHP CGI RCE (CVE-2024-4577)"], inventory, logs
        )

        self.assertEqual(report["cve_id"], "CVE-2024-4577")
        self.assertEqual(report["affected_hosts"], ["app-php-01"])
        self.assertTrue(report["threat_detected_in_logs"])
        self.assertTrue(
            any("198.51.100.42" in line for line in report["detected_log_evidence"])
        )
        self.assertEqual(report["mitre_attack"]["technique_id"], "T1190")
        self.assertIn("8.2.20", report["remediation_script"])
        self.assertNotIn("apt-get", section(report["remediation_script"], "app-php-01"))

    def test_node_runtime_marks_api_host_and_command_injection_technique(self):
        from agent import run_hunt

        inventory, logs, advisories = load_inputs()
        report = run_hunt(
            advisories["Node.js Windows Command Injection (CVE-2024-27980)"],
            inventory,
            logs,
        )

        self.assertEqual(report["cve_id"], "CVE-2024-27980")
        self.assertEqual(report["affected_hosts"], ["api-node-01"])
        self.assertTrue(report["threat_detected_in_logs"])
        self.assertTrue(
            any("203.0.113.105" in line for line in report["detected_log_evidence"])
        )
        self.assertEqual(
            report["mitre_attack"],
            {
                "tactic": "Execution",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "mitre_mitigation_id": "M1051",
            },
        )
        self.assertIn("20.12.2", report["remediation_script"])
        self.assertNotIn("apt-get", section(report["remediation_script"], "api-node-01"))
        self.assertNotIn("Request Smuggling", advisories[
            "Node.js Windows Command Injection (CVE-2024-27980)"
        ])


class DetectionTests(unittest.TestCase):
    def test_empty_advisory_detects_attacks_from_logs_alone(self):
        from agent import run_hunt

        inventory, logs, _advisories = load_inputs()
        report = run_hunt("", inventory, logs)
        json.dumps(report)

        self.assertTrue(report["threat_detected_in_logs"])
        self.assertEqual(
            report["affected_hosts"],
            ["web-nginx-01", "app-php-01", "api-node-01"],
        )
        cves = {item["cve_id"] for item in report["findings"]}
        self.assertIn("CVE-2026-21443", cves)
        self.assertIn("CVE-2024-4577", cves)
        self.assertIn("CVE-2024-27980", cves)
        self.assertIsNone(report["cve_id"])
        self.assertFalse(any("index.html" in line for line in report["detected_log_evidence"]))
        self.assertNotIn("192.168.1.50", [item["actor"] for item in report["kill_chain"]])

    def test_php_signature_accepts_encoded_and_soft_hyphen_forms(self):
        from agent import run_hunt

        inventory = [
            {
                "hostname": "app-php-01",
                "os": "windows",
                "software": "PHP CGI / Apache",
                "version": "8.2.18",
                "status": "Active",
            }
        ]
        styles = [
            "2026-10-24 10:14:12 198.51.100.42 POST /php-cgi/php-cgi.exe?%2d%64+%61%6c%6c%6f%77%5f%75%72%6c%5f%69%6e%63%6c%75%64%65%3d%31 200\n",
            "2026-10-24 10:14:12 198.51.100.42 POST /php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1 200\n",
        ]
        for logs in styles:
            report = run_hunt("", inventory, logs)
            self.assertEqual(report["cve_id"], "CVE-2024-4577")
            self.assertEqual(report["affected_hosts"], ["app-php-01"])

    def test_header_abuse_is_not_mapped_to_node_cve(self):
        from agent import run_hunt

        inventory = [
            {
                "hostname": "api-node-01",
                "os": "windows",
                "software": "Node.js runtime",
                "version": "20.11.1",
                "status": "Active",
            }
        ]
        logs = (
            '2026-10-24 11:05:45 203.0.113.105 GET /api '
            '"Transfer-Encoding: \\x00chunked" 400\n'
        )
        report = run_hunt("", inventory, logs)
        self.assertTrue(report["threat_detected_in_logs"])
        self.assertIsNone(report["cve_id"])
        self.assertEqual(report["affected_hosts"], [])
        self.assertTrue(report["findings"])
        self.assertIsNone(report["findings"][0]["cve_id"])
        self.assertIn("not evidence of CVE-2024-27980", report["findings"][0]["cve_note"])

    def test_ioc_only_advisory_derives_cve_from_the_signature(self):
        from agent import run_hunt

        inventory, logs, _advisories = load_inputs()
        report = run_hunt("IoC IP: 198.51.100.42\n", inventory, logs)
        self.assertEqual(report["cve_id"], "CVE-2024-4577")
        self.assertEqual(report["affected_hosts"], ["app-php-01"])


class VersionLogicTests(unittest.TestCase):
    def test_php_branches_are_not_a_single_less_than_check(self):
        from agent import run_hunt

        advisory = (
            "CVE: CVE-2024-4577\nSoftware: PHP\n"
            "Vulnerable versions: < 8.2.20\nFixed version: 8.2.20\n"
        )
        cases = {
            "8.1.28": True,
            "8.1.29": False,
            "8.2.19": True,
            "8.2.20": False,
            "8.3.7": True,
            "8.3.8": False,
            "8.4.1": False,
        }
        for version, vulnerable in cases.items():
            inventory = [
                {
                    "hostname": "php-host",
                    "os": "windows",
                    "software": "PHP",
                    "version": version,
                    "status": "Active",
                }
            ]
            report = run_hunt(advisory, inventory, "")
            self.assertEqual(report["is_system_vulnerable"], vulnerable, version)
        self.assertIn("8.3.8", _hunt_php("8.3.7")["remediation_script"])
        self.assertIn("PHP.PHP.8.3", _hunt_php("8.3.7")["remediation_script"])
        self.assertIn("8.1.29", _hunt_php("8.1.28")["remediation_script"])

    def test_node_branches_use_their_own_fix_points(self):
        from agent import run_hunt

        advisory = (
            "CVE: CVE-2024-27980\nSoftware: Node.js\n"
            "Vulnerable versions: < 20.12.2\nFixed version: 20.12.2\n"
        )
        cases = {
            "18.20.1": True,
            "18.20.2": False,
            "20.12.1": True,
            "20.12.2": False,
            "21.7.2": True,
            "21.7.3": False,
            "22.0.0": False,
        }
        for version, vulnerable in cases.items():
            report = run_hunt(advisory, [_node(version)], "")
            self.assertEqual(report["is_system_vulnerable"], vulnerable, version)

    def test_inactive_host_is_ignored(self):
        from agent import run_hunt

        advisory = "CVE: CVE-2024-4577\nSoftware: PHP\nVulnerable versions: < 8.2.20\n"
        inventory = [
            {
                "hostname": "old",
                "os": "windows",
                "software": "PHP",
                "version": "8.2.18",
                "status": "Retired",
            }
        ]
        report = run_hunt(advisory, inventory, "")
        self.assertEqual(report["affected_hosts"], [])


class RemediationTests(unittest.TestCase):
    def test_package_names_follow_the_host_os(self):
        from agent import run_hunt

        php_log = (
            "2026-10-24 10:14:12 198.51.100.42 POST "
            "/php-cgi/php-cgi.exe?%ADd+allow_url_include=1 200\n"
        )
        node_log = (
            '2026-10-24 11:05:44 203.0.113.105 POST /api/v1/jobs '
            'child_process.spawn task.bat "report&whoami" 500\n'
        )
        nginx_log = "2026-10-24 09:16:41 203.0.113.50 GET / 200 ZD-Hunter/6.0\n"

        linux_php = run_hunt("", [_php("8.2.18", "linux", "php-lin")], php_log)
        self.assertFalse(linux_php["is_system_vulnerable"])
        self.assertIn("apt-get install -y php8.2-cgi", linux_php["remediation_script"])
        self.assertIn("does not apply to Linux", linux_php["remediation_script"])
        self.assertNotIn("PHP=", linux_php["remediation_script"])

        windows_php = run_hunt("", [_php("8.2.18", "windows", "php-win")], php_log)
        self.assertTrue(windows_php["is_system_vulnerable"])
        self.assertNotIn("apt-get", windows_php["remediation_script"])
        self.assertIn("PHP.PHP.8.2", windows_php["remediation_script"])
        self.assertIn("8.2.20", windows_php["remediation_script"])
        self.assertIn("php-cgi.exe", windows_php["remediation_script"])
        self.assertIn("php -v", windows_php["remediation_script"])

        linux_node = run_hunt("", [_node("20.11.1", "linux")], node_log)
        self.assertFalse(linux_node["is_system_vulnerable"])
        self.assertIn("apt-get install -y nodejs", linux_node["remediation_script"])
        self.assertNotRegex(linux_node["remediation_script"], r"Node\.js=")
        self.assertIn("does not apply to Linux", linux_node["remediation_script"])

        windows_node = run_hunt("", [_node("20.11.1")], node_log)
        self.assertNotIn("apt-get", windows_node["remediation_script"])
        self.assertIn("20.12.2", windows_node["remediation_script"])
        self.assertIn("node -v", windows_node["remediation_script"])

        linux_nginx = run_hunt(
            "",
            [
                {
                    "hostname": "web",
                    "os": "linux",
                    "software": "nginx",
                    "version": "1.24.0",
                    "status": "Active",
                }
            ],
            nginx_log,
        )
        self.assertIn("apt-get install -y nginx", linux_nginx["remediation_script"])
        self.assertIn("1.26.2", linux_nginx["remediation_script"])

    def test_demo_inventory_uses_real_package_names(self):
        from agent import run_hunt

        inventory, logs, _advisories = load_inputs()
        script = run_hunt("", inventory, logs)["remediation_script"]
        self.assertNotRegex(script, r'apt-get install[^\n]*"(PHP|Node\.js|Nginx HTTP Server)=')
        nginx = section(script, "web-nginx-01")
        php = section(script, "app-php-01")
        node = section(script, "api-node-01")
        self.assertIn("apt-get install -y nginx", nginx)
        self.assertIn("ufw deny from 203.0.113.50", nginx)
        self.assertIn("nginx -v", nginx)
        self.assertNotIn("apt-get", php)
        self.assertIn("php -v", php)
        self.assertNotIn("apt-get", node)
        self.assertIn("node -v", node)
        self.assertIn("/admin/config", node)

    def test_unknown_product_does_not_invent_an_apt_name(self):
        from agent import run_hunt

        advisory = (
            "CVE: CVE-2024-0001\nSoftware: Redis\n"
            "Vulnerable versions: < 7.2.4\nFixed version: 7.2.4\n"
            "IoC IP: 203.0.113.9\n"
        )
        inventory = [
            {
                "hostname": "cache-01",
                "os": "linux",
                "software": "Redis",
                "version": "7.0.0",
                "status": "Active",
            }
        ]
        logs = "2026-10-24 12:00:00 203.0.113.9 GET / 200\n"
        report = run_hunt(advisory, inventory, logs)
        self.assertEqual(report["affected_hosts"], ["cache-01"])
        self.assertNotIn("apt-get install", report["remediation_script"])
        self.assertIn("7.2.4", report["remediation_script"])


class ReportTests(unittest.TestCase):
    def test_specialist_report_covers_the_required_sections(self):
        from agent import generate_report, generate_report_html, run_hunt

        inventory, logs, _advisories = load_inputs()
        report = run_hunt("", inventory, logs)
        original = report["corrections"][0]["status"]
        markdown = generate_report(report)
        self.assertEqual(report["corrections"][0]["status"], original)
        for heading in [
            "## Executive summary",
            "## Attacker profile",
            "## Kill-chain timeline",
            "## Findings",
            "## Per-phase findings",
            "## Honeypot session analysis",
            "## CVEs",
            "## Per-phase remediations",
            "## Proposed patches",
            "## Corrections taken",
            "## Residual risks, assumptions, and limitations",
            "## Reviewer sign-off",
        ]:
            self.assertIn(heading, markdown)
        self.assertIn("198.51.100.42", markdown)
        self.assertIn("203.0.113.105", markdown)
        self.assertIn("203.0.113.50", markdown)
        self.assertIn("CVE-2024-4577", markdown)
        self.assertIn("CVE-2024-27980", markdown)
        self.assertIn("OpenEMR", markdown)
        self.assertIn("T1059", markdown)
        self.assertIn("T1190", markdown)
        self.assertIn("/admin/config", markdown)
        self.assertIn("8.2.18", markdown)
        self.assertIn("not an attack pattern", markdown)
        self.assertIn("simulation", markdown.lower())
        self.assertIn("- [ ]", markdown)
        self.assertNotIn("- [x]", markdown)

        marked = generate_report(report, {report["corrections"][0]["id"]: True})
        self.assertIn("- [x]", marked)
        html_report = generate_report_html(report)
        self.assertIn("<h2>Executive summary</h2>", html_report)
        self.assertIn("Kill-chain timeline", html_report)


def _php(version: str, os_name: str = "windows", hostname: str = "php-host") -> dict:
    return {
        "hostname": hostname,
        "os": os_name,
        "software": "PHP CGI / Apache",
        "version": version,
        "status": "Active",
    }


def _node(version: str, os_name: str = "windows") -> dict:
    return {
        "hostname": "api-node-01",
        "os": os_name,
        "software": "Node.js runtime",
        "version": version,
        "status": "Active",
    }


def _hunt_php(version: str) -> dict:
    from agent import run_hunt

    advisory = (
        "CVE: CVE-2024-4577\nSoftware: PHP\n"
        "Vulnerable versions: < 8.2.20\nFixed version: 8.2.20\n"
    )
    return run_hunt(advisory, [_php(version)], "")


if __name__ == "__main__":
    unittest.main()
