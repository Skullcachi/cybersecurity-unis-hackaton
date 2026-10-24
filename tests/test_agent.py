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


def load_inputs():
    inventory = json.loads((ROOT / "inventory.json").read_text(encoding="utf-8"))
    logs = (ROOT / "system_logs.txt").read_text(encoding="utf-8")
    scenarios = json.loads((ROOT / "scenarios.json").read_text(encoding="utf-8"))
    advisories = {item["label"]: item["advisory"] for item in scenarios}
    return inventory, logs, advisories


class ScenarioHuntTests(unittest.TestCase):
    def test_nginx_zero_day_marks_web_host_and_scanner_ioc(self):
        from agent import run_hunt

        inventory, logs, advisories = load_inputs()
        report = run_hunt(advisories["Nginx Zero-Day"], inventory, logs)
        json.dumps(report)

        self.assertEqual(set(report), REPORT_KEYS)
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

    def test_node_runtime_marks_api_host_and_command_injection_technique(self):
        from agent import run_hunt

        inventory, logs, advisories = load_inputs()
        report = run_hunt(
            advisories["Node.js Request Smuggling (CVE-2024-27980)"],
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


if __name__ == "__main__":
    unittest.main()
