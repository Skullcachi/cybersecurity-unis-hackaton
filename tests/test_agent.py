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
    "response_outcome",
    "response_evidence",
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
        self.assertEqual(report["response_outcome"], "attack_completed")
        self.assertTrue(
            any("attack_completed" in line for line in report["response_evidence"])
        )
        self.assertIn("1.26.2", report["remediation_script"])

    def test_php_cgi_marks_app_host_and_source_ip(self):
        from agent import run_hunt

        inventory, logs, advisories = load_inputs()
        report = run_hunt(
            advisories["PHP CGI RCE (CVE-2024-4577)"], inventory, logs
        )

        self.assertEqual(report["cve_id"], "CVE-2024-4577")
        self.assertFalse(report["is_system_vulnerable"])
        self.assertEqual(report["affected_hosts"], [])
        self.assertTrue(report["threat_detected_in_logs"])
        self.assertTrue(
            any("198.51.100.42" in line for line in report["detected_log_evidence"])
        )
        self.assertEqual(report["response_outcome"], "patched_after_detection")
        self.assertTrue(
            any("app-php-01" in line for line in report["response_evidence"])
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
        self.assertFalse(report["is_system_vulnerable"])
        self.assertEqual(report["affected_hosts"], [])
        self.assertFalse(report["threat_detected_in_logs"])
        self.assertFalse(
            any("203.0.113.105" in line for line in report["detected_log_evidence"])
        )
        self.assertEqual(report["response_outcome"], "patched_from_advisory")
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


class HuntReportViewTests(unittest.TestCase):
    def view_for(self, label: str) -> tuple[dict, dict]:
        from agent import run_hunt
        from report_view import hunt_report

        inventory, logs, advisories = load_inputs()
        report = run_hunt(advisories[label], inventory, logs)
        return report, hunt_report(report)

    def test_nginx_report_repeats_the_completed_attack(self):
        report, view = self.view_for("Nginx Zero-Day")

        self.assertEqual(view["cve_id"], report["cve_id"])
        self.assertEqual(view["affected_hosts"], report["affected_hosts"])
        self.assertEqual(view["iocs"], report["iocs"])
        self.assertEqual(view["evidence"], report["detected_log_evidence"])
        self.assertEqual(view["action"], report["response_evidence"])
        self.assertEqual(view["remediation_script"], report["remediation_script"])
        self.assertEqual(view["mitre"]["technique_id"], "T1190")
        self.assertIn("Ataque ejecutado por completo", view["verdict"])

    def test_php_report_repeats_the_patch_after_the_attempt(self):
        report, view = self.view_for("PHP CGI RCE (CVE-2024-4577)")

        self.assertEqual(view["affected_hosts"], report["affected_hosts"])
        self.assertEqual(view["evidence"], report["detected_log_evidence"])
        self.assertEqual(view["action"], report["response_evidence"])
        self.assertTrue(view["evidence"])
        self.assertIn("identificó el intento", view["verdict"])

    def test_node_report_repeats_the_patch_from_the_advisory(self):
        report, view = self.view_for("Node.js Request Smuggling (CVE-2024-27980)")

        self.assertEqual(view["evidence"], report["detected_log_evidence"])
        self.assertEqual(view["evidence"], [])
        self.assertEqual(view["action"], report["response_evidence"])
        self.assertIn("patched_from_advisory", view["action"][0])
        self.assertIn("leyó el advisory", view["verdict"])


if __name__ == "__main__":
    unittest.main()
