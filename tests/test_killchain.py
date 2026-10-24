import json
import unittest
from pathlib import Path

from catalog import TACTIC_ORDER


ROOT = Path(__file__).resolve().parents[1]


def load_inputs():
    inventory = json.loads((ROOT / "inventory.json").read_text(encoding="utf-8"))
    logs = (ROOT / "system_logs.txt").read_text(encoding="utf-8")
    return inventory, logs


class KillChainTests(unittest.TestCase):
    def test_order_allows_pre_access_swap_and_rejects_inversions(self):
        from killchain import plausible_order

        self.assertTrue(
            plausible_order(["TA0042", "TA0043", "TA0001", "TA0002", "TA0009"])
        )
        self.assertTrue(
            plausible_order(["TA0043", "TA0043", "TA0042", "TA0001", "TA0002"])
        )
        self.assertFalse(plausible_order(["TA0010", "TA0043"]))
        self.assertFalse(plausible_order(["TA0002", "TA0001"]))

    def test_session_gap_does_not_stitch_unrelated_bursts(self):
        from killchain import correlate_events

        events = [
            {
                "ip": "203.0.113.9",
                "timestamp": "2026-10-24 09:00:00",
                "tactic_id": "TA0043",
                "text": "scan",
            },
            {
                "ip": "203.0.113.9",
                "timestamp": "2026-10-24 12:00:00",
                "tactic_id": "TA0002",
                "text": "exec",
            },
        ]
        result = correlate_events(events)
        self.assertEqual(len(result), 2)
        self.assertTrue(all(not item["is_attack_pattern"] for item in result))
        self.assertTrue(all(item["confidence"] <= 0.4 for item in result))

    def test_fixture_promotes_only_multi_tactic_actors(self):
        from agent import run_hunt

        inventory, logs = load_inputs()
        report = run_hunt("", inventory, logs)
        actors = {item["actor"]: item for item in report["kill_chain"]}

        scanner = actors["203.0.113.50"]
        self.assertFalse(scanner["is_attack_pattern"])
        self.assertLessEqual(scanner["confidence"], 0.4)
        self.assertEqual(scanner["tactics"], ["TA0043"])
        self.assertNotIn("203.0.113.50", report["honeypot"]["targets"])

        chain = actors["198.51.100.42"]
        self.assertTrue(chain["is_attack_pattern"])
        self.assertGreaterEqual(chain["confidence"], 0.8)
        for tactic in ("TA0043", "TA0042", "TA0001", "TA0002", "TA0009", "TA0010"):
            self.assertIn(tactic, chain["tactics"])
        self.assertEqual(
            chain["tactics"],
            sorted(chain["tactics"], key=TACTIC_ORDER.index),
        )
        self.assertNotIn("TA0003", chain["tactics"])
        self.assertNotIn("TA0008", chain["tactics"])
        self.assertIn("198.51.100.42", report["honeypot"]["targets"])
        for phase in chain["phases"]:
            remediation = phase["remediation"]
            self.assertTrue(remediation["preventive"])
            self.assertTrue(remediation["detective"])
            self.assertTrue(remediation["corrective"])
            self.assertTrue(remediation["mitigation_ids"])
            self.assertTrue(all(item.startswith("M") for item in remediation["mitigation_ids"]))

        node = actors["203.0.113.105"]
        self.assertTrue(node["is_attack_pattern"])
        self.assertTrue(node["follow_up"])
        self.assertIn("TA0002", node["tactics"])
        self.assertIn("TA0009", node["tactics"])
        self.assertLess(node["confidence"], chain["confidence"])
        finding = next(item for item in report["findings"] if item["cve_id"] == "CVE-2024-27980")
        self.assertEqual(finding["severity"], "critical")
        self.assertTrue(finding["follow_up"])
        self.assertTrue(any("/admin/config" in line for line in finding["evidence"]))


class HoneypotTests(unittest.TestCase):
    def test_decoy_never_executes_input(self):
        import honeypot
        from honeypot import DecoyService

        source = Path(honeypot.__file__).read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)

        marker = "UNIQUE_CANARY_OUTPUT_987"
        touched = ROOT / "sentinel-gnome-decoy-test"
        if touched.exists():
            touched.unlink()
        response = DecoyService().handle(
            {
                "method": "POST",
                "path": "/php-cgi/php-cgi.exe",
                "body": f"echo {marker}; touch {touched}",
            }
        )
        self.assertFalse(response["executed"])
        self.assertFalse(response["outbound"])
        self.assertNotIn(marker, response["body"])
        self.assertNotIn("honeypot", response["body"].lower())
        self.assertFalse(touched.exists())

    def test_redirect_is_text_and_replay_keeps_the_session(self):
        from agent import run_hunt

        inventory, logs = load_inputs()
        report = run_hunt("", inventory, logs)
        policy = report["honeypot"]["policy"]
        self.assertTrue(report["honeypot"]["simulated"])
        self.assertFalse(report["honeypot"]["executed"])
        self.assertIn("iptables", policy)
        self.assertIn("proxy_pass", policy)
        self.assertIn("198.51.100.42", policy)
        self.assertIn("203.0.113.105", policy)
        self.assertNotIn("203.0.113.50", policy)
        self.assertIn("does not apply", policy)

        session = next(
            item
            for item in report["honeypot"]["sessions"]
            if item["actor"] == "198.51.100.42"
        )
        self.assertGreaterEqual(len(session["transcript"]), 6)
        self.assertTrue(all(entry["executed"] is False for entry in session["transcript"]))
        self.assertTrue(all(entry["outbound"] is False for entry in session["transcript"]))
        self.assertTrue(
            all("honeypot" not in (entry.get("response_body") or "").lower() for entry in session["transcript"])
        )
        self.assertTrue(
            any("CANARY-DEMO-NOT-A-SECRET" in entry["response_body"] for entry in session["transcript"])
        )
        analysis = next(
            item
            for item in report["honeypot"]["analysis"]
            if item["actor"] == "198.51.100.42"
        )
        self.assertEqual(len(analysis["phases"]), len(session["transcript"]))
        self.assertTrue(all(phase["executed"] is False for phase in analysis["phases"]))


if __name__ == "__main__":
    unittest.main()
