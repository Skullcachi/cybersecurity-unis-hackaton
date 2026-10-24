"""Local decoy used only to replay log lines.

Responses are static. Payloads are stored as text. This module does not open
sockets, apply firewall rules, or run attacker input. A production honeypot
would also need an isolated host, an authorization and retention policy,
egress denial, and monitoring. None of that is performed here.
"""

from __future__ import annotations

from typing import Any

DECOY_ADDRESS = "127.0.0.1:8089"
CANARY_TOKEN = "CANARY-DEMO-NOT-A-SECRET"
ADMIN_BODY = f"service=admin\nbuild=4.2.0\nadmin_token={CANARY_TOKEN}\n"
GENERIC_BODY = "ok\n"
CGI_BODY = "status=accepted\n"
SINK_BODY = "accepted\n"


class DecoyService:
    """Fake service. ``handle`` never runs the request body."""

    def handle(self, request: dict[str, str]) -> dict[str, Any]:
        path = (request.get("path") or "") + " " + (request.get("body") or "")
        lowered = path.lower()
        if "admin/config" in lowered:
            body = ADMIN_BODY
            canary = True
        elif "php-cgi" in lowered or "cmd.exe" in lowered:
            body = CGI_BODY
            canary = False
        elif "attacker-lab.example" in lowered or "/collect" in lowered:
            body = SINK_BODY
            canary = False
        else:
            body = GENERIC_BODY
            canary = False
        return {
            "status": 200,
            "body": body,
            "executed": False,
            "outbound": False,
            "canary": canary,
        }


def replay_session(assessment: dict[str, Any], decoy: DecoyService | None = None) -> dict[str, Any]:
    """Replay one correlated session against the decoy in log order."""
    service = decoy or DecoyService()
    transcript: list[dict[str, Any]] = []
    for phase in assessment.get("phases") or []:
        request = {
            "method": str(phase.get("method") or ""),
            "path": str(phase.get("path") or ""),
            "body": str(phase.get("payload") or ""),
        }
        response = service.handle(request)
        transcript.append(
            {
                "timestamp": phase.get("timestamp"),
                "method": request["method"],
                "path": request["path"],
                "payload": request["body"],
                "tactic_id": phase.get("tactic_id"),
                "technique_id": phase.get("technique_id"),
                "response_status": response["status"],
                "response_body": response["body"],
                "executed": response["executed"],
                "outbound": response["outbound"],
                "canary": response["canary"],
            }
        )
    return {
        "actor": assessment.get("actor"),
        "ip": assessment.get("ip"),
        "confidence": assessment.get("confidence"),
        "simulated": True,
        "executed": False,
        "outbound": False,
        "transcript": transcript,
    }


def render_redirect_policy(targets: list[str]) -> str:
    """Defender-only policy text. Nothing in this function is applied."""
    if not targets:
        return (
            "# No attack pattern reached the diversion threshold.\n"
            "# Sentinel Gnome does not apply redirect rules.\n"
        )
    lines = [
        "# Simulated redirect policy for the local decoy.",
        "# Sentinel Gnome does not apply or execute these rules.",
        "# The decoy answer does not tell the client that the session was diverted.",
        f"# Decoy listen address: {DECOY_ADDRESS}",
        "",
    ]
    nginx_names = " ".join(targets)
    lines.extend(
        [
            "# nginx",
            "geo $steer_to_decoy {",
            "    default 0;",
        ]
    )
    for ip in targets:
        lines.append(f"    {ip} 1;")
    lines.extend(
        [
            "}",
            "server {",
            "    listen 80;",
            "    if ($steer_to_decoy) {",
            f"        proxy_pass http://{DECOY_ADDRESS};",
            "    }",
            "}",
            "",
            "# iptables local redirect (not applied)",
        ]
    )
    for ip in targets:
        lines.append(
            "iptables -t nat -A PREROUTING "
            f"-s {ip}/32 -p tcp --dport 80 -j REDIRECT --to-ports 8089"
        )
    lines.extend(
        [
            "",
            "# reverse proxy",
            f"# upstream decoy {{ server {DECOY_ADDRESS}; }}",
            f"# clients: {nginx_names}",
            "",
        ]
    )
    return "\n".join(lines)


def build_honeypot(assessments: list[dict[str, Any]]) -> dict[str, Any]:
    patterns = [item for item in assessments if item.get("is_attack_pattern")]
    targets = [str(item["actor"]) for item in patterns]
    sessions = [replay_session(item) for item in patterns]
    return {
        "engaged": bool(targets),
        "simulated": True,
        "executed": False,
        "outbound": False,
        "targets": targets,
        "policy": render_redirect_policy(targets),
        "sessions": sessions,
        "analysis": [_session_analysis(item, session) for item, session in zip(patterns, sessions)],
    }


def _session_analysis(assessment: dict[str, Any], session: dict[str, Any]) -> dict[str, Any]:
    phases = []
    for phase, entry in zip(assessment.get("phases") or [], session.get("transcript") or []):
        phases.append(
            {
                "timestamp": phase.get("timestamp"),
                "tactic_id": phase.get("tactic_id"),
                "tactic_name": phase.get("tactic_name"),
                "technique_id": phase.get("technique_id"),
                "technique_name": phase.get("technique_name"),
                "objective": phase.get("objective"),
                "tooling": phase.get("tooling"),
                "evidence": phase.get("evidence") or [],
                "cve_id": phase.get("cve_id"),
                "confidence": assessment.get("confidence"),
                "decoy_status": entry.get("response_status"),
                "executed": False,
            }
        )
    return {
        "actor": assessment.get("actor"),
        "confidence": assessment.get("confidence"),
        "reasons": assessment.get("reasons") or [],
        "tooling": assessment.get("tooling") or [],
        "objectives": [phase.get("objective") for phase in assessment.get("phases") or []],
        "phases": phases,
    }
