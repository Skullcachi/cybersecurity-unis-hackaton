"""Presentation of a Sentinel Gnome hunt report.

``hunt_report`` reads the strict JSON from ``run_hunt``. It does not hunt again.
"""

from __future__ import annotations

from typing import Any

VERDICTS = {
    "attack_completed": (
        "error",
        "Ataque ejecutado por completo en {hosts}. "
        "El parche no se aplicó y el sistema sigue vulnerable.",
    ),
    "patched_after_detection": (
        "success",
        "Sentinel Gnome identificó el intento, parchó el host "
        "y el sistema ya no cae en el rango vulnerable.",
    ),
    "patched_from_advisory": (
        "success",
        "Sentinel Gnome leyó el advisory y aplicó el parche "
        "antes de cualquier intento de ataque.",
    ),
}


def hunt_report(report: dict[str, Any]) -> dict[str, Any]:
    hosts = list(report.get("affected_hosts") or [])
    outcome = report.get("response_outcome")
    level, verdict = _verdict(report, hosts, outcome)
    mitre = report.get("mitre_attack") or {}
    return {
        "title": "Reporte de caza",
        "cve_id": report.get("cve_id") or "—",
        "affected_software": report.get("affected_software") or "—",
        "vulnerable_versions": report.get("vulnerable_versions") or "—",
        "outcome": outcome,
        "level": level,
        "verdict": verdict,
        "threat_detected": bool(report.get("threat_detected_in_logs")),
        "affected_hosts": hosts,
        "iocs": list(report.get("iocs") or []),
        "evidence": list(report.get("detected_log_evidence") or []),
        "action": list(report.get("response_evidence") or []),
        "mitre": {
            "tactic": mitre.get("tactic"),
            "technique_id": mitre.get("technique_id"),
            "technique_name": mitre.get("technique_name"),
            "mitre_mitigation_id": mitre.get("mitre_mitigation_id"),
        },
        "remediation_script": report.get("remediation_script") or "",
    }


def _verdict(
    report: dict[str, Any], hosts: list[str], outcome: str | None
) -> tuple[str, str]:
    known = VERDICTS.get(outcome or "")
    if known is not None:
        level, template = known
        host_text = ", ".join(hosts) or "el host afectado"
        return level, template.format(hosts=host_text)
    if report.get("is_system_vulnerable"):
        host_text = ", ".join(hosts) or "sin hostname"
        return "error", f"SISTEMA VULNERABLE: {host_text}"
    return (
        "success",
        "SISTEMA SEGURO: ningún activo activo cae en el rango vulnerable.",
    )
