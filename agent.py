"""Deterministic hunt agent for Sentinel Gnome.

``run_hunt`` keeps the original keys and adds severity, findings, kill-chain
correlation, and a simulated honeypot decision. Nothing in this module is executed.
"""

from __future__ import annotations

import re
from typing import Any

from catalog import CVE_RULES, EMPTY_MITRE, PUBLIC_EXPLOIT, SCANNING, SEVERITY_RANK
from detect import parse_logs
from honeypot import build_honeypot
from killchain import correlate_events
from remediate import (
    build_plan,
    classify_cve,
    constraint_hosts,
    controls_for_phase,
    software_matches,
)
from report import SIGNOFF_ITEMS, generate_report, generate_report_html

RESPONSE_FORMAT = {"type": "json_object"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
IOC_LINE_RE = re.compile(
    r"^IoC\s+(IP|User-Agent|Domain|SHA256|Path|Header):\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
LABELED_VALUE_RE = {
    "cve": re.compile(r"^CVE:\s*(CVE-\d{4}-\d{4,})\s*$", re.IGNORECASE | re.MULTILINE),
    "software": re.compile(r"^Software:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE),
    "vulnerable_versions": re.compile(
        r"^Vulnerable versions:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE
    ),
    "fixed_version": re.compile(
        r"^Fixed version:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE
    ),
}
FOLLOW_UP_SIGNATURES = {"php_cgi_injection", "node_spawn_injection", "shell_execution"}


def run_hunt(advisory: str, inventory: list[dict[str, Any]], logs: str) -> dict[str, Any]:
    """Run the local hunt. Remediation text and honeypot policy are not applied."""
    advisory = advisory or ""
    inventory = list(inventory or [])
    logs = logs or ""

    intel = extract_threat_intel(advisory)
    events = [event for event in parse_logs(logs) if _event_in_scope(event, intel)]
    findings = _apply_follow_up(_build_findings(events, inventory), events)
    assessments = _with_controls(correlate_events(events), inventory)
    evidence = _evidence(logs, events, intel)
    cve_id = _resolved_cve(intel, findings)
    hosts = _affected_hostnames(intel, inventory, findings)
    cve_ids = _cve_ids(intel, findings)
    script, corrections = build_plan(cve_ids, assessments, inventory, intel)
    honeypot = build_honeypot(assessments)
    if honeypot["engaged"]:
        corrections.append(
            {
                "id": "review-honeypot-policy",
                "summary": (
                    "Review the simulated honeypot redirect policy. "
                    "Do not apply it until the decoy is isolated."
                ),
                "status": "pending",
            }
        )
    _attach_finding_remediation(findings, script)
    return {
        "cve_id": cve_id,
        "affected_software": _resolved_software(intel, cve_id),
        "vulnerable_versions": _resolved_versions(intel, cve_id),
        "iocs": _resolved_iocs(intel, events),
        "is_system_vulnerable": bool(hosts),
        "affected_hosts": hosts,
        "threat_detected_in_logs": bool(evidence),
        "detected_log_evidence": evidence,
        "mitre_attack": _resolved_mitre(intel, cve_id, findings),
        "remediation_script": script,
        "severity": _max_severity([item["severity"] for item in findings]),
        "findings": findings,
        "corrections": corrections,
        "signoff": [dict(item, status="pending") for item in SIGNOFF_ITEMS],
        "cve_note": CVE_RULES[cve_id].note if cve_id in CVE_RULES else None,
        "alerts": [item for item in assessments if not item["is_attack_pattern"]],
        "attack_patterns": [item for item in assessments if item["is_attack_pattern"]],
        "kill_chain": assessments,
        "honeypot": honeypot,
    }


def extract_threat_intel(advisory: str) -> dict[str, Any]:
    cve_match = LABELED_VALUE_RE["cve"].search(advisory) or CVE_RE.search(advisory)
    software_match = LABELED_VALUE_RE["software"].search(advisory)
    versions_match = LABELED_VALUE_RE["vulnerable_versions"].search(advisory)
    fixed_match = LABELED_VALUE_RE["fixed_version"].search(advisory)
    return {
        "cve_id": cve_match.group(1).upper() if cve_match else None,
        "affected_software": software_match.group(1) if software_match else None,
        "vulnerable_versions": versions_match.group(1) if versions_match else None,
        "fixed_version": fixed_match.group(1) if fixed_match else None,
        "iocs": extract_iocs(advisory),
    }


def extract_iocs(advisory: str) -> list[str]:
    iocs: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            return
        seen.add(cleaned)
        iocs.append(cleaned)

    for match in IOC_LINE_RE.finditer(advisory):
        add(match.group(2))
    for match in IPV4_RE.finditer(advisory):
        add(match.group(0))
    return iocs


def map_mitre(intel: dict[str, Any]) -> dict[str, str | None]:
    cve_id = intel.get("cve_id")
    if cve_id in CVE_RULES:
        return dict(CVE_RULES[cve_id].mitre)
    if cve_id:
        return dict(PUBLIC_EXPLOIT)
    if intel.get("iocs"):
        return dict(SCANNING)
    return dict(EMPTY_MITRE)


def simulate_script(script: str) -> str:
    """Return a dry-run transcript. This function never executes commands."""
    lines = ["Simulación de remediación. Ningún comando se ejecutó."]
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(f"[simulado] {stripped}")
    return "\n".join(lines) + "\n"


def _build_findings(
    events: list[dict[str, Any]], inventory: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for event in events:
        key = str(event["signature_id"])
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(event)
    findings: list[dict[str, Any]] = []
    for key in order:
        bucket = grouped[key]
        first = bucket[0]
        cve_id = first.get("cve_id")
        rule = CVE_RULES.get(cve_id) if cve_id else None
        vulnerable, excluded = classify_cve(cve_id, inventory) if rule else ([], [])
        findings.append(
            {
                "id": key,
                "title": first["title"],
                "cve_id": cve_id,
                "cve_note": rule.note if rule else first.get("cve_note"),
                "demo": bool(rule and rule.demo),
                "severity": _initial_severity(first, bucket),
                "base_severity": first.get("base_severity"),
                "follow_up": False,
                "attacker_ips": _unique(str(item["ip"]) for item in bucket),
                "timestamps": [str(item["timestamp"]) for item in bucket],
                "evidence": [str(item["text"]) for item in bucket],
                "software": first.get("software"),
                "affected_hosts": vulnerable,
                "platform_excluded": excluded,
                "mitre_attack": dict(rule.mitre) if rule else _technique_mitre(first),
                "tactic_id": first.get("tactic_id"),
                "remediation": "",
            }
        )
    return findings


def _apply_follow_up(
    findings: list[dict[str, Any]], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    admin = [event for event in events if event.get("signature_id") == "admin_collection"]
    for finding in findings:
        if finding["id"] not in FOLLOW_UP_SIGNATURES:
            continue
        ips = set(finding["attacker_ips"])
        for event in admin:
            if event["ip"] not in ips:
                continue
            if event["text"] not in finding["evidence"]:
                finding["evidence"].append(event["text"])
            finding["follow_up"] = True
            finding["severity"] = "critical"
    return findings


def _with_controls(
    assessments: list[dict[str, Any]], inventory: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    annotated: list[dict[str, Any]] = []
    for assessment in assessments:
        phases = []
        for phase in assessment["phases"]:
            updated = dict(phase)
            updated["remediation"] = controls_for_phase(
                phase, inventory, str(assessment.get("ip") or "")
            )
            phases.append(updated)
        annotated.append({**assessment, "phases": phases})
    return annotated


def _event_in_scope(event: dict[str, Any], intel: dict[str, Any]) -> bool:
    if _advisory_empty(intel):
        return True
    if intel.get("cve_id") and event.get("cve_id") == intel["cve_id"]:
        return True
    software = event.get("software")
    if intel.get("affected_software") and isinstance(software, str):
        if software_matches(str(intel["affected_software"]), software):
            return True
    return any(ioc_in_line(ioc, str(event.get("text") or "")) for ioc in intel.get("iocs") or [])


def _advisory_empty(intel: dict[str, Any]) -> bool:
    return not any(
        [
            intel.get("cve_id"),
            intel.get("affected_software"),
            intel.get("vulnerable_versions"),
            intel.get("fixed_version"),
            intel.get("iocs"),
        ]
    )


def _evidence(logs: str, events: list[dict[str, Any]], intel: dict[str, Any]) -> list[str]:
    wanted = {str(event["text"]) for event in events}
    wanted.update(hunt_logs(intel.get("iocs") or [], logs))
    evidence: list[str] = []
    for line in logs.splitlines():
        if line in wanted and line not in evidence:
            evidence.append(line)
    return evidence


def hunt_logs(iocs: list[str], logs: str) -> list[str]:
    evidence: list[str] = []
    for line in logs.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if any(ioc_in_line(ioc, line) for ioc in iocs):
            evidence.append(line)
    return evidence


def ioc_in_line(ioc: str, line: str) -> bool:
    if IPV4_RE.fullmatch(ioc):
        return re.search(rf"(?<!\d){re.escape(ioc)}(?!\d)", line) is not None
    return ioc in line


def _affected_hostnames(
    intel: dict[str, Any],
    inventory: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[str]:
    selected: list[str] = []
    if intel.get("cve_id") in CVE_RULES:
        vulnerable, _excluded = classify_cve(str(intel["cve_id"]), inventory)
        selected.extend(str(item["hostname"]) for item in vulnerable)
    elif intel.get("cve_id"):
        selected.extend(str(item["hostname"]) for item in constraint_hosts(intel, inventory))
    else:
        for finding in findings:
            for host in finding.get("affected_hosts") or []:
                selected.append(str(host["hostname"]))
    return _order_hosts(inventory, selected)


def _order_hosts(inventory: list[dict[str, Any]], hostnames: list[str]) -> list[str]:
    wanted = set(hostnames)
    ordered: list[str] = []
    for asset in inventory:
        hostname = str(asset.get("hostname") or "")
        if hostname in wanted and hostname not in ordered:
            ordered.append(hostname)
    for hostname in hostnames:
        if hostname not in ordered:
            ordered.append(hostname)
    return ordered


def _cve_ids(intel: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    if intel.get("cve_id"):
        return [str(intel["cve_id"])]
    return _unique(str(item["cve_id"]) for item in findings if item.get("cve_id"))


def _resolved_cve(intel: dict[str, Any], findings: list[dict[str, Any]]) -> str | None:
    if intel.get("cve_id"):
        return str(intel["cve_id"])
    found = _unique(str(item["cve_id"]) for item in findings if item.get("cve_id"))
    if len(found) == 1:
        return found[0]
    return None


def _resolved_software(intel: dict[str, Any], cve_id: str | None) -> str | None:
    if intel.get("affected_software"):
        return str(intel["affected_software"])
    if cve_id in CVE_RULES:
        return CVE_RULES[cve_id].software
    return None


def _resolved_versions(intel: dict[str, Any], cve_id: str | None) -> str | None:
    if intel.get("vulnerable_versions"):
        return str(intel["vulnerable_versions"])
    if cve_id in CVE_RULES:
        return CVE_RULES[cve_id].vulnerable_text
    return None


def _resolved_iocs(intel: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    if intel.get("iocs"):
        return list(intel["iocs"])
    iocs = _unique(str(event["ip"]) for event in events)
    for event in events:
        indicator = event.get("indicator")
        if indicator and indicator not in iocs:
            iocs.append(str(indicator))
    return iocs


def _resolved_mitre(
    intel: dict[str, Any], cve_id: str | None, findings: list[dict[str, Any]]
) -> dict[str, str | None]:
    if intel.get("cve_id"):
        return map_mitre(intel)
    if cve_id in CVE_RULES:
        return dict(CVE_RULES[cve_id].mitre)
    if intel.get("iocs"):
        return dict(SCANNING)
    if findings:
        best = max(findings, key=lambda item: SEVERITY_RANK.get(str(item["severity"]), 0))
        return dict(best["mitre_attack"])
    return dict(EMPTY_MITRE)


def _initial_severity(first: dict[str, Any], events: list[dict[str, Any]]) -> str:
    if first.get("kind") == "exploit" and any(event.get("status") == "200" for event in events):
        return "critical"
    return str(first.get("base_severity") or "low")


def _technique_mitre(event: dict[str, Any]) -> dict[str, str | None]:
    return {
        "tactic": event.get("tactic_name"),
        "technique_id": event.get("technique_id"),
        "technique_name": event.get("technique_name"),
        "mitre_mitigation_id": "M1031",
    }


def _attach_finding_remediation(findings: list[dict[str, Any]], script: str) -> None:
    for finding in findings:
        cve_id = finding.get("cve_id") or "none"
        chunks = []
        for host in finding.get("affected_hosts") or []:
            marker = f"##### host={host['hostname']} "
            start = script.find(marker)
            if start < 0:
                continue
            end = script.find("\n##### ", start + 1)
            chunks.append(script[start:] if end < 0 else script[start:end])
        if not chunks and cve_id in script:
            chunks.append(script)
        finding["remediation"] = "\n".join(chunks).strip()


def _max_severity(values: list[str]) -> str | None:
    ranked = [value for value in values if value in SEVERITY_RANK]
    if not ranked:
        return None
    return max(ranked, key=lambda value: SEVERITY_RANK[value])


def _unique(values: Any) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


__all__ = [
    "RESPONSE_FORMAT",
    "extract_iocs",
    "extract_threat_intel",
    "generate_report",
    "generate_report_html",
    "map_mitre",
    "run_hunt",
    "simulate_script",
]
