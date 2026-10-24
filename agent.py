"""Deterministic hunt agent for Sentinel Gnome.

``run_hunt`` returns a strict JSON object. ``RESPONSE_FORMAT`` documents that
contract for callers that expect ``response_format={"type": "json_object"}``.
"""

from __future__ import annotations

import re
from typing import Any

RESPONSE_FORMAT = {"type": "json_object"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
CONSTRAINT_RE = re.compile(r"(<=|>=|<|>|==)\s*(\d+(?:\.\d+)*)")
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
MITRE_BY_CVE = {
    "CVE-2026-21443": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "mitre_mitigation_id": "M1051",
    },
    "CVE-2024-4577": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "mitre_mitigation_id": "M1051",
    },
    "CVE-2024-27980": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "mitre_mitigation_id": "M1051",
    },
}
PUBLIC_EXPLOIT = {
    "tactic": "Initial Access",
    "technique_id": "T1190",
    "technique_name": "Exploit Public-Facing Application",
    "mitre_mitigation_id": "M1051",
}
SCANNING = {
    "tactic": "Reconnaissance",
    "technique_id": "T1595",
    "technique_name": "Active Scanning",
    "mitre_mitigation_id": "M1056",
}
EMPTY_MITRE = {
    "tactic": None,
    "technique_id": None,
    "technique_name": None,
    "mitre_mitigation_id": None,
}


def run_hunt(advisory: str, inventory: list[dict[str, Any]], logs: str) -> dict[str, Any]:
    """Run the Sentinel Gnome cycle and return the strict demo JSON object."""
    advisory = advisory or ""
    inventory = list(inventory or [])
    logs = logs or ""

    intel = extract_threat_intel(advisory)
    affected_hosts = assess_hosts(intel, inventory)
    evidence = hunt_logs(intel["iocs"], logs)
    return {
        "cve_id": intel["cve_id"],
        "affected_software": intel["affected_software"],
        "vulnerable_versions": intel["vulnerable_versions"],
        "iocs": intel["iocs"],
        "is_system_vulnerable": bool(affected_hosts),
        "affected_hosts": affected_hosts,
        "threat_detected_in_logs": bool(evidence),
        "detected_log_evidence": evidence,
        "mitre_attack": map_mitre(intel),
        "remediation_script": build_remediation(intel),
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


def assess_hosts(intel: dict[str, Any], inventory: list[dict[str, Any]]) -> list[str]:
    software = intel.get("affected_software")
    constraint = parse_constraint(intel.get("vulnerable_versions"))
    if not software or constraint is None:
        return []

    operator, bound = constraint
    hosts: list[str] = []
    for asset in inventory:
        if str(asset.get("status") or "Active").casefold() != "active":
            continue
        installed = asset.get("software")
        version = str(asset.get("version") or "")
        hostname = asset.get("hostname")
        if not isinstance(installed, str) or not hostname:
            continue
        if not software_matches(software, installed):
            continue
        if version_matches(version, operator, bound):
            hosts.append(str(hostname))
    return hosts


def hunt_logs(iocs: list[str], logs: str) -> list[str]:
    evidence: list[str] = []
    for line in logs.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if any(ioc_in_line(ioc, line) for ioc in iocs):
            evidence.append(line)
    return evidence


def map_mitre(intel: dict[str, Any]) -> dict[str, str | None]:
    cve_id = intel.get("cve_id")
    if cve_id in MITRE_BY_CVE:
        return dict(MITRE_BY_CVE[cve_id])
    if cve_id:
        return dict(PUBLIC_EXPLOIT)
    if intel.get("iocs"):
        return dict(SCANNING)
    return dict(EMPTY_MITRE)


def build_remediation(intel: dict[str, Any]) -> str:
    cve_id = intel.get("cve_id") or "UNKNOWN-CVE"
    software = intel.get("affected_software")
    fixed_version = intel.get("fixed_version")
    lines = [
        "#!/bin/bash",
        f"# Defensive mitigation for {cve_id}. Review before running.",
        "# Sentinel Gnome does not execute this script.",
        "set -euo pipefail",
    ]
    if software and fixed_version:
        lines.append(f'echo "Upgrade {software} to {fixed_version}"')
        lines.append(f'apt-get install -y "{software}={fixed_version}*"')
    else:
        lines.append('echo "Fixed version was not identified; no upgrade command generated."')
    for ioc in intel.get("iocs") or []:
        if IPV4_RE.fullmatch(ioc):
            lines.append(f'echo "Block IoC {ioc}"')
            lines.append(f"ufw deny from {ioc} to any")
    return "\n".join(lines) + "\n"


def simulate_script(script: str) -> str:
    """Return a dry-run transcript. This function never executes commands."""
    lines = ["Simulación de remediación. Ningún comando se ejecutó."]
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(f"[simulado] {stripped}")
    return "\n".join(lines) + "\n"


def parse_constraint(text: str | None) -> tuple[str, tuple[int, ...]] | None:
    if not text:
        return None
    match = CONSTRAINT_RE.search(text)
    if match is None:
        return None
    return match.group(1), version_tuple(match.group(2))


def version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts) or (0,)


def version_matches(version: str, operator: str, bound: tuple[int, ...]) -> bool:
    compared = compare_versions(version_tuple(version), bound)
    if operator == "<=":
        return compared <= 0
    if operator == "<":
        return compared < 0
    if operator == ">=":
        return compared >= 0
    if operator == ">":
        return compared > 0
    return compared == 0


def compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def software_matches(affected: str, installed: str) -> bool:
    left = affected.casefold().strip()
    right = installed.casefold().strip()
    if not left or not right:
        return False
    return left in right or right in left


def ioc_in_line(ioc: str, line: str) -> bool:
    if IPV4_RE.fullmatch(ioc):
        return re.search(rf"(?<!\d){re.escape(ioc)}(?!\d)", line) is not None
    return ioc in line
