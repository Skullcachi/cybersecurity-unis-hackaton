"""CVE facts, version rules, and ATT&CK tactic order for Sentinel Gnome.

CVE-2024-4577 and CVE-2024-27980 are matched per release branch. A single
comparison such as ``< 8.2.20`` is not used for PHP, because 8.1.29, 8.2.20,
and 8.3.8 are separate fix points. CVE-2026-21443 is not an nginx flaw; see
``DEMO_NGINX_NOTE``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

CONSTRAINT_RE = re.compile(r"(<=|>=|<|>|==)\s*(\d+(?:\.\d+)*)")

DEMO_NGINX_NOTE = (
    "Demo identifier only. The authoritative CVE-2026-21443 record is an OpenEMR "
    "XSS issue (unescaped xl() output, fixed in OpenEMR 8.0.0), not an nginx "
    "vulnerability. This lab reuses the id for a fictional nginx scanner scenario. "
    "The range <= 1.24.0 and the fixed build 1.26.2 are scenario data, not the OpenEMR advisory."
)

PHP_NOTE = (
    "CVE-2024-4577 is argument injection in PHP-CGI on Windows. Windows Best-Fit "
    "maps a soft hyphen (0xAD) to '-'. Affected branches are 8.1.x before 8.1.29, "
    "8.2.x before 8.2.20, and 8.3.x before 8.3.8. Linux builds are not affected."
)

NODE_NOTE = (
    "CVE-2024-27980 is a Windows command injection in child_process.spawn and "
    "child_process.spawnSync when a .bat or .cmd file is spawned without shell:true. "
    "It is not HTTP request smuggling. Fixed in Node.js 18.20.2, 20.12.2, and 21.7.3. "
    "The initial fix was incomplete (CVE-2024-36138); Node.js 20.x should move to "
    "20.15.1 or later."
)

HEADER_NOTE = (
    "Malformed Transfer-Encoding or an embedded internal Host header is suspicious "
    "HTTP parser abuse. It is not evidence of CVE-2024-27980."
)

PHP_FIXES: dict[tuple[int, int], tuple[int, ...]] = {
    (8, 1): (8, 1, 29),
    (8, 2): (8, 2, 20),
    (8, 3): (8, 3, 8),
}

NODE_FIXES: dict[int, tuple[int, ...]] = {
    18: (18, 20, 2),
    20: (20, 12, 2),
    21: (21, 7, 3),
}

NGINX_DEMO_FIXED = (1, 26, 2)
NGINX_DEMO_VULNERABLE_THROUGH = (1, 24, 0)

# Enterprise tactic order used for plausible kill-chain checks.
# Reconnaissance and Resource Development may swap with each other.
TACTIC_ORDER: tuple[str, ...] = (
    "TA0043",
    "TA0042",
    "TA0001",
    "TA0002",
    "TA0003",
    "TA0004",
    "TA0005",
    "TA0006",
    "TA0007",
    "TA0008",
    "TA0009",
    "TA0011",
    "TA0010",
    "TA0040",
)

TACTIC_NAMES: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

TECHNIQUE_NAMES: dict[str, str] = {
    "T1595": "Active Scanning",
    "T1608": "Stage Capabilities",
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1005": "Data from Local System",
    "T1041": "Exfiltration Over C2 Channel",
}

MITIGATION_NAMES: dict[str, str] = {
    "M1051": "Update Software",
    "M1056": "Pre-compromise",
    "M1037": "Filter Network Traffic",
    "M1031": "Network Intrusion Prevention",
    "M1021": "Restrict Web-Based Content",
    "M1042": "Disable or Remove Feature or Program",
    "M1038": "Execution Prevention",
    "M1035": "Limit Access to Resource Over Network",
    "M1030": "Network Segmentation",
    "M1040": "Behavior Prevention on Endpoint",
    "M1022": "Restrict File and Directory Permissions",
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

SESSION_GAP_SECONDS = 30 * 60
ATTACK_PATTERN_MIN_TACTICS = 2
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class CveRule:
    cve_id: str
    software: str
    platform: str
    note: str
    demo: bool
    vulnerable_text: str
    mitre: dict[str, str | None]
    is_vulnerable: Callable[[str], bool]
    fixed_version: Callable[[str], str | None]


def version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version or "")
    return tuple(int(part) for part in parts)


def format_version(parts: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in parts)


def has_version(version: str) -> bool:
    return bool(re.search(r"\d", version or ""))


def compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right), 1)
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def version_matches(version: str, operator: str, bound: tuple[int, ...]) -> bool:
    if not has_version(version):
        return False
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


def parse_constraint(text: str | None) -> tuple[str, tuple[int, ...]] | None:
    if not text:
        return None
    match = CONSTRAINT_RE.search(text)
    if match is None:
        return None
    return match.group(1), version_tuple(match.group(2))


def php_fixed_version(version: str) -> str | None:
    parsed = version_tuple(version)
    if len(parsed) < 2:
        return None
    fixed = PHP_FIXES.get((parsed[0], parsed[1]))
    if fixed is None:
        return None
    return format_version(fixed)


def php_vulnerable(version: str) -> bool:
    fixed = php_fixed_version(version)
    if fixed is None:
        return False
    return compare_versions(version_tuple(version), version_tuple(fixed)) < 0


def node_fixed_version(version: str) -> str | None:
    parsed = version_tuple(version)
    if not parsed:
        return None
    fixed = NODE_FIXES.get(parsed[0])
    if fixed is None:
        return None
    return format_version(fixed)


def node_vulnerable(version: str) -> bool:
    fixed = node_fixed_version(version)
    if fixed is None:
        return False
    return compare_versions(version_tuple(version), version_tuple(fixed)) < 0


def nginx_demo_fixed_version(version: str) -> str | None:
    if not has_version(version):
        return None
    return format_version(NGINX_DEMO_FIXED)


def nginx_demo_vulnerable(version: str) -> bool:
    if not has_version(version):
        return False
    return compare_versions(version_tuple(version), NGINX_DEMO_VULNERABLE_THROUGH) <= 0


def _mitre(tactic: str, technique_id: str, mitigation_id: str) -> dict[str, str | None]:
    return {
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": TECHNIQUE_NAMES[technique_id],
        "mitre_mitigation_id": mitigation_id,
    }


CVE_RULES: dict[str, CveRule] = {
    "CVE-2024-4577": CveRule(
        cve_id="CVE-2024-4577",
        software="PHP",
        platform="windows",
        note=PHP_NOTE,
        demo=False,
        vulnerable_text="8.1.x < 8.1.29; 8.2.x < 8.2.20; 8.3.x < 8.3.8",
        mitre=_mitre("Initial Access", "T1190", "M1051"),
        is_vulnerable=php_vulnerable,
        fixed_version=php_fixed_version,
    ),
    "CVE-2024-27980": CveRule(
        cve_id="CVE-2024-27980",
        software="Node.js",
        platform="windows",
        note=NODE_NOTE,
        demo=False,
        vulnerable_text="18.x < 18.20.2; 20.x < 20.12.2; 21.x < 21.7.3",
        mitre=_mitre("Execution", "T1059", "M1051"),
        is_vulnerable=node_vulnerable,
        fixed_version=node_fixed_version,
    ),
    "CVE-2026-21443": CveRule(
        cve_id="CVE-2026-21443",
        software="nginx",
        platform="linux",
        note=DEMO_NGINX_NOTE,
        demo=True,
        vulnerable_text="<= 1.24.0",
        mitre=_mitre("Initial Access", "T1190", "M1051"),
        is_vulnerable=nginx_demo_vulnerable,
        fixed_version=nginx_demo_fixed_version,
    ),
}
