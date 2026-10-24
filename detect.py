"""Line-level signatures. Correlation across tactics lives in ``killchain``."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from catalog import HEADER_NOTE, TACTIC_NAMES, TECHNIQUE_NAMES

LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<body>.*)$"
)
METHOD_RE = re.compile(r"\b(GET|POST|PUT|DELETE|HEAD)\b", re.IGNORECASE)
STATUS_RE = re.compile(r"\b([1-5]\d{2})\b")
ATTACKER_DOMAIN = "tools.attacker-lab.example"
PROBE_MARKERS = ("php-cgi", "phpinfo.php", "/.env", "robots.txt", "server-status", ".git/")


def parse_logs(logs: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for raw in (logs or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = LINE_RE.match(stripped)
        if match is None:
            continue
        event = classify_line(
            stripped,
            match.group("timestamp"),
            match.group("ip"),
            match.group("body"),
        )
        if event is not None:
            events.append(event)
    return events


def classify_line(text: str, timestamp: str, ip: str, body: str) -> dict[str, Any] | None:
    observation = _observation(text)
    if observation is None:
        return None
    method_match = METHOD_RE.search(body)
    method = method_match.group(1).upper() if method_match else None
    path = _path_after_method(body, method)
    return {
        "timestamp": timestamp,
        "ip": ip,
        "text": text,
        "method": method,
        "path": path,
        "status": _status(text),
        "payload": text,
        **observation,
    }


def _observation(text: str) -> dict[str, Any] | None:
    if _is_php_cgi_injection(text):
        return _event(
            "php_cgi_injection",
            "PHP-CGI argument injection",
            "TA0001",
            "T1190",
            "CVE-2024-4577",
            "PHP",
            "exploit",
            "high",
            "/php-cgi/php-cgi.exe",
        )
    if _is_node_spawn_injection(text):
        return _event(
            "node_spawn_injection",
            "Node.js Windows command injection via child_process.spawn",
            "TA0002",
            "T1059",
            "CVE-2024-27980",
            "Node.js",
            "attempt",
            "high",
            None,
        )
    if _is_shell_execution(text):
        return _event(
            "shell_execution",
            "Command execution via cmd.exe",
            "TA0002",
            "T1059",
            None,
            "PHP",
            "exploit",
            "high",
            "cmd.exe",
        )
    if _is_exfiltration(text):
        return _event(
            "exfiltration",
            "Transfer toward attacker infrastructure",
            "TA0010",
            "T1041",
            None,
            None,
            "exfil",
            "high",
            ATTACKER_DOMAIN,
        )
    if _is_resource_development(text):
        return _event(
            "resource_development",
            "Staged payload on attacker infrastructure",
            "TA0042",
            "T1608",
            None,
            None,
            "stage",
            "medium",
            ATTACKER_DOMAIN,
        )
    if _is_admin_collection(text):
        return _event(
            "admin_collection",
            "Read of administrative configuration",
            "TA0009",
            "T1005",
            None,
            None,
            "collection",
            "high",
            "/admin",
        )
    if _is_header_abuse(text):
        observed = _event(
            "http_header_abuse",
            "Malformed HTTP header abuse",
            "TA0001",
            "T1190",
            None,
            None,
            "suspicious",
            "medium",
            None,
        )
        observed["cve_note"] = HEADER_NOTE
        return observed
    if _is_zd_hunter(text):
        return _event(
            "nginx_scanner",
            "Nginx scanner ZD-Hunter/6.0",
            "TA0043",
            "T1595",
            "CVE-2026-21443",
            "nginx",
            "scan",
            "medium",
            "ZD-Hunter/6.0",
        )
    if _is_recon_probe(text):
        return _event(
            "recon_probe",
            "Service probe",
            "TA0043",
            "T1595",
            None,
            "PHP" if "php" in text.lower() else None,
            "scan",
            "low",
            None,
        )
    return None


def _event(
    signature_id: str,
    title: str,
    tactic_id: str,
    technique_id: str,
    cve_id: str | None,
    software: str | None,
    kind: str,
    base_severity: str,
    indicator: str | None,
) -> dict[str, Any]:
    return {
        "signature_id": signature_id,
        "title": title,
        "tactic_id": tactic_id,
        "tactic_name": TACTIC_NAMES[tactic_id],
        "technique_id": technique_id,
        "technique_name": TECHNIQUE_NAMES[technique_id],
        "cve_id": cve_id,
        "cve_note": None,
        "software": software,
        "kind": kind,
        "base_severity": base_severity,
        "indicator": indicator,
    }


def _is_php_cgi_injection(text: str) -> bool:
    lowered = text.lower()
    if "php-cgi" not in lowered:
        return False
    if "%ad" in lowered or "\xad" in lowered:
        return True
    return "allow_url_include" in unquote(lowered)


def _is_node_spawn_injection(text: str) -> bool:
    lowered = text.lower()
    spawn = "child_process.spawn" in lowered or "spawnsync" in lowered
    batch = ".bat" in lowered or ".cmd" in lowered
    if spawn and batch:
        return True
    return bool(spawn and re.search(r"[&|]", text))


def _is_shell_execution(text: str) -> bool:
    lowered = text.lower()
    return "cmd.exe" in lowered or "powershell.exe" in lowered


def _is_exfiltration(text: str) -> bool:
    lowered = text.lower()
    return ATTACKER_DOMAIN in lowered and "/collect" in lowered


def _is_resource_development(text: str) -> bool:
    lowered = text.lower()
    return ATTACKER_DOMAIN in lowered and "/stage/" in lowered


def _is_admin_collection(text: str) -> bool:
    """Successful read or write of an /admin route, before generic scanner rules."""
    if _status(text) != "200":
        return False
    return re.search(r"/admin(?:/|\b)", text, re.IGNORECASE) is not None


def _is_header_abuse(text: str) -> bool:
    lowered = text.lower()
    if "transfer-encoding" in lowered and ("\\x00" in lowered or "%00" in lowered):
        return True
    return re.search(r'"host\s*:\s*internal', lowered) is not None


def _is_zd_hunter(text: str) -> bool:
    return "ZD-Hunter/6.0" in text


def _is_recon_probe(text: str) -> bool:
    if _status(text) not in {"401", "403", "404"}:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in PROBE_MARKERS)


def _status(text: str) -> str | None:
    codes = STATUS_RE.findall(text)
    return codes[-1] if codes else None


def _path_after_method(body: str, method: str | None) -> str | None:
    if not method:
        return None
    match = re.search(rf"\b{method}\s+(\S+)", body, re.IGNORECASE)
    if match is None:
        return None
    return match.group(1)
