"""OS-aware upgrade text and per-phase controls. Nothing here is executed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from catalog import (
    CVE_RULES,
    MITIGATION_NAMES,
    TACTIC_NAMES,
    compare_versions,
    parse_constraint,
    version_matches,
    version_tuple,
)

PHASE_CONTROLS: dict[str, dict[str, Any]] = {
    "TA0043": {
        "preventive": [
            "Rate-limit probes and reject known scanner user agents at the edge.",
            "Disable public server-status and directory listing.",
        ],
        "detective": [
            "Alert on User-Agent ZD-Hunter/6.0 and on short bursts of 404 discovery probes.",
        ],
        "corrective": [
            "Block the scanning address after confirming it is not a shared proxy.",
        ],
        "mitigation_ids": ["M1037", "M1031", "M1056"],
        "waf": 'if ($http_user_agent ~* "ZD-Hunter/6.0") { return 403; }',
    },
    "TA0042": {
        "preventive": [
            "Deny egress to unapproved domains so a host cannot fetch a staged payload.",
        ],
        "detective": [
            "Alert when a client or host requests tools.attacker-lab.example or another new staging domain.",
        ],
        "corrective": [
            "Block the staging domain and keep the sample for the case record.",
        ],
        "mitigation_ids": ["M1037", "M1031"],
        "waf": 'if ($request_uri ~* "tools\\.attacker-lab\\.example|/stage/") { return 403; }',
    },
    "TA0001": {
        "preventive": [
            "Remove the public PHP-CGI mapping and reject soft-hyphen arguments.",
            "Upgrade PHP on Windows to the fixed build for its branch.",
        ],
        "detective": [
            "Alert on php-cgi.exe queries that contain %AD or allow_url_include.",
        ],
        "corrective": [
            "Disable php-cgi.exe, upgrade PHP, and restart the web server.",
        ],
        "mitigation_ids": ["M1051", "M1021", "M1042"],
        "waf": 'if ($args ~* "(?i)(%ad|allow_url_include)") { return 403; }',
    },
    "TA0002": {
        "preventive": [
            "Upgrade Node.js on Windows and do not spawn .bat or .cmd files without a trusted shell policy.",
            "Block direct use of cmd.exe from the web application account.",
        ],
        "detective": [
            "Alert on child_process.spawn of a batch file and on cmd.exe /c in request logs.",
        ],
        "corrective": [
            "Upgrade the runtime, stop the worker, and review the process lineage.",
        ],
        "mitigation_ids": ["M1051", "M1038", "M1042", "M1040"],
        "waf": "# Detect child_process.spawn of .bat/.cmd and cmd.exe /c in application logs.",
    },
    "TA0009": {
        "preventive": [
            "Require authentication and an allowlist for /admin/config and /admin/session.",
        ],
        "detective": [
            "Alert when an external address receives HTTP 200 from /admin/config or /admin/session.",
        ],
        "corrective": [
            "Restrict the admin route and rotate any canary that was read.",
        ],
        "mitigation_ids": ["M1035", "M1030", "M1022"],
        "waf": "location /admin/ { allow 192.168.1.0/24; deny all; }",
    },
    "TA0010": {
        "preventive": [
            "Block outbound posts to attacker-controlled collection endpoints.",
        ],
        "detective": [
            "Alert on posts to tools.attacker-lab.example/collect.",
        ],
        "corrective": [
            "Block the domain and the source address, then scope what left the host.",
        ],
        "mitigation_ids": ["M1037", "M1031"],
        "waf": 'if ($request_uri ~* "tools\\.attacker-lab\\.example/collect") { return 403; }',
    },
}

DEFAULT_CONTROLS: dict[str, Any] = {
    "preventive": ["Reduce exposure of the service that produced this log line."],
    "detective": ["Alert when this request pattern repeats from the same source."],
    "corrective": ["Contain the source address and preserve the log line."],
    "mitigation_ids": ["M1037", "M1031"],
    "waf": None,
}


@dataclass
class Action:
    id: str
    summary: str
    lines: list[str] = field(default_factory=list)
    host: str | None = None
    os_name: str | None = None
    cve_id: str | None = None


def software_matches(affected: str, installed: str) -> bool:
    left = affected.casefold().strip()
    right = installed.casefold().strip()
    if not left or not right:
        return False
    return left in right or right in left


def host_os(asset: dict[str, Any], fallback: str) -> str:
    raw = str(asset.get("os") or "").strip().lower()
    if raw in {"linux", "windows"}:
        return raw
    if fallback in {"linux", "windows"}:
        return fallback
    return "linux"


def is_active(asset: dict[str, Any]) -> bool:
    return str(asset.get("status") or "Active").casefold() == "active"


def apt_package(software: str, version: str) -> str | None:
    name = software.casefold()
    if "nginx" in name:
        return "nginx"
    if "php" in name:
        parsed = version_tuple(version)
        if len(parsed) >= 2:
            return f"php{parsed[0]}.{parsed[1]}-cgi"
        return "php-cgi"
    if "node" in name:
        return "nodejs"
    return None


def patched_hosts(cve_id: str, inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Hosts on the CVE platform whose installed build already meets the fix."""
    rule = CVE_RULES.get(cve_id)
    if rule is None:
        return []
    hosts: list[dict[str, Any]] = []
    for asset in inventory:
        if not is_active(asset):
            continue
        installed = asset.get("software")
        hostname = str(asset.get("hostname") or "")
        version = str(asset.get("version") or "")
        if not isinstance(installed, str) or not hostname:
            continue
        if not software_matches(rule.software, installed):
            continue
        fixed = rule.fixed_version(version)
        if not fixed or rule.is_vulnerable(version):
            continue
        if compare_versions(version_tuple(version), version_tuple(fixed)) < 0:
            continue
        os_name = host_os(asset, rule.platform)
        if rule.platform != "any" and os_name != rule.platform:
            continue
        hosts.append(_record(asset, os_name, False))
    return hosts


def classify_cve(
    cve_id: str, inventory: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rule = CVE_RULES.get(cve_id)
    if rule is None:
        return [], []
    vulnerable: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for asset in inventory:
        record = _matching_record(asset, rule.software, rule.is_vulnerable, rule.platform)
        if record is None:
            continue
        if record["vulnerable"]:
            vulnerable.append(record)
        else:
            excluded.append(record)
    return vulnerable, excluded


def constraint_hosts(intel: dict[str, Any], inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    software = intel.get("affected_software")
    constraint = parse_constraint(intel.get("vulnerable_versions"))
    if not isinstance(software, str) or constraint is None:
        return []
    operator, bound = constraint
    hosts: list[dict[str, Any]] = []
    for asset in inventory:
        if not is_active(asset):
            continue
        installed = asset.get("software")
        hostname = str(asset.get("hostname") or "")
        version = str(asset.get("version") or "")
        if not isinstance(installed, str) or not hostname:
            continue
        if not software_matches(software, installed):
            continue
        if not version_matches(version, operator, bound):
            continue
        hosts.append(_record(asset, host_os(asset, "linux"), True))
    return hosts


def controls_for_phase(
    phase: dict[str, Any], inventory: list[dict[str, Any]], actor_ip: str
) -> dict[str, Any]:
    template = PHASE_CONTROLS.get(str(phase.get("tactic_id")), DEFAULT_CONTROLS)
    preventive = list(template["preventive"])
    detective = list(template["detective"])
    corrective = list(template["corrective"])
    corrective.append(f"Block {actor_ip} at the perimeter after review.")
    upgrade = _upgrade_text(phase.get("cve_id"), inventory)
    if upgrade:
        preventive.append("Apply the branch-specific version fix for the matched CVE.")
        corrective.append("Upgrade the affected build, then verify the reported version.")
    mitigation_ids = list(template["mitigation_ids"])
    return {
        "preventive": preventive,
        "detective": detective,
        "corrective": corrective,
        "mitigation_ids": mitigation_ids,
        "mitigation_names": [MITIGATION_NAMES.get(item, item) for item in mitigation_ids],
        "waf": template.get("waf"),
        "upgrade": upgrade,
    }


def build_plan(
    cve_ids: list[str],
    actors: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
    intel: dict[str, Any],
    logs: str = "",
) -> tuple[str, list[dict[str, str]]]:
    actions: list[Action] = []
    blocked: set[str] = set()
    covered: set[str] = set()
    for cve_id in cve_ids:
        if cve_id not in CVE_RULES:
            continue
        vulnerable, excluded = classify_cve(cve_id, inventory)
        patched = patched_hosts(cve_id, inventory)
        ips = _ips_for_cve(cve_id, actors, intel)
        follow_up = _cve_follow_up(cve_id, actors)
        for asset in vulnerable:
            actions.extend(_host_actions(asset, cve_id, ips, follow_up, blocked, "vulnerable"))
            covered.add(str(asset["hostname"]))
        for asset in excluded:
            actions.extend(_host_actions(asset, cve_id, ips, follow_up, blocked, "excluded"))
            covered.add(str(asset["hostname"]))
        for asset in patched:
            actions.extend(_host_actions(asset, cve_id, ips, follow_up, blocked, "patched"))
            covered.add(str(asset["hostname"]))
    if intel.get("cve_id") and intel["cve_id"] not in CVE_RULES:
        ips = [ioc for ioc in intel.get("iocs") or [] if _is_ip(ioc)]
        for asset in constraint_hosts(intel, inventory):
            actions.extend(_generic_actions(asset, intel, ips, blocked))
            covered.add(str(asset["hostname"]))
    actions.extend(_recorded_response_actions(logs, inventory, covered))
    actions.extend(_phase_actions(actors))
    actions = _dedup(actions)
    return render_plan(actions), [_correction(action) for action in actions if action.summary]


def render_plan(actions: list[Action]) -> str:
    if not actions:
        return (
            "# Sentinel Gnome remediation plan\n"
            "# No host-specific commands were generated.\n"
            "# Sentinel Gnome does not execute this file.\n"
        )
    linux_only = all((action.os_name or "") == "linux" for action in actions)
    lines: list[str] = []
    if linux_only:
        lines.extend(["#!/bin/bash", "set -euo pipefail"])
    lines.extend(
        [
            "# Sentinel Gnome remediation plan",
            "# Review each host section before use.",
            "# Sentinel Gnome does not execute this file.",
            "",
        ]
    )
    grouped: dict[tuple[str, str, str], list[Action]] = {}
    for action in actions:
        key = (action.host or "unscoped", action.os_name or "unknown", action.cve_id or "none")
        grouped.setdefault(key, []).append(action)
    for (host, os_name, cve_id), group in grouped.items():
        lines.append(f"##### host={host} os={os_name} cve={cve_id}")
        for action in group:
            lines.extend(action.lines)
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _host_actions(
    asset: dict[str, Any],
    cve_id: str,
    ips: list[str],
    follow_up: bool,
    blocked: set[str],
    state: str,
) -> list[Action]:
    hostname = str(asset["hostname"])
    os_name = str(asset["os"])
    rule = CVE_RULES[cve_id]
    version = str(asset["version"])
    fixed = rule.fixed_version(version) or "vendor-fixed"
    applicable = state == "vulnerable"
    if state == "patched":
        summary = f"Confirm {hostname} is already at {fixed}"
        lines = [
            f"# {hostname} is already at {version}, which meets {fixed} for {cve_id}.",
            "# No upgrade command is proposed.",
        ]
    elif applicable:
        summary = f"Upgrade {rule.software} on {hostname} ({os_name}) to {fixed}"
        lines = _upgrade_lines(asset, cve_id, True)
    else:
        summary = f"Record that {cve_id} does not apply to {hostname} ({os_name})"
        lines = _upgrade_lines(asset, cve_id, False)
    actions = [
        Action(
            id=_slug("upgrade", hostname, cve_id, fixed),
            summary=summary,
            lines=lines,
            host=hostname,
            os_name=os_name,
            cve_id=cve_id,
        )
    ]
    if applicable and cve_id == "CVE-2024-4577" and os_name == "windows":
        actions.append(
            Action(
                id=_slug("disable-php-cgi", hostname),
                summary=f"Disable or block php-cgi.exe on {hostname} until PHP is upgraded",
                lines=[
                    "# Temporary mitigation: stop exposing php-cgi.exe.",
                    "# Remove the Apache ScriptAlias for /php-cgi/ and deny execute on php-cgi.exe.",
                    "# Reject soft-hyphen queries until PHP is upgraded:",
                    "# RewriteCond %{QUERY_STRING} %ad [NC]",
                    "# RewriteRule ^ - [F,L]",
                ],
                host=hostname,
                os_name=os_name,
                cve_id=cve_id,
            )
        )
    if follow_up:
        actions.append(
            Action(
                id=_slug("restrict-admin", hostname),
                summary=f"Restrict /admin/config on {hostname}",
                lines=[
                    "# Temporary mitigation: restrict /admin/config to an admin allowlist.",
                    "# Do not leave this route reachable from the attacker address.",
                ],
                host=hostname,
                os_name=os_name,
                cve_id=cve_id,
            )
        )
    for ip in ips:
        if ip in blocked:
            continue
        blocked.add(ip)
        actions.append(_block_action(hostname, os_name, cve_id, ip))
    actions.append(
        Action(
            id=_slug("verify", hostname, cve_id),
            summary=f"Verify the fix on {hostname}",
            lines=[_verify_command(rule.software)],
            host=hostname,
            os_name=os_name,
            cve_id=cve_id,
        )
    )
    return actions


def _generic_actions(
    asset: dict[str, Any],
    intel: dict[str, Any],
    ips: list[str],
    blocked: set[str],
) -> list[Action]:
    hostname = str(asset["hostname"])
    os_name = str(asset["os"])
    software = str(asset.get("software") or "software")
    fixed = str(intel.get("fixed_version") or "the vendor fixed build")
    cve_id = str(intel.get("cve_id") or "UNKNOWN-CVE")
    package = apt_package(software, str(asset.get("version") or ""))
    if os_name == "linux" and package:
        lines = ["apt-get update", f"apt-get install -y {package}", f"# Target version {fixed}"]
    else:
        lines = [f"# Upgrade {software} to {fixed} manually. No packaged name is mapped."]
    actions = [
        Action(
            id=_slug("upgrade", hostname, cve_id, fixed),
            summary=f"Upgrade {software} on {hostname} to {fixed}",
            lines=lines,
            host=hostname,
            os_name=os_name,
            cve_id=cve_id,
        )
    ]
    for ip in ips:
        if ip in blocked:
            continue
        blocked.add(ip)
        actions.append(_block_action(hostname, os_name, cve_id, ip))
    return actions


def _recorded_response_actions(
    logs: str, inventory: list[dict[str, Any]], covered: set[str]
) -> list[Action]:
    """Note a patch that the logs already recorded when no CVE section covers the host."""
    actions: list[Action] = []
    outcome_re = re.compile(
        r"outcome=(attack_completed|patched_after_detection|patched_from_advisory)"
    )
    for line in (logs or "").splitlines():
        match = outcome_re.search(line)
        host_match = re.search(r"host=(\S+)", line)
        if match is None or host_match is None:
            continue
        hostname = host_match.group(1)
        if hostname in covered:
            continue
        asset = next(
            (item for item in inventory if str(item.get("hostname") or "") == hostname),
            None,
        )
        if asset is None:
            continue
        version_match = re.search(r"version=(\S+)", line)
        version = version_match.group(1) if version_match else str(asset.get("version") or "")
        software = str(asset.get("software") or "")
        outcome = match.group(1)
        os_name = host_os(asset, "linux")
        actions.append(
            Action(
                id=_slug("recorded", hostname, outcome),
                summary=f"Confirm {hostname} recorded response {outcome}",
                lines=[
                    f"# {hostname} recorded {outcome} at version {version}.",
                    "# Inventory already reports this build. No install command is proposed.",
                    _verify_command(software),
                ],
                host=hostname,
                os_name=os_name,
                cve_id=outcome,
            )
        )
        covered.add(hostname)
    return actions


def _phase_actions(actors: list[dict[str, Any]]) -> list[Action]:
    actions: list[Action] = []
    for actor in actors:
        for phase in actor.get("phases") or []:
            remediation = phase.get("remediation") or {}
            if not remediation:
                continue
            lines = [
                (
                    f"# {phase.get('timestamp')} {actor.get('actor')} "
                    f"{phase.get('tactic_id')} {phase.get('technique_id')}"
                ),
                "# Preventive: " + "; ".join(remediation.get("preventive") or []),
                "# Detective: " + "; ".join(remediation.get("detective") or []),
                "# Corrective: " + "; ".join(remediation.get("corrective") or []),
                "# ATT&CK mitigations: " + ", ".join(remediation.get("mitigation_ids") or []),
            ]
            waf = remediation.get("waf")
            if waf:
                lines.append(str(waf))
            actions.append(
                Action(
                    id=_slug(
                        "phase",
                        str(actor.get("actor")),
                        str(phase.get("timestamp")),
                        str(phase.get("tactic_id")),
                    ),
                    summary=(
                        f"{phase.get('tactic_name')} controls for {actor.get('actor')}"
                    ),
                    lines=lines,
                    host="edge",
                    os_name="any",
                    cve_id=phase.get("cve_id"),
                )
            )
    return actions


def _upgrade_lines(asset: dict[str, Any], cve_id: str, applicable: bool) -> list[str]:
    rule = CVE_RULES[cve_id]
    os_name = str(asset["os"])
    version = str(asset["version"])
    fixed = rule.fixed_version(version)
    if not applicable:
        platform_name = "Linux" if os_name == "linux" else "Windows"
        lines = [f"# {cve_id} does not apply to {platform_name}."]
        package = apt_package(rule.software, version)
        if os_name == "linux" and package:
            lines.append(f"# Correct apt package name if this host is updated for version parity.")
            lines.append(f"apt-get install -y {package}")
        return lines
    if os_name == "linux":
        lines = ["apt-get update"]
        package = apt_package(rule.software, version)
        if package:
            lines.append(f"apt-get install -y {package}")
        if fixed:
            lines.append(f"# Target version {fixed}.")
        if rule.demo:
            lines.append("# Demo identifier: authoritative CVE-2026-21443 is OpenEMR, not nginx.")
        return lines
    lines = [f"# {cve_id} is Windows-specific. Package manager apt does not apply."]
    if cve_id == "CVE-2024-4577":
        parsed = version_tuple(version)
        winget_id = f"PHP.PHP.{parsed[0]}.{parsed[1]}" if len(parsed) >= 2 else "PHP.PHP"
        lines.extend(
            [
                "# Fixed versions: 8.1.29, 8.2.20, and 8.3.8.",
                f"# This host runs {version}; minimum for this branch is {fixed}.",
                "# If this winget id is unavailable, install the Windows build from https://windows.php.net/download/",
                f"winget install --id {winget_id} --exact",
            ]
        )
        return lines
    if cve_id == "CVE-2024-27980":
        lines.extend(
            [
                "# CVE-2024-27980 fix points: 18.20.2, 20.12.2, and 21.7.3.",
                f"# This host runs {version}; install {fixed} or later.",
                "# On the 20.x line, prefer 20.15.1 or later because CVE-2024-36138 bypassed the first fix.",
                f"# Official installer: https://nodejs.org/dist/v{fixed}/node-v{fixed}-x64.msi",
                f"$installer = Join-Path $env:TEMP 'node-v{fixed}-x64.msi'",
                (
                    "Invoke-WebRequest -Uri "
                    f"'https://nodejs.org/dist/v{fixed}/node-v{fixed}-x64.msi' -OutFile $installer"
                ),
                'Start-Process msiexec.exe -ArgumentList "/i `"$installer`" /qn" -Wait',
            ]
        )
        return lines
    lines.append(f"# Upgrade {rule.software} to {fixed} with the vendor Windows installer.")
    return lines


def _upgrade_text(cve_id: str | None, inventory: list[dict[str, Any]]) -> str:
    if not cve_id or cve_id not in CVE_RULES:
        return ""
    vulnerable, excluded = classify_cve(cve_id, inventory)
    chunks: list[str] = []
    for asset in vulnerable:
        chunks.extend(_upgrade_lines(asset, cve_id, True))
    for asset in excluded:
        chunks.extend(_upgrade_lines(asset, cve_id, False))
    return "\n".join(chunks)


def _block_action(hostname: str, os_name: str, cve_id: str, ip: str) -> Action:
    if os_name == "windows":
        command = (
            f'New-NetFirewallRule -DisplayName "SentinelGnome-block-{ip}" '
            f"-Direction Inbound -Action Block -RemoteAddress {ip}"
        )
    else:
        command = f"ufw deny from {ip} to any"
    return Action(
        id=_slug("block-ip", ip),
        summary=f"Block attacker IP {ip}",
        lines=[f"# Temporary mitigation: block attacker {ip}", command],
        host=hostname,
        os_name=os_name,
        cve_id=cve_id,
    )


def _verify_command(software: str) -> str:
    name = software.casefold()
    if "nginx" in name:
        return "nginx -v"
    if "php" in name:
        return "php -v"
    if "node" in name:
        return "node -v"
    return f"# Verify the installed {software} version with the vendor command."


def _ips_for_cve(
    cve_id: str, actors: list[dict[str, Any]], intel: dict[str, Any]
) -> list[str]:
    ips: list[str] = []
    if intel.get("cve_id") == cve_id:
        for ioc in intel.get("iocs") or []:
            if _is_ip(str(ioc)) and ioc not in ips:
                ips.append(str(ioc))
    for actor in actors:
        matched = any(phase.get("cve_id") == cve_id for phase in actor.get("phases") or [])
        ip = str(actor.get("ip") or "")
        if matched and _is_ip(ip) and ip not in ips:
            ips.append(ip)
    return ips


def _cve_follow_up(cve_id: str, actors: list[dict[str, Any]]) -> bool:
    for actor in actors:
        has_cve = any(phase.get("cve_id") == cve_id for phase in actor.get("phases") or [])
        if has_cve and actor.get("follow_up"):
            return True
    return False


def _matching_record(
    asset: dict[str, Any],
    software: str,
    vulnerable_fn: Any,
    platform: str,
) -> dict[str, Any] | None:
    if not is_active(asset):
        return None
    installed = asset.get("software")
    hostname = str(asset.get("hostname") or "")
    version = str(asset.get("version") or "")
    if not isinstance(installed, str) or not hostname:
        return None
    if not software_matches(software, installed):
        return None
    if not vulnerable_fn(version):
        return None
    os_name = host_os(asset, platform)
    applicable = platform == "any" or os_name == platform
    return _record(asset, os_name, applicable)


def _record(asset: dict[str, Any], os_name: str, vulnerable: bool) -> dict[str, Any]:
    return {
        "hostname": str(asset.get("hostname") or ""),
        "ip": asset.get("ip"),
        "os": os_name,
        "software": asset.get("software"),
        "version": str(asset.get("version") or ""),
        "vulnerable": vulnerable,
    }


def _correction(action: Action) -> dict[str, str]:
    return {"id": action.id, "summary": action.summary, "status": "pending"}


def _dedup(actions: list[Action]) -> list[Action]:
    seen: set[str] = set()
    unique: list[Action] = []
    for action in actions:
        if action.id in seen:
            continue
        seen.add(action.id)
        unique.append(action)
    return unique


def _slug(*parts: str) -> str:
    text = "-".join(parts)
    text = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return text


def _is_ip(value: str) -> bool:
    return re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value or "") is not None


def tactic_label(tactic_id: str) -> str:
    name = TACTIC_NAMES.get(tactic_id, "")
    return f"{tactic_id} {name}".strip()
