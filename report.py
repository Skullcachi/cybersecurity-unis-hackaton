"""Specialist Markdown and HTML reports. The hunt result is not mutated."""

from __future__ import annotations

import html
from typing import Any

SIGNOFF_ITEMS: list[dict[str, str]] = [
    {
        "id": "signoff-timeline",
        "summary": "Kill-chain timeline reviewed against the raw logs",
    },
    {
        "id": "signoff-honeypot",
        "summary": "Honeypot transcript reviewed; confirmed payloads were not executed",
    },
    {
        "id": "signoff-cve",
        "summary": "CVE mapping checked, including the CVE-2026-21443 demo note",
    },
    {
        "id": "signoff-controls",
        "summary": "Per-phase preventive, detective, and corrective controls approved",
    },
    {
        "id": "signoff-policy",
        "summary": "Redirect policy remains unapplied until a production change is approved",
    },
]


def generate_report(
    hunt: dict[str, Any],
    corrections: dict[str, bool] | None = None,
    signoff: dict[str, bool] | None = None,
) -> str:
    applied = corrections or {}
    reviewed = signoff or {}
    parts = [
        "# Sentinel Gnome report",
        "",
        _executive_summary(hunt),
        _attacker_profile(hunt),
        _timeline(hunt),
        _findings(hunt),
        _phase_findings(hunt),
        _honeypot_section(hunt),
        _cves(hunt),
        _phase_remediations(hunt),
        _patches(hunt),
        _checklist("## Corrections taken", hunt.get("corrections") or [], applied),
        _limitations(),
        _checklist("## Reviewer sign-off", hunt.get("signoff") or SIGNOFF_ITEMS, reviewed),
    ]
    return "\n".join(parts).rstrip() + "\n"


def generate_report_html(
    hunt: dict[str, Any],
    corrections: dict[str, bool] | None = None,
    signoff: dict[str, bool] | None = None,
) -> str:
    body = _markdown_to_html(generate_report(hunt, corrections, signoff))
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        "<title>Sentinel Gnome report</title></head><body>\n"
        f"{body}\n</body></html>\n"
    )


def _executive_summary(hunt: dict[str, Any]) -> str:
    patterns = hunt.get("attack_patterns") or []
    alerts = hunt.get("alerts") or []
    hosts = hunt.get("affected_hosts") or []
    honeypot = hunt.get("honeypot") or {}
    lines = [
        "## Executive summary",
        "",
        (
            f"The local logs produced {len(patterns)} attack pattern(s) and "
            f"{len(alerts)} low-confidence alert(s). "
            f"{len(hosts)} host(s) match a vulnerable build."
        ),
        f"Highest severity: {hunt.get('severity') or 'none'}.",
        (
            "Honeypot diversion is simulated for "
            + ", ".join(honeypot.get("targets") or [])
            + "."
            if honeypot.get("engaged")
            else "No attacker met the pattern threshold, so the decoy was not engaged."
        ),
        "Isolated single-tactic activity, including a lone scanner, stays an alert.",
        "Sentinel Gnome did not execute remediation commands or attacker payloads.",
    ]
    if _mentions_demo(hunt):
        lines.append(
            "CVE-2026-21443 is a demo identifier in this lab. The authoritative "
            "record is an OpenEMR XSS issue, not an nginx vulnerability."
        )
    lines.append("")
    return "\n".join(lines)


def _attacker_profile(hunt: dict[str, Any]) -> str:
    lines = ["## Attacker profile", ""]
    actors = list(hunt.get("kill_chain") or [])
    if not actors:
        lines.append("No attacker activity was correlated.")
        lines.append("")
        return "\n".join(lines)
    for actor in actors:
        tooling = ", ".join(actor.get("tooling") or []) or "none recorded"
        cves = sorted(
            {
                str(phase.get("cve_id"))
                for phase in actor.get("phases") or []
                if phase.get("cve_id")
            }
        )
        lines.extend(
            [
                f"### {actor.get('actor')}",
                "",
                f"- Classification: {actor.get('classification')}",
                f"- Attack pattern: {'yes' if actor.get('is_attack_pattern') else 'no'}",
                f"- Confidence: {actor.get('confidence')}",
                f"- Tactics: {', '.join(actor.get('tactics') or [])}",
                f"- Tooling: {tooling}",
                f"- CVEs: {', '.join(cves) if cves else 'none'}",
                f"- Follow-up admin read: {'yes' if actor.get('follow_up') else 'no'}",
            ]
        )
        for reason in actor.get("reasons") or []:
            lines.append(f"- Reason: {reason}")
        lines.append("")
    return "\n".join(lines)


def _timeline(hunt: dict[str, Any]) -> str:
    lines = [
        "## Kill-chain timeline",
        "",
        "| Time | Actor | Tactic | Technique | Confidence | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    rows = 0
    for actor in hunt.get("kill_chain") or []:
        for phase in actor.get("phases") or []:
            evidence = " ".join(phase.get("evidence") or [])
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(phase.get("timestamp")),
                        _cell(actor.get("actor")),
                        _cell(f"{phase.get('tactic_id')} {phase.get('tactic_name')}"),
                        _cell(f"{phase.get('technique_id')} {phase.get('technique_name')}"),
                        _cell(actor.get("confidence")),
                        _cell(evidence),
                    ]
                )
                + " |"
            )
            rows += 1
    if rows == 0:
        lines.append("| — | — | — | — | — | No correlated events |")
    lines.append("")
    return "\n".join(lines)


def _findings(hunt: dict[str, Any]) -> str:
    lines = ["## Findings", ""]
    findings = hunt.get("findings") or []
    if not findings:
        lines.extend(["No signature findings.", ""])
        return "\n".join(lines)
    for index, finding in enumerate(findings, start=1):
        hosts = ", ".join(
            f"{item.get('hostname')} ({item.get('software')} {item.get('version')}, {item.get('os')})"
            for item in finding.get("affected_hosts") or []
        ) or "none"
        mitre = finding.get("mitre_attack") or {}
        lines.extend(
            [
                f"### {index}. {finding.get('title')}",
                "",
                f"- Severity: {finding.get('severity')}",
                f"- CVE: {finding.get('cve_id') or 'none'}",
                f"- Note: {finding.get('cve_note') or 'none'}",
                f"- Attacker IPs: {', '.join(finding.get('attacker_ips') or []) or 'none'}",
                f"- Timestamps: {', '.join(finding.get('timestamps') or []) or 'none'}",
                f"- Affected hosts: {hosts}",
                (
                    "- MITRE ATT&CK: "
                    f"{mitre.get('tactic')} / {mitre.get('technique_id')} / "
                    f"{mitre.get('technique_name')} / {mitre.get('mitre_mitigation_id')}"
                ),
                "",
                "```",
                "\n".join(finding.get("evidence") or []),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def _phase_findings(hunt: dict[str, Any]) -> str:
    lines = ["## Per-phase findings", ""]
    wrote = False
    for actor in hunt.get("kill_chain") or []:
        for phase in actor.get("phases") or []:
            wrote = True
            evidence = "\n".join(phase.get("evidence") or [])
            lines.extend(
                [
                    f"### {actor.get('actor')} {phase.get('timestamp')} {phase.get('tactic_id')}",
                    "",
                    f"- Tactic: {phase.get('tactic_id')} {phase.get('tactic_name')}",
                    f"- Technique: {phase.get('technique_id')} {phase.get('technique_name')}",
                    f"- Confidence: {phase.get('confidence')}",
                    f"- Objective: {phase.get('objective')}",
                    f"- Tooling: {phase.get('tooling') or 'none'}",
                    f"- CVE: {phase.get('cve_id') or 'none'}",
                    "",
                    "```",
                    evidence,
                    "```",
                    "",
                ]
            )
    if not wrote:
        lines.extend(["No phases to report.", ""])
    return "\n".join(lines)


def _honeypot_section(hunt: dict[str, Any]) -> str:
    honeypot = hunt.get("honeypot") or {}
    lines = [
        "## Honeypot session analysis",
        "",
        "The honeypot is a local simulation. Payloads were not executed and no outbound connection was made.",
        f"Engaged: {'yes' if honeypot.get('engaged') else 'no'}.",
        f"Targets: {', '.join(honeypot.get('targets') or []) or 'none'}.",
        "",
        "```",
        str(honeypot.get("policy") or "").rstrip(),
        "```",
        "",
    ]
    for session in honeypot.get("sessions") or []:
        lines.append(f"### Session {session.get('actor')}")
        lines.append("")
        lines.append("| Time | Method | Path | Executed | Response |")
        lines.append("| --- | --- | --- | --- | --- |")
        for entry in session.get("transcript") or []:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(entry.get("timestamp")),
                        _cell(entry.get("method")),
                        _cell(entry.get("path")),
                        _cell(entry.get("executed")),
                        _cell(entry.get("response_status")),
                    ]
                )
                + " |"
            )
        lines.append("")
    for analysis in honeypot.get("analysis") or []:
        lines.append(f"Reconstructed objectives for {analysis.get('actor')}:")
        for objective in analysis.get("objectives") or []:
            if objective:
                lines.append(f"- {objective}")
        lines.append("")
    if not honeypot.get("sessions"):
        lines.append("No decoy session was recorded.")
        lines.append("")
    return "\n".join(lines)


def _cves(hunt: dict[str, Any]) -> str:
    lines = ["## CVEs", ""]
    seen: set[str] = set()
    for finding in hunt.get("findings") or []:
        cve_id = finding.get("cve_id")
        if not cve_id or cve_id in seen:
            continue
        seen.add(str(cve_id))
        hosts = ", ".join(
            f"{item.get('hostname')} {item.get('version')}"
            for item in finding.get("affected_hosts") or []
        ) or "no vulnerable host in inventory"
        lines.append(f"- {cve_id}: {hosts}. {finding.get('cve_note') or ''}".rstrip())
    if not seen:
        lines.append("- No CVE was mapped from the in-scope evidence.")
    lines.append("")
    return "\n".join(lines)


def _phase_remediations(hunt: dict[str, Any]) -> str:
    lines = ["## Per-phase remediations", ""]
    wrote = False
    for actor in hunt.get("kill_chain") or []:
        for phase in actor.get("phases") or []:
            remediation = phase.get("remediation") or {}
            if not remediation:
                continue
            wrote = True
            lines.extend(
                [
                    f"### {actor.get('actor')} {phase.get('tactic_id')} {phase.get('technique_id')}",
                    "",
                    "- Preventive: " + "; ".join(remediation.get("preventive") or []),
                    "- Detective: " + "; ".join(remediation.get("detective") or []),
                    "- Corrective: " + "; ".join(remediation.get("corrective") or []),
                    "- ATT&CK mitigations: "
                    + ", ".join(remediation.get("mitigation_ids") or []),
                ]
            )
            if remediation.get("waf"):
                lines.extend(["", "```", str(remediation["waf"]), "```"])
            if remediation.get("upgrade"):
                lines.extend(["", "```", str(remediation["upgrade"]).rstrip(), "```"])
            lines.append("")
    if not wrote:
        lines.extend(["No phase controls were generated.", ""])
    return "\n".join(lines)


def _patches(hunt: dict[str, Any]) -> str:
    return "\n".join(
        [
            "## Proposed patches",
            "",
            "Sentinel Gnome does not execute remediation commands.",
            "",
            "```",
            str(hunt.get("remediation_script") or "").rstrip(),
            "```",
            "",
        ]
    )


def _limitations() -> str:
    return "\n".join(
        [
            "## Residual risks, assumptions, and limitations",
            "",
            "- The logs are synthetic demo data, not a capture from a production network.",
            "- One log line is mapped to one tactic. Unobserved tactics (persistence, privilege escalation, defense evasion, credential access, lateral movement, command and control, impact) are not assumed.",
            "- Timestamps are assumed to be trustworthy and comparable. A gap longer than 30 minutes splits sessions so unrelated bursts are not stitched into a pattern.",
            "- The client address is treated as the actor. Network address translation can collapse unrelated clients.",
            "- CVE-2024-4577 and CVE-2024-27980 apply to Windows. A Linux package name is guidance for version parity only.",
            "- CVE-2024-27980 is fixed in 20.12.2 for the 20.x line, but CVE-2024-36138 means 20.15.1 or later is the safer follow-up.",
            "- CVE-2026-21443 is a demo identifier here. The real record describes OpenEMR, not nginx.",
            "- The honeypot is a simulation: static answers, no payload execution, no outbound network, and redirect rules that are shown but not applied.",
            "- A production deployment would additionally need an isolated decoy host, written authorization, retention limits, egress denial, monitoring, and a change-controlled path before any steering rule is installed.",
            "- A lone scanner can become a real intrusion later. The alert should stay queued, not discarded.",
            "",
        ]
    )


def _checklist(heading: str, items: list[dict[str, Any]], applied: dict[str, bool]) -> str:
    lines = [heading, ""]
    if not items:
        lines.extend(["- [ ] No items.", ""])
        return "\n".join(lines)
    for item in items:
        mark = "x" if applied.get(str(item.get("id"))) else " "
        lines.append(f"- [{mark}] {item.get('summary')}")
    lines.append("")
    return "\n".join(lines)


def _mentions_demo(hunt: dict[str, Any]) -> bool:
    if hunt.get("cve_id") == "CVE-2026-21443":
        return True
    for finding in hunt.get("findings") or []:
        if finding.get("demo") or finding.get("cve_id") == "CVE-2026-21443":
            return True
    return False


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "/").replace("\n", " ")


def _markdown_to_html(markdown: str) -> str:
    chunks: list[str] = []
    in_code = False
    code_lines: list[str] = []
    in_table = False
    table_rows: list[str] = []

    def flush_table() -> None:
        nonlocal in_table, table_rows
        if not table_rows:
            in_table = False
            return
        body = ["<table>"]
        data_rows = [row for row in table_rows if not _is_separator(row)]
        for index, row in enumerate(data_rows):
            cells = [_cell_html(part) for part in row.strip("|").split("|")]
            tag = "th" if index == 0 else "td"
            body.append("<tr>" + "".join(f"<{tag}>{cell}</{tag}>" for cell in cells) + "</tr>")
        body.append("</table>")
        chunks.append("".join(body))
        table_rows = []
        in_table = False

    for line in markdown.splitlines():
        if line.startswith("```"):
            if in_table:
                flush_table()
            if in_code:
                chunks.append("<pre>" + html.escape("\n".join(code_lines)) + "</pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if line.startswith("|"):
            in_table = True
            table_rows.append(line)
            continue
        if in_table:
            flush_table()
        if line.startswith("### "):
            chunks.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("## "):
            chunks.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            chunks.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("- "):
            chunks.append(f"<li>{html.escape(line[2:])}</li>")
        elif line.strip():
            chunks.append(f"<p>{html.escape(line)}</p>")
    if in_code:
        chunks.append("<pre>" + html.escape("\n".join(code_lines)) + "</pre>")
    if in_table:
        flush_table()
    return "\n".join(chunks)


def _is_separator(row: str) -> bool:
    cells = [part.strip() for part in row.strip("|").split("|")]
    return bool(cells) and all(set(part) <= {"-", ":"} and part for part in cells)


def _cell_html(value: str) -> str:
    return html.escape(value.strip())
