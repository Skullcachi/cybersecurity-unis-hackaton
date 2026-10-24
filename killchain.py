"""Group one actor's events into an ordered kill chain.

An attack pattern requires at least two distinct ATT&CK tactics in plausible
order. A single tactic, or a sequence that runs backwards, stays an alert.
Reconnaissance and Resource Development may occur in either order; later
tactics may not precede earlier ones.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from catalog import (
    ATTACK_PATTERN_MIN_TACTICS,
    SESSION_GAP_SECONDS,
    TACTIC_NAMES,
    TACTIC_ORDER,
)

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
PRE_ACCESS = {"TA0043", "TA0042"}


def correlate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_ip.setdefault(str(event["ip"]), []).append(event)
    assessments: list[dict[str, Any]] = []
    for ip in _ips_by_first_seen(events):
        sessions = split_sessions(by_ip.get(ip, []))
        for index, session in enumerate(sessions, start=1):
            actor = ip if len(sessions) == 1 else f"{ip}#{index}"
            assessments.append(assess_session(actor, ip, session))
    return assessments


def split_sessions(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    ordered = sorted(events, key=lambda item: str(item["timestamp"]))
    sessions: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    previous: datetime | None = None
    for event in ordered:
        current_time = _parse_time(str(event["timestamp"]))
        if current and previous is not None:
            gap = (current_time - previous).total_seconds()
            if gap > SESSION_GAP_SECONDS:
                sessions.append(current)
                current = []
        current.append(event)
        previous = current_time
    if current:
        sessions.append(current)
    return sessions


def assess_session(actor: str, ip: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(events, key=lambda item: str(item["timestamp"]))
    sequence = [str(event["tactic_id"]) for event in ordered]
    distinct = list(dict.fromkeys(sequence))
    ordered_ok = plausible_order(sequence)
    is_pattern = len(distinct) >= ATTACK_PATTERN_MIN_TACTICS and ordered_ok
    confidence = confidence_for(len(distinct), ordered_ok)
    phases = [_phase(event, confidence) for event in ordered]
    return {
        "actor": actor,
        "ip": ip,
        "classification": "attack_pattern" if is_pattern else "alert",
        "is_attack_pattern": is_pattern,
        "confidence": confidence,
        "reasons": _reasons(distinct, sequence, ordered_ok, is_pattern),
        "tactics": distinct,
        "tactic_names": [TACTIC_NAMES.get(tactic, tactic) for tactic in distinct],
        "phases": phases,
        "follow_up": _has_admin_follow_up(ordered),
        "tooling": _tooling(ordered),
        "timestamps": [str(event["timestamp"]) for event in ordered],
    }


def plausible_order(sequence: list[str]) -> bool:
    """Return True when tactic ranks do not move backwards.

    TA0043 and TA0042 are both pre-access and may swap. Any other inversion
    rejects the sequence.
    """
    last_rank = -1
    for tactic_id in sequence:
        current = _rank(tactic_id)
        if last_rank >= 0 and current < last_rank:
            previous_id = TACTIC_ORDER[last_rank]
            if not (tactic_id in PRE_ACCESS and previous_id in PRE_ACCESS):
                return False
        last_rank = max(last_rank, current)
    return True


def confidence_for(distinct_count: int, ordered: bool) -> float:
    if distinct_count <= 0:
        return 0.0
    if not ordered or distinct_count < ATTACK_PATTERN_MIN_TACTICS:
        return 0.3
    return round(min(0.93, 0.46 + 0.08 * distinct_count), 2)


def _phase(event: dict[str, Any], confidence: float) -> dict[str, Any]:
    tactic_id = str(event["tactic_id"])
    return {
        "timestamp": event.get("timestamp"),
        "tactic_id": tactic_id,
        "tactic_name": event.get("tactic_name") or TACTIC_NAMES.get(tactic_id, ""),
        "technique_id": event.get("technique_id"),
        "technique_name": event.get("technique_name") or "",
        "title": event.get("title"),
        "cve_id": event.get("cve_id"),
        "cve_note": event.get("cve_note"),
        "software": event.get("software"),
        "kind": event.get("kind"),
        "signature_id": event.get("signature_id"),
        "evidence": [event.get("text") or ""],
        "objective": _objective(tactic_id),
        "tooling": event.get("indicator"),
        "confidence": confidence,
        "method": event.get("method"),
        "path": event.get("path"),
        "status": event.get("status"),
        "payload": event.get("payload") or event.get("text") or "",
        "base_severity": event.get("base_severity") or "low",
    }


def _objective(tactic_id: str) -> str:
    objectives = {
        "TA0043": "Identify exposed services and handlers.",
        "TA0042": "Stage a payload on attacker-controlled infrastructure.",
        "TA0001": "Gain a foothold through a public-facing service.",
        "TA0002": "Run a command on the host.",
        "TA0009": "Read administrative configuration data.",
        "TA0010": "Send collected data toward attacker infrastructure.",
    }
    return objectives.get(tactic_id, "Activity mapped to this tactic from the log line.")


def _reasons(
    distinct: list[str],
    sequence: list[str],
    ordered_ok: bool,
    is_pattern: bool,
) -> list[str]:
    labels = ", ".join(f"{tactic} {TACTIC_NAMES.get(tactic, '')}".strip() for tactic in distinct)
    if not distinct:
        return ["No tactic was observed."]
    if len(distinct) < ATTACK_PATTERN_MIN_TACTICS:
        return [
            f"Only one tactic ({labels}); isolated activity is an alert, not an attack pattern.",
            "A lone scanner or single hit is not promoted.",
        ]
    if not ordered_ok:
        return [
            f"Tactics were not in a plausible kill-chain order: {labels}.",
            f"Observed sequence: {' > '.join(sequence)}.",
            "Out-of-order activity stays an alert.",
        ]
    return [
        f"{len(distinct)} distinct tactics in plausible order: {' > '.join(distinct)}.",
        f"Tactic names: {labels}.",
        "Same source address and timestamps support one session.",
        "Classified as an attack pattern." if is_pattern else "Not classified as an attack pattern.",
    ]


def _has_admin_follow_up(events: list[dict[str, Any]]) -> bool:
    seen_other = False
    for event in events:
        if event.get("signature_id") == "admin_collection" and seen_other:
            return True
        if event.get("tactic_id") != "TA0009":
            seen_other = True
    return False


def _tooling(events: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for event in events:
        indicator = event.get("indicator")
        if indicator and indicator not in found:
            found.append(str(indicator))
    return found


def _rank(tactic_id: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic_id)
    except ValueError:
        return len(TACTIC_ORDER)


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, TIMESTAMP_FORMAT)


def _ips_by_first_seen(events: list[dict[str, Any]]) -> list[str]:
    ordered = sorted(events, key=lambda item: str(item["timestamp"]))
    ips: list[str] = []
    for event in ordered:
        ip = str(event["ip"])
        if ip not in ips:
            ips.append(ip)
    return ips
