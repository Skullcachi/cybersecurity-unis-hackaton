"""Streamlit dashboard for Sentinel Gnome."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from agent import generate_report, generate_report_html, run_hunt, simulate_script

ROOT = Path(__file__).resolve().parent
CUSTOM_SCENARIO = "Opción Personalizada"


def read_text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def load_scenarios() -> list[dict[str, str]]:
    return json.loads(read_text("scenarios.json"))


def render_mitre(mitre: dict[str, Any]) -> None:
    st.subheader("MITRE ATT&CK")
    tactic, technique, name, mitigation = st.columns(4)
    tactic.metric("Táctica", mitre.get("tactic") or "—")
    technique.metric("Técnica", mitre.get("technique_id") or "—")
    name.metric("Nombre", mitre.get("technique_name") or "—")
    mitigation.metric("Mitigación", mitre.get("mitre_mitigation_id") or "—")


def render_findings(report: dict[str, Any]) -> None:
    st.subheader("Hallazgos")
    findings = report.get("findings") or []
    if not findings:
        st.info("Sin hallazgos de firma.")
        return
    for finding in findings:
        hosts = ", ".join(
            f"{item['hostname']} {item['version']}" for item in finding.get("affected_hosts") or []
        )
        st.markdown(
            f"**{finding['title']}** — {finding.get('severity') or '—'} — "
            f"{finding.get('cve_id') or 'sin CVE'}"
        )
        if finding.get("cve_note"):
            st.caption(finding["cve_note"])
        if hosts:
            st.write(f"Hosts: {hosts}")
        if finding.get("evidence"):
            st.code("\n".join(finding["evidence"]), language="text")


def render_timeline(report: dict[str, Any]) -> None:
    st.subheader("Línea de tiempo de la kill chain")
    rows: list[dict[str, Any]] = []
    for actor in report.get("kill_chain") or []:
        label = "patrón" if actor.get("is_attack_pattern") else "alerta"
        for phase in actor.get("phases") or []:
            rows.append(
                {
                    "Hora": phase.get("timestamp"),
                    "Actor": actor.get("actor"),
                    "Clase": label,
                    "Confianza": actor.get("confidence"),
                    "Táctica": f"{phase.get('tactic_id')} {phase.get('tactic_name')}",
                    "Técnica": phase.get("technique_id"),
                }
            )
    if not rows:
        st.info("No hay eventos correlacionados.")
        return
    st.table(rows)
    for actor in report.get("kill_chain") or []:
        with st.expander(f"{actor.get('actor')} — {actor.get('classification')}"):
            for reason in actor.get("reasons") or []:
                st.write(reason)


def render_honeypot(report: dict[str, Any]) -> None:
    st.subheader("Honeypot simulado")
    st.caption(
        "El decoy solo responde con texto fijo. No ejecuta payloads, no abre red "
        "y las reglas de desvío no se aplican."
    )
    honeypot = report.get("honeypot") or {}
    if honeypot.get("engaged"):
        st.warning("Decisión de desvío para: " + ", ".join(honeypot.get("targets") or []))
    else:
        st.success("Ningún actor alcanzó el umbral de patrón. No hay desvío.")
    st.code(honeypot.get("policy") or "", language="text")
    for session in honeypot.get("sessions") or []:
        st.markdown(f"**Sesión {session.get('actor')}**")
        rows = [
            {
                "Hora": entry.get("timestamp"),
                "Método": entry.get("method"),
                "Ruta": entry.get("path"),
                "Ejecutado": entry.get("executed"),
                "Estado": entry.get("response_status"),
            }
            for entry in session.get("transcript") or []
        ]
        if rows:
            st.table(rows)
        canary = [
            entry.get("response_body")
            for entry in session.get("transcript") or []
            if entry.get("canary")
        ]
        if canary:
            st.caption("Respuesta canary (no es un secreto real)")
            st.code(canary[0], language="text")


def render_checks(title: str, items: list[dict[str, Any]], store_key: str) -> dict[str, bool]:
    st.subheader(title)
    store = st.session_state.setdefault(store_key, {})
    for item in items:
        widget_key = f"{store_key}_{item['id']}"
        if widget_key not in st.session_state:
            st.session_state[widget_key] = bool(store.get(item["id"], False))
        store[item["id"]] = st.checkbox(item["summary"], key=widget_key)
    return dict(store)


def render_report(report: dict[str, Any]) -> None:
    cve_count = len({item.get("cve_id") for item in report.get("findings") or [] if item.get("cve_id")})
    cve_label = report.get("cve_id") or (f"{cve_count} CVEs" if cve_count else "—")
    cve, hosts, patterns, alerts = st.columns(4)
    cve.metric("CVE", cve_label)
    hosts.metric("Hosts en riesgo", len(report["affected_hosts"]))
    patterns.metric("Patrones", len(report.get("attack_patterns") or []))
    alerts.metric("Alertas", len(report.get("alerts") or []))

    if report["is_system_vulnerable"]:
        st.error("SISTEMA VULNERABLE: " + ", ".join(report["affected_hosts"]))
    else:
        st.success("SISTEMA SEGURO: ningún activo activo cae en el rango vulnerable.")

    if report["threat_detected_in_logs"]:
        st.error(f"Actividad en logs. Severidad {report.get('severity') or '—'}.")
    else:
        st.success("Los logs no contienen la actividad buscada.")
    if report.get("cve_note"):
        st.info(report["cve_note"])

    panel = st.session_state.get("panel", "findings")
    view_findings, view_timeline, view_honeypot, view_report = st.columns(4)
    if view_findings.button("Hallazgos"):
        st.session_state["panel"] = "findings"
        panel = "findings"
    if view_timeline.button("Línea de tiempo"):
        st.session_state["panel"] = "timeline"
        panel = "timeline"
    if view_honeypot.button("Sesión honeypot"):
        st.session_state["panel"] = "honeypot"
        panel = "honeypot"
    if view_report.button("Informe"):
        st.session_state["panel"] = "report"
        panel = "report"

    if panel == "timeline":
        render_timeline(report)
    elif panel == "honeypot":
        render_honeypot(report)
    elif panel == "report":
        st.subheader("Informe para revisión")
        st.caption("El Markdown se genera en el navegador. Nada se ejecuta al descargarlo.")
    else:
        render_findings(report)
        render_mitre(report["mitre_attack"])

    evidence_col, script_col = st.columns(2)
    with evidence_col:
        st.subheader("Evidencia en logs")
        if report["detected_log_evidence"]:
            st.code("\n".join(report["detected_log_evidence"]), language="text")
        else:
            st.info("Sin líneas coincidentes.")
    with script_col:
        st.subheader("Script de remediación")
        st.caption("La simulación no ejecuta comandos en esta máquina.")
        st.code(report["remediation_script"], language="bash")
        st.download_button(
            "Descargar script",
            data=report["remediation_script"],
            file_name="mitigation.txt",
            mime="text/plain",
            key="download_script",
        )
        if st.button("Simular remediación", type="primary"):
            st.session_state["show_simulation"] = True
        if st.session_state.get("show_simulation"):
            st.code(simulate_script(report["remediation_script"]), language="text")

    applied = render_checks(
        "Correcciones tomadas",
        report.get("corrections") or [],
        "corrections_taken",
    )
    reviewed = render_checks(
        "Firma del revisor",
        report.get("signoff") or [],
        "signoff_state",
    )
    markdown = generate_report(report, applied, reviewed)
    html_report = generate_report_html(report, applied, reviewed)
    payload = {
        "hunt": report,
        "corrections_taken": applied,
        "signoff": reviewed,
    }
    md_col, html_col, json_col = st.columns(3)
    md_col.download_button(
        "Descargar informe Markdown",
        data=markdown,
        file_name="sentinel-gnome-report.md",
        mime="text/markdown",
        key="download_report_md",
    )
    html_col.download_button(
        "Descargar informe HTML",
        data=html_report,
        file_name="sentinel-gnome-report.html",
        mime="text/html",
        key="download_report_html",
    )
    json_col.download_button(
        "Descargar informe JSON",
        data=json.dumps(payload, indent=2),
        file_name="sentinel-gnome-report.json",
        mime="application/json",
        key="download_report_json",
    )
    if panel == "report":
        st.markdown(markdown)

    with st.expander("JSON estricto"):
        st.json(report)


def main() -> None:
    st.set_page_config(page_title="Sentinel Gnome", layout="wide")
    st.title("Sentinel Gnome")
    st.caption(
        "Caza local por firmas y kill chain. El honeypot y el script de remediación "
        "se muestran y se simulan; el dashboard no los ejecuta."
    )

    try:
        scenarios = load_scenarios()
        inventory = json.loads(read_text("inventory.json"))
        logs = read_text("system_logs.txt")
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"No se pudieron leer los insumos locales: {exc}")
        return

    advisories = {item["label"]: item["advisory"] for item in scenarios}
    labels = [*advisories.keys(), CUSTOM_SCENARIO]
    choice = st.selectbox("Escenario", labels, key="scenario_choice")
    analyze_col, reset_col = st.columns(2)
    if analyze_col.button("Analizar todos los logs"):
        st.session_state["analyze_all"] = True
        st.session_state["show_simulation"] = False
    if reset_col.button("Usar escenario"):
        st.session_state["analyze_all"] = False
        st.session_state["show_simulation"] = False

    if "loaded_scenario" not in st.session_state:
        st.session_state["loaded_scenario"] = choice
        st.session_state["advisory_text"] = advisories.get(choice, "")
    elif st.session_state["loaded_scenario"] != choice:
        st.session_state["loaded_scenario"] = choice
        st.session_state["advisory_text"] = advisories.get(choice, "")
        st.session_state["show_simulation"] = False
        st.session_state["analyze_all"] = False
        st.rerun()

    advisory = st.text_area("Advisory", height=240, key="advisory_text")
    if st.session_state.get("analyze_all"):
        st.warning(
            "Análisis de system_logs.txt completo. El advisory no filtra los hallazgos. "
            "Los logs son datos sintéticos de demostración."
        )
        hunt_advisory = ""
    else:
        hunt_advisory = advisory
    render_report(run_hunt(hunt_advisory, inventory, logs))


main()
