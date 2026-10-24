"""Streamlit dashboard for Sentinel Gnome."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from agent import run_hunt, simulate_script
from report_view import hunt_report

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


def render_outcome(report: dict[str, Any]) -> None:
    view = hunt_report(report)
    banner = st.error if view["level"] == "error" else st.success
    banner(view["verdict"])


def render_report(report: dict[str, Any]) -> None:
    cve, hosts, iocs, evidence = st.columns(4)
    cve.metric("CVE", report["cve_id"] or "—")
    hosts.metric("Hosts en riesgo", len(report["affected_hosts"]))
    iocs.metric("IoCs", len(report["iocs"]))
    evidence.metric("Evidencias", len(report["detected_log_evidence"]))

    render_outcome(report)

    render_mitre(report["mitre_attack"])

    evidence_col, script_col = st.columns(2)
    with evidence_col:
        st.subheader("Evidencia en logs")
        if report["detected_log_evidence"]:
            st.code("\n".join(report["detected_log_evidence"]), language="text")
        else:
            st.info("Sin intento de ataque en los logs.")
        if report["response_evidence"]:
            st.subheader("Acción registrada")
            st.code("\n".join(report["response_evidence"]), language="text")
    with script_col:
        st.subheader("Script de remediación")
        st.caption("La simulación no ejecuta comandos en esta máquina.")
        st.code(report["remediation_script"], language="bash")
        st.download_button(
            "Descargar script",
            data=report["remediation_script"],
            file_name="mitigation.sh",
            mime="text/x-shellscript",
        )
        if st.button("Simular remediación", type="primary"):
            st.session_state["show_simulation"] = True
        if st.session_state.get("show_simulation"):
            st.code(simulate_script(report["remediation_script"]), language="text")

    with st.expander("JSON estricto"):
        st.json(report)


def render_lines(lines: list[str], empty: str) -> None:
    if lines:
        st.code("\n".join(lines), language="text")
        return
    st.info(empty)


def render_hunt_report(report: dict[str, Any]) -> None:
    view = hunt_report(report)
    st.header(view["title"])
    st.caption("Este reporte sale del JSON de la caza. El script no se ejecuta.")
    render_outcome(report)

    cve, software, versions, threat = st.columns(4)
    cve.metric("CVE", view["cve_id"])
    software.metric("Software", view["affected_software"])
    versions.metric("Versiones", view["vulnerable_versions"])
    threat.metric("Intento en logs", "Sí" if view["threat_detected"] else "No")

    hosts_col, iocs_col = st.columns(2)
    with hosts_col:
        st.subheader("Hosts en el rango")
        render_lines(view["affected_hosts"], "Ningún host activo queda en el rango vulnerable.")
    with iocs_col:
        st.subheader("Indicadores")
        render_lines(view["iocs"], "El advisory no declaró indicadores.")

    st.subheader("Evidencia del intento")
    render_lines(view["evidence"], "Sin intento de ataque en los logs.")

    st.subheader("Acción registrada")
    render_lines(view["action"], "No hay una acción registrada para este host.")

    render_mitre(view["mitre"])

    st.subheader("Remediación propuesta")
    st.caption("La simulación no ejecuta comandos en esta máquina.")
    st.code(view["remediation_script"], language="bash")


def main() -> None:
    st.set_page_config(page_title="Sentinel Gnome", layout="wide")
    st.title("Sentinel Gnome")
    st.caption(
        "Caza local y determinista. El script de remediación se muestra y se simula; "
        "el dashboard no lo ejecuta."
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

    if "loaded_scenario" not in st.session_state:
        st.session_state["loaded_scenario"] = choice
        st.session_state["advisory_text"] = advisories.get(choice, "")
    elif st.session_state["loaded_scenario"] != choice:
        st.session_state["loaded_scenario"] = choice
        st.session_state["advisory_text"] = advisories.get(choice, "")
        st.session_state["show_simulation"] = False
        st.rerun()

    advisory = st.text_area("Advisory", height=240, key="advisory_text")
    view_name = st.radio(
        "Vista",
        ["Tablero", "Reporte"],
        horizontal=True,
        key="active_view",
    )
    report = run_hunt(advisory, inventory, logs)
    if view_name == "Reporte":
        render_hunt_report(report)
    else:
        render_report(report)


main()
