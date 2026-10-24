# Sentinel Gnome

Local SOC demo. Pick a scenario, compare it with the asset inventory, hunt IoCs in the logs, show the MITRE ATT&CK mapping, and simulate a defensive bash script. The dashboard never executes that script.

## Quick path

1. `python3 -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt`
3. `streamlit run app.py`

The scenario menu is **Nginx Zero-Day**, **PHP CGI RCE (CVE-2024-4577)**, **Node.js Request Smuggling (CVE-2024-27980)**, and **Opción Personalizada**.

The logs tell three outcomes: the Nginx attack completes and stays unpatched, PHP is patched after the attempt, and Node.js is patched from the advisory before any probe.

## Details

| Topic | Decision |
|-------|----------|
| Engine | `agent.run_hunt` returns one strict JSON object. No network and no model call. |
| Inputs | `scenarios.json`, `inventory.json`, `system_logs.txt` |
| UI | Metrics, red or green exposure, MITRE cards, log evidence, a simulation button, and a Reporte view built only from the hunt JSON. |
| Check | `python3 -m unittest tests.test_agent -v` |

## Next step

Choose **Opción Personalizada** and paste another advisory.
