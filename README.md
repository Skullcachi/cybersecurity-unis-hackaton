# Sentinel Gnome

Local SOC demo. It reads the synthetic logs, correlates attacker activity across ATT&CK tactics, compares the result with the asset inventory, and writes a specialist report. Remediation commands and honeypot steering rules are shown and can be simulated. The dashboard never executes them and never contacts the network.

The bundled logs tell three outcomes: the Nginx attack completes and stays unpatched, PHP is patched after the attempt, and Node.js is patched from the advisory before any probe.

## Quick path

1. `python3 -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt`
3. `streamlit run app.py`

The scenario menu is **Nginx Zero-Day**, **PHP CGI RCE (CVE-2024-4577)**, **Node.js Windows Command Injection (CVE-2024-27980)**, and **Opción Personalizada**. **Analizar todos los logs** runs the same engine with an empty advisory, so detection comes from `system_logs.txt` alone. **Tablero** shows findings, the kill chain, and the honeypot session. **Reporte** is built only from the hunt JSON.

## What the engine does

| Topic | Decision |
|-------|----------|
| Engine | `agent.run_hunt` returns one JSON object. No network and no model call. Original keys stay, including `response_outcome` and `response_evidence`. |
| Detection | Built-in signatures: `ZD-Hunter/6.0`, PHP-CGI argument injection (`%AD` / `allow_url_include`), `child_process.spawn` of `.bat`/`.cmd`, staged downloads, successful `/admin` access, and malformed `Transfer-Encoding`. Lines that contain `outcome=` are response records, not detections. |
| Outcomes | `attack_completed` keeps the host vulnerable. `patched_after_detection` keeps the attempt and clears the host. `patched_from_advisory` has no probe. An empty advisory that sees more than one outcome returns `response_outcome: null` and lists every record. |
| Correlation | Events are grouped by source IP and split when the gap exceeds 30 minutes. A pattern needs at least two distinct tactics in plausible order. One tactic stays a low-confidence alert. |
| Honeypot | Established patterns are replayed against a local decoy. Answers are static. Payloads are not executed. nginx, iptables, and proxy rules are text only. |
| Report | `report_view.hunt_report` reads the hunt JSON for the Reporte view. `generate_report` writes the specialist Markdown. `generate_report_html` writes HTML. The dashboard also downloads JSON. |
| Inputs | `scenarios.json`, `inventory.json`, `system_logs.txt` (synthetic) |
| Check | `python3 -m unittest -v` |

## Sample story

`system_logs.txt` is labeled synthetic demo data.

- `192.168.1.10`, `192.168.1.50`, `192.168.1.75`, and `192.168.1.80` are benign clients.
- `203.0.113.50` scans with `ZD-Hunter/6.0` and then `POST /admin/session 200`. That is reconnaissance plus collection, so it is an attack pattern. `web-nginx-01` stays on nginx 1.24.0 and the audit line says `attack_completed`.
- `203.0.113.77` is only reconnaissance. It is an alert, not an attack pattern, and it is not steered to the decoy.
- `198.51.100.42` probes PHP-CGI, stages `cgi-drop.php` on `tools.attacker-lab.example`, exploits CVE-2024-4577, runs `cmd.exe`, reads `/admin/config`, and posts to `/collect`. The inventory is already PHP 8.2.20 and the log records `patched_after_detection`, so the host is not vulnerable. The campaign is still a pattern.
- `api-node-01` is Node.js 20.12.2. The log records `patched_from_advisory` and does not contain a probe from `203.0.113.105`. Command-injection detection still runs when those lines are supplied.

## CVE notes

- **CVE-2024-4577** is PHP-CGI argument injection on Windows (soft hyphen / Best-Fit). Fixed in 8.1.29, 8.2.20, and 8.3.8. The version check is per branch. `8.1.29` is not treated as vulnerable just because it is numerically below `8.2.20`, and `8.3.7` is vulnerable even though it is above `8.2.20`.
- **CVE-2024-27980** is a Windows command injection in `child_process.spawn` / `spawnSync` for `.bat` and `.cmd` without `shell: true`. It is not request smuggling. Fixed in 18.20.2, 20.12.2, and 21.7.3. CVE-2024-36138 bypassed the first fix; the 20.x line should move to 20.15.1 or later.
- **CVE-2026-21443** is a **demo identifier** in this lab. The authoritative record is an OpenEMR XSS issue (`xl()` output, fixed in OpenEMR 8.0.0), not an nginx vulnerability. The nginx range `<= 1.24.0` and the `ZD-Hunter/6.0` user agent are scenario data.
- Malformed `Transfer-Encoding` or an internal `Host` header is recorded as suspicious HTTP abuse and is not mapped to CVE-2024-27980.

EOL PHP branches outside 8.1, 8.2, and 8.3 are not scored by this demo.

## Remediation

Each host section follows `inventory.json` `os`.

- Linux: `apt-get install -y nginx`, `php8.2-cgi` (or the matching `php8.1-cgi` / `php8.3-cgi` branch), and `nodejs`. The package name is the distro name, not `PHP=8.2.20*` or `Node.js=20.12.2*`.
- Windows: `winget` id `PHP.PHP.8.x`, or the Node.js MSI for the branch fix. CVE-2024-4577 and CVE-2024-27980 do not use apt.
- A Linux host running a Windows-only CVE is not marked vulnerable. The script still shows the correct apt package name and says the CVE does not apply.
- A host that already meets the fix is not marked vulnerable. The script still names that version and a verify command (`php -v`, `node -v`, or `nginx -v`) and does not propose an install.
- Temporary controls include blocking `php-cgi.exe`, blocking attacker IPs, and restricting `/admin/config` and `/admin/session`.
- Every observed kill-chain phase gets preventive, detective, and corrective text with ATT&CK mitigation ids. Tactics that are not in the logs are not invented.

The dashboard checkbox state for corrections and reviewer sign-off is kept in session state and copied into the exported report.

## Honeypot simulation

The decoy listens only in the generated policy (`127.0.0.1:8089`). Replay walks the attacker's log lines in order, returns canned bodies (including a canary admin token that is not a real secret), and records the transcript. The body a client would see does not say that the session was diverted.

A production deployment would additionally need:

- an isolated decoy host or VLAN with no route back to production data
- written authorization, a retention limit, and an owner for the transcript
- egress denial so staged URLs and payloads are not fetched
- monitoring and alerting on the decoy itself
- a change-controlled install of any nginx, iptables, or proxy rule

This demo does none of those. It does not scan, attack, or contact third parties.
