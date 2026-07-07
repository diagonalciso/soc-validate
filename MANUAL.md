# soc-Validate — Purple-Team Detection Validation

> Run Atomic Red Team techniques and prove the SOC detects them.

**Port:** `8104` &nbsp;|&nbsp; **Repo:** `diagonalciso/soc-validate` &nbsp;|&nbsp; **Service:** `soc-validate.service` &nbsp;|&nbsp; **Stack:** stdlib Python (no external deps)

Part of the **CD / Wazuh Full SOC** suite. Open the in-app **`?` Help button** (top-right of the dashboard) to read this manual, or view it here.

---

## 1. Overview

soc-Validate closes the loop on detection engineering. It runs an ATT&CK technique from the Atomic Red Team library, waits, then queries Wazuh / soc-ops for a matching alert inside the detection window — scoring each technique PASS (detected) or FAIL (blind spot). Results are shown as an ATT&CK matrix heatmap so coverage and gaps are obvious.

## 2. Key features

- ATT&CK matrix heatmap: green = detected, red = blind spot, grey = untested
- Run a single technique or a chained sequence
- Automatic verification against the Wazuh / soc-ops alert API
- Coverage trend and run history
- SAFE BY DEFAULT: `EXECUTION_ENABLED=0` — techniques are dry-run/simulated until you opt in

## 3. Running the service

The service is a single self-contained `app.py` using only the Python standard library.

```bash
# systemd (fleet / suite install)
sudo systemctl status soc-validate
sudo systemctl restart soc-validate
sudo journalctl -u soc-validate -f

# manual run (from the repo directory)
cp .env.example .env      # then edit as needed
env $(grep -v '^#' .env | xargs) python3 app.py
```

Then open **http://<host>:8104/**.

## 4. Configuration (environment variables)

Set these in `.env` (see `.env.example` for defaults):

| Variable | Notes |
|---|---|
| `ATOMICS_DIR` |  |
| `DETECT_WINDOW` |  |
| `EXECUTION_ENABLED` | Safety switch — OFF (0) by default; opt in deliberately. |
| `RUN_TIMEOUT` |  |
| `SOC_OPS_URL` | Upstream service base URL. |
| `VAL_DB` |  |
| `VAL_HOST` |  |
| `VAL_PORT` | Listen port (default 8104). |

## 5. HTTP endpoints

| Path | |
|---|---|
| `/` | Main dashboard (HTML) |
| `/api/matrix` | API endpoint (JSON) |
| `/api/run` | API endpoint (JSON) |
| `/api/stats` | API endpoint (JSON) |
| `/api/technique` | API endpoint (JSON) |
| `/health` | Health check |
| `/manual` | This manual (opened by the top-right **?** Help button) |

## 6. Integration

Queries the Wazuh / soc-ops alert API to confirm detections. Complements soc-detections (deploy rules) by validating them.

## 7. Security & operational notes

Execution is OFF by default. Only enable it against a scoped lab agent, never production endpoints. Many atomics are Windows/PowerShell — begin with the Linux-safe allow-list.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Page will not load | `systemctl status soc-validate`; confirm the port `8104` is listening (`lsof -i:8104`). |
| Help button shows "MANUAL.md not found" | Ensure `MANUAL.md` sits next to `app.py` in the service directory. |
| Service keeps restarting | `journalctl -u soc-validate -e` for the traceback; usually a missing `.env` value. |
| Empty / stale data | Confirm upstream sources and any API keys in `.env` are reachable. |

---

*Manual for soc-validate. Part of the CD / Wazuh Full SOC suite. Private © CisoDiagonal.*
