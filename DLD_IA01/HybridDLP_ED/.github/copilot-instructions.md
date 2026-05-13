<!-- Copilot instructions for working on HybridDLP_ED -->
# HybridDLP_ED — Copilot Instructions

Purpose: give an AI coding assistant the minimal, concrete knowledge to be productive in this repo.

**Big Picture**
- **Architecture:** lightweight Windows sensor (monitoring) + local IPC queue + worker(s) + decision engine. See [docs/architecture.md](docs/architecture.md) for high-level design choices.
- **Runtime shape:** `agent/` contains sensor, watchdog and a Windows service wrapper. `worker/` contains consumer logic.

**Key files to inspect first**
- `agent/watchdog.py`: supervisor that spawns `sensor.py`, writes heartbeats to `agent/runtime/state`, and restarts worker on failure.
- `agent/sensor.py`: simple loop writing a heartbeat file; place where sensor event-generation logic belongs.
- `agent/service.py`: Windows Service wrapper (pywin32) that runs the watchdog under SYSTEM.
- `docs/architecture.md` and `docs/design_decisions.md`: rationale for separation of sensor vs worker and IPC choices.

**How to run / dev workflows**
- Create a Python venv and install dependencies (this project currently has an empty `requirements.txt`; add needed deps like `pywin32` when testing services).
  - Windows commands (PowerShell):
    ```powershell
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    ```
- Run watchdog in foreground (recommended for development):
  - `python agent/watchdog.py`
- Run sensor alone (fast loop + heartbeat):
  - `python agent/sensor.py`
- Install/run as Windows service (requires admin & `pywin32`):
  - `python agent/service.py install`
  - `python agent/service.py start`
  - Use same script with `remove`/`stop` commands supported by `win32serviceutil`.

**Project-specific patterns & gotchas**
- Heartbeat files: `agent/runtime/state/*.json` (e.g. `sensor_heartbeat.json`, `watchdog_heartbeat.json`). Code uses an atomic write pattern (`.tmp` file then replace) — follow `atomic_write_json` when updating state.
- Watchdog expects to run with repo `cwd` = `agent/` (service runs from System32 by default; code uses `os.chdir(BASE_DIR)` in `service.py` and `watchdog.py`). Always ensure `cwd` is correct in tests that spawn subprocesses.
- Process management: Windows-only `taskkill` is used to terminate worker trees (`kill_process_tree_windows`) instead of `psutil` — tests and mocks should account for this.
- IPC/queue integration: `agent/ipc.py` and `agent/config.py` are currently placeholders; design docs mention Redis for IPC. Treat IPC as an integration point to implement later.

**Tests & debugging tips**
- To unit test supervisor logic, avoid spawning real subprocesses: monkeypatch `Supervisor.spawn_worker` to return a fake `Popen`-like object.
- To validate restart/backoff behavior, manipulate the heartbeat files in `agent/runtime/state` and observe `watchdog.log` in `agent/runtime/logs`.

**When editing code**
- Preserve use of `BASE_DIR` and explicit `cwd` handling — these are intentional to support service behavior.
- Prefer the existing atomic write pattern for state files to avoid race conditions.

If anything here is unclear or you need examples added (tests, mocks, or commands for CI), tell me which section to expand.
