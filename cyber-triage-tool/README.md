# Cyber Triage Tool

A cyber triage tool with automated analysis and one-click investigation.

## Features (initial scaffold)
- Quick scan mode for rapid triage (hashes, entropy, optional PE and YARA)
- Full analysis mode (currently reuses quick scan)
- Investigation workflow (stub)
- Optional web interface (stub)

## Getting Started (Windows PowerShell)
1. Create and activate a virtual environment:
   - `python -m venv .venv`
   - `.venv\\Scripts\\Activate.ps1`
2. Install dependencies (some optional deps may require build tools):
   - `pip install -r requirements.txt`
3. Run the CLI help:
   - `python .\\main.py --help`
4. Quick scan example:
   - `python .\\main.py --quick-scan C:\\Windows\\System32 --output-dir data\\cases`
5. (Optional) Start the web interface (stub):
   - `python -m flask --app src.web.app:create_app run --port 8000`

## Reports
- Reports are generated into `data/cases/CASE-<timestamp>/` with `report.json` and `report.html`.

## Notes
- Git is not initialized because `git` is not detected in PATH.
  After installing Git, run:
  - `git init`
  - `git add .`
  - `git commit -m "Initial commit: scaffold cyber triage tool"`

