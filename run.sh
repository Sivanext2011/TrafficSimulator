#!/usr/bin/env bash
# Run the Telecom Traffic Simulator locally (dev).
# Primary supported deployment is Docker (see README). This script is for quick
# local runs.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8080}"
python3 -m pip install -q -r requirements.txt
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
