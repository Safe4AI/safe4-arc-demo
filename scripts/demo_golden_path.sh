#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f scripts/demo_golden_path.env ]; then
  set -a
  # Committed public Arc Testnet evidence; contains no credentials.
  . scripts/demo_golden_path.env
  set +a
fi

if [ -f shipline/verify.env ]; then
  set -a
  # Private-workspace verifier values may override the public demo evidence.
  . shipline/verify.env
  set +a
fi

if [ -n "${PYTHON:-}" ]; then
  :
elif [ -x .python313/python.exe ]; then
  PYTHON=.python313/python.exe
elif [ -x .venv/Scripts/python.exe ]; then
  PYTHON=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then
  PYTHON=.venv/bin/python
elif command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi

exec "$PYTHON" -m scripts.demo_golden_path
