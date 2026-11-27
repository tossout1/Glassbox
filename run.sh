#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ -x .venv/bin/python ]]; then
    python_bin=".venv/bin/python"
elif [[ -x venv/bin/python ]]; then
    python_bin="venv/bin/python"
else
    python_bin="python3"
fi

"$python_bin" -m py_compile glassbox_nn.py
"$python_bin" glassbox_nn.py --train
exec ./run_wsgi.sh "$@"
