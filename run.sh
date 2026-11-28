#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ -x .venv/bin/python ]]; then
    python_bin=".venv/bin/python"
elif [[ -x venv/bin/python ]]; then
    python_bin="venv/bin/python"
else
    python3 -m venv .venv
    python_bin=".venv/bin/python"
fi

if ! "$python_bin" -c 'from importlib.metadata import version; [version(name) for name in ("Flask", "gunicorn", "torch", "transformers", "huggingface-hub", "Pillow")]' >/dev/null 2>&1; then
    "$python_bin" -m pip install -r requirements.txt
fi

"$python_bin" -m py_compile glassbox_nn.py
"$python_bin" glassbox_nn.py --train
exec ./run_wsgi.sh "$@"
