#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ -x .venv/bin/gunicorn ]]; then
    gunicorn_bin=".venv/bin/gunicorn"
elif [[ -x venv/bin/gunicorn ]]; then
    gunicorn_bin="venv/bin/gunicorn"
else
    echo "Gunicorn is missing. Install project dependencies first: python3 -m pip install -r requirements.txt" >&2
    exit 1
fi

export GLASSBOX_BIND="${GLASSBOX_BIND:-127.0.0.1:8000}"
export GLASSBOX_TRUSTED_HOSTS="${GLASSBOX_TRUSTED_HOSTS:-localhost,127.0.0.1}"

exec "$gunicorn_bin" \
    --bind "$GLASSBOX_BIND" \
    --workers 1 \
    --threads 8 \
    --timeout 60 \
    wsgi:app
