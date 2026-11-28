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

export GLASSBOX_BIND="${GLASSBOX_BIND:-127.0.0.1:5000}"
export GLASSBOX_TRUSTED_HOSTS="${GLASSBOX_TRUSTED_HOSTS:-localhost,127.0.0.1}"

cert_dir=".local-certs"
cert_file="$cert_dir/localhost.crt"
key_file="$cert_dir/localhost.key"

if [[ ! -s "$cert_file" || ! -s "$key_file" ]]; then
    mkdir -p "$cert_dir"
    openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    chmod 600 "$key_file"
    chmod 644 "$cert_file"
fi

exec "$gunicorn_bin" \
    --bind "$GLASSBOX_BIND" \
    --certfile "$cert_file" \
    --keyfile "$key_file" \
    --workers 1 \
    --threads 8 \
    --timeout 60 \
    wsgi:app
