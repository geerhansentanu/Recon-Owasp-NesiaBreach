#!/usr/bin/env sh
set -eu

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  printf "Masukkan target domain/URL: "
  read TARGET
fi

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
python -m pip install -r requirements.txt
python owasp_recon.py "$TARGET" --scope-file scope.txt --out report.html --json-out report.json

echo "Report dibuat: $(pwd)/report.html"
