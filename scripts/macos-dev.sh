#!/usr/bin/env bash
# Local Mac smoke test on the develop branch.
# Does not touch main and does not push anywhere.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x /opt/homebrew/Caskroom/miniconda/base/bin/python3 ]]; then
  PY="${PYTHON:-/opt/homebrew/Caskroom/miniconda/base/bin/python3}"
else
  PY="${PYTHON:-python3}"
fi

if [[ ! -d .venv ]]; then
  echo "Creating .venv with $PY"
  "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q -U pip
python -m pip install -e ".[golden]"

if [[ ! -f tgws-server.yaml ]]; then
  tgws-server gen -o tgws-server.yaml \
    --host 127.0.0.1 \
    --secrets 1 \
    --domain cloudflare.com \
    --log-file tgws-server.log
fi

echo
echo "=== tgws-server doctor (this Mac) ==="
set +e
tgws-server doctor -c tgws-server.yaml
doctor_rc=$?
set -e

echo
echo "Doctor exit: $doctor_rc"
echo "Next:"
echo "  source .venv/bin/activate"
echo "  tgws-server run -c tgws-server.yaml -v"
echo "  python scripts/golden_connect.py"
echo
echo "Telegram Desktop: MTProto proxy 127.0.0.1:1443, secret from:"
echo "  tgws-server links -c tgws-server.yaml"
