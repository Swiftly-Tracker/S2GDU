#!/usr/bin/env bash
set -euo pipefail
root=${S2G_ROOT:-/opt/s2gdu}
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl python3 7zip
mkdir -p "$root"/{tools/s2gdu,jobs,ida/linux,app,seed,cache,state/linux}
bash S2GDU.Automation/deploy/build.sh
test -f "$root/ida/linux/libidalib.so"
docker run --rm --entrypoint python3 -v "$root/ida/linux:/ida:ro" -v "$root/state/linux:/state" \
  -v "$PWD/S2GDU.Automation/deploy/accept_eula.py:/accept_eula.py:ro" \
  s2gdu-linux:local /accept_eula.py /ida /state
if [[ ! -f "$root/service.env" ]]; then
  umask 077
  python3 - "$root" <<'PY'
import pathlib, secrets, sys
root = pathlib.Path(sys.argv[1])
(root / 'service.env').write_text(f'S2G_ROOT={root}\nS2G_API_KEY={secrets.token_hex(32)}\nASPNETCORE_URLS=http://127.0.0.1:5080\n')
PY
fi
install -m 644 S2GDU.Automation/deploy/s2gdu.service /etc/systemd/system/s2gdu.service
systemctl daemon-reload
systemctl enable --now s2gdu
