#!/usr/bin/env bash
set -euo pipefail
root=${S2G_ROOT:-/opt/s2gdu}
mkdir -p "$root"/{sources,tools,ida/linux}
base=https://github.com/Yigods/ida94_b1/releases/download/v9.4-installers
curl -fL --retry 3 -o "$root/tools/ida-linux.run" "$base/ida-pro_94_x64linux.run"
(cd "$root/tools"; sha256sum -c <<'SUMS'
ec59282dba8e72eca2a750b5514f3d6722022d8b29bfc0cebd29a6403d2db19a  ida-linux.run
SUMS
)
chmod +x "$root/tools/ida-linux.run"
"$root/tools/ida-linux.run" --mode unattended --prefix "$root/ida/linux" --activate_idalib 0
if [[ ${1:-} == --apply-source-patches ]]; then
  source_dir="$root/sources/ida94_b1"
  if [[ ! -d "$source_dir/.git" ]]; then git clone https://github.com/Yigods/ida94_b1.git "$source_dir"; fi
  git -C "$source_dir" fetch origin
  git -C "$source_dir" checkout --detach 0f05a79bbb52bdece0c358b758b4f0914d22e96e
  cp "$source_dir"/kg_patch/x64linux/libida*.so "$root/ida/linux/"
  (cd "$root/ida/linux"; python3 "$source_dir/kg_patch/全平台注册机IDA94b1.py")
fi
printf '%s\n' 'IDA installed. Supply licenses if needed, then run deploy/provision.sh.'
