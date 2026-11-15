#!/usr/bin/env bash
set -euo pipefail
root=${S2G_ROOT:-/opt/s2gdu}
mkdir -p "$root/app" "$root/tools/s2gdu" "$root/tools/nuget"
docker run --rm -v "$PWD:/src" -v "$root:$root" -w /src \
  -e NUGET_PACKAGES="$root/tools/nuget" mcr.microsoft.com/dotnet/sdk:10.0 \
  bash -euc "dotnet publish S2GDU.csproj -c Release -r linux-x64 --self-contained true -o '$root/tools/s2gdu'; \
    dotnet publish S2GDU.Automation -c Release -r linux-x64 --self-contained true -o '$root/app'"
docker build -t s2gdu-linux:local -f S2GDU.Automation/deploy/Dockerfile.linux "$root/tools/s2gdu"
