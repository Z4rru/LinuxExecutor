#!/usr/bin/env bash
set -euo pipefail

export OSS_HOME="${HOME}/.oss-executor"
export GSK_RENDERER=gl

if [ ! -f build/OSSExecutor ]; then
    echo "[!] Not built yet. Running build..."
    bash build.sh
fi

exec ./build/OSSExecutor "$@"