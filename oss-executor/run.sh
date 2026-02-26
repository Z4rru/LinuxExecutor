#!/usr/bin/env bash
set -euo pipefail

export OSS_HOME="${HOME}/.oss-executor"

# ── GIO/GVFS isolation ──────────────────────────────────────
# Prevent loading system GIO modules compiled against a different
# GLib version. Fixes "undefined symbol: g_task_set_static_name"
export GIO_MODULE_DIR=""
export GIO_USE_VFS="local"

# ── Renderer fix for Linux Mint / Cinnamon ──────────────────
export GSK_RENDERER="${GSK_RENDERER:-gl}"

# ── GTK debug noise suppression ─────────────────────────────
export GTK_A11Y=none          # Suppress accessibility bus warnings
export NO_AT_BRIDGE=1         # Suppress AT-SPI bridge warnings

if [ ! -f build/OSSExecutor ]; then
    echo "[!] Not built yet. Running build..."
    bash build.sh
fi

echo "[*] Starting OSS Executor..."
exec ./build/OSSExecutor "$@"
