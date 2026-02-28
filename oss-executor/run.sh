#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$SCRIPT_DIR"

export OSS_HOME="${HOME}/.oss-executor"

# ─── Fix GTK/ibus crash ──────────────────────────────────────────────
# Fixes: "undefined symbol: g_task_set_static_name"
# Fixes: "Failed to load module: libim-ibus.so"
export GTK_IM_MODULE=""
export XMODIFIERS=""
# ─────────────────────────────────────────────────────────────────────

export GIO_MODULE_DIR=""
export GIO_USE_VFS="local"

export GSK_RENDERER="${GSK_RENDERER:-gl}"

export GTK_A11Y=none
export NO_AT_BRIDGE=1

export LIBGL_DRI3_DISABLE=1
export EGL_LOG_LEVEL=fatal

# ─── Suppress noisy GLib debug output ────────────────────────────────
export G_MESSAGES_DEBUG=""
export GDK_DEBUG=""
# ─────────────────────────────────────────────────────────────────────

if [ ! -f build/OSSExecutor ]; then
    echo "[!] Not built yet. Running build..."
    bash build.sh
fi

echo "[*] Starting OSS Executor..."
exec ./build/OSSExecutor "$@"
