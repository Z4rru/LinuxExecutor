#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║       OSS Executor — Build System v2.0           ║"
echo "║       Linux Native Build                         ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

check_glib_version() {
    local glib_ver
    glib_ver=$(pkg-config --modversion glib-2.0 2>/dev/null || echo "unknown")
    echo -e "${CYAN}[i] System GLib version: ${glib_ver}${NC}"

    local gvfs_lib="/usr/lib/x86_64-linux-gnu/gio/modules/libgvfsdbus.so"
    if [ -f "$gvfs_lib" ] && command -v objdump &>/dev/null; then
        local gvfs_needs
        gvfs_needs=$(objdump -T "$gvfs_lib" 2>/dev/null | grep -c "g_task_set_static_name" || true)
        if [ "$gvfs_needs" -gt 0 ]; then
            echo -e "${YELLOW}[!] System GVFS requires g_task_set_static_name (GLib 2.76+)"
            echo -e "    Build sets GIO_MODULE_DIR=\"\" to isolate from system GVFS${NC}"
        fi
    fi
}

install_deps() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        build-essential cmake ninja-build git pkg-config \
        libgtk-4-dev libcurl4-openssl-dev libssl-dev \
        libgirepository1.0-dev fonts-jetbrains-mono \
        luajit libluajit-5.1-dev \
        libspdlog-dev nlohmann-json3-dev \
        2>/dev/null || true

    echo -e "${GREEN}[✓] Dependencies installed${NC}"
}

build_project() {
    echo -e "${YELLOW}[*] Configuring build...${NC}"

    mkdir -p build
    cd build

    cmake .. \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local

    echo -e "${YELLOW}[*] Building...${NC}"
    ninja -j"$(nproc)"

    echo -e "${GREEN}[✓] Build complete${NC}"
    cd ..
}

setup_dirs() {
    local home="${HOME}/.oss-executor"
    mkdir -p "${home}"/{scripts/autoexec,themes,logs,cache,workspace}
    cp -r scripts/* "${home}/scripts/" 2>/dev/null || true
    cp -r themes/* "${home}/themes/" 2>/dev/null || true
    cp -r resources "${home}/" 2>/dev/null || true

    if [ ! -f "${home}/config.json" ]; then
        cp config.json "${home}/config.json" 2>/dev/null || true
    fi

    echo -e "${GREEN}[✓] Directory structure ready${NC}"
}

create_appimage_wrapper() {
    local appdir="$1"
    cat > "${appdir}/AppRun" << 'APPRUN_EOF'
#!/usr/bin/env bash
SELF_DIR="$(dirname "$(readlink -f "$0")")"

export GIO_MODULE_DIR=""
export GIO_USE_VFS="local"
export GSK_RENDERER="${GSK_RENDERER:-gl}"
export GTK_A11Y=none
export NO_AT_BRIDGE=1

if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    export DBUS_SESSION_BUS_ADDRESS="disabled:"
fi

if [ -d "${SELF_DIR}/usr/lib" ]; then
    export LD_LIBRARY_PATH="${SELF_DIR}/usr/lib:${LD_LIBRARY_PATH:-}"
fi

export OSS_HOME="${HOME}/.oss-executor"
exec "${SELF_DIR}/usr/bin/OSSExecutor" "$@"
APPRUN_EOF
    chmod +x "${appdir}/AppRun"
    echo -e "${GREEN}[✓] AppRun wrapper created${NC}"
}

check_glib_version

if ! command -v cmake &>/dev/null || ! pkg-config --exists gtk4 2>/dev/null; then
    install_deps
fi

build_project
setup_dirs

echo ""
echo -e "${GREEN}${BOLD}[✓] OSS Executor built successfully!${NC}"
echo -e "${CYAN}    Run: ./run.sh${NC}"
echo ""
echo -e "${CYAN}    If using AppImage and FUSE fails:${NC}"
echo -e "${CYAN}    ./OSS_Executor-x86_64.AppImage --appimage-extract-and-run${NC}"
