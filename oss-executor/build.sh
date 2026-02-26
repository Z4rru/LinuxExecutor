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
echo "║       Linux Mint Native Build                    ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

install_deps() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        build-essential cmake ninja-build git pkg-config \
        libgtk-4-dev libcurl4-openssl-dev libssl-dev \
        libgirepository1.0-dev fonts-jetbrains-mono \
        luajit libluajit-5.1-dev 2>/dev/null
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
    ninja -j$(nproc)
    
    echo -e "${GREEN}[✓] Build complete${NC}"
    cd ..
}

setup_dirs() {
    mkdir -p ~/.oss-executor/{scripts/autoexec,themes,logs,cache}
    cp -r scripts/* ~/.oss-executor/scripts/ 2>/dev/null || true
    cp -r themes/* ~/.oss-executor/themes/ 2>/dev/null || true
    cp -r resources ~/.oss-executor/ 2>/dev/null || true
    
    if [ ! -f ~/.oss-executor/config.json ]; then
        cp config.json ~/.oss-executor/config.json
    fi
    
    echo -e "${GREEN}[✓] Directory structure ready${NC}"
}

if ! command -v cmake &>/dev/null || ! pkg-config --exists gtk4 2>/dev/null; then
    install_deps
fi

build_project
setup_dirs

echo ""
echo -e "${GREEN}${BOLD}[✓] OSS Executor built successfully!${NC}"
echo -e "${CYAN}    Run: ./run.sh${NC}"