# ◈ OSS Executor v2.0

**Open Source Softworks — Roblox Executor for Linux Mint**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20Mint-green.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![LuaJIT](https://img.shields.io/badge/engine-LuaJIT%202.1-orange.svg)

A transparent, open-source Roblox script executor built natively for Linux Mint. Powered by LuaJIT, GTK4, and the Quorum API.

---

## ⚡ Quick Install (Linux Mint / Ubuntu)

### One-Line Install
Copy and paste this into your terminal to download, build, and run automatically:

```bash
git clone https://github.com/Z4rru/oss-executor.git && cd oss-executor && chmod +x build.sh && ./build.sh && ./run.sh
Manual Install
If you prefer to run the steps individually:
# 1. Clone the repository
git clone https://github.com/Z4rru/oss-executor.git
cd oss-executor

# 2. Build (auto-installs dependencies)
chmod +x build.sh run.sh
./build.sh

# 3. Run
./run.sh
```
Download Pre-Built Binary
Go to Releases and download the latest .tar.gz for your system.
✨ Features
Feature	Status
LuaJIT Script Execution	✅
GTK4 Native UI	✅
Syntax Highlighting	✅
Multi-Tab Editor	✅
Console Output	✅
Script Hub (ScriptBlox)	✅
File System Functions	✅
HTTP Requests	✅
Auto-Execute Scripts	✅
Theme Engine (JSON)	✅
Process Memory Access	✅
Auto Roblox Detection	✅
Keyboard Shortcuts	✅
Clipboard Access	✅
AES-256 Encryption	✅
Logging System	✅
⌨️ Keybinds
Action	Shortcut
Execute Script	Ctrl+Enter
Save Script	Ctrl+S
Open Script	Ctrl+O
New Tab	Ctrl+T
Close Tab	Ctrl+W
Clear Editor	Ctrl+L
Inject	F5
Toggle Console	F12
Undo	Ctrl+Z
Redo	Ctrl+Y
📁 Project Structure
See ARCHITECTURE.md for detailed explanations.
🔧 Requirements
OS: Linux Mint 21+ / Ubuntu 22.04+
UI: GTK4 development libraries
Engine: LuaJIT 2.1
Network/Crypto: libcurl, OpenSSL
Build Tools: CMake 3.20+, Ninja
📜 License
MIT License — See LICENSE
