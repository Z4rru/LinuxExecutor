# ◈ OSS Executor v1.0
<img width="958" height="575" alt="image" src="https://github.com/user-attachments/assets/5e365f64-68b9-4e80-a550-7a693082ded9" />

![Uploading image.png…]()


**Open Source Softworks — Roblox Executor for Linux Mint**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20Mint%20%7C%20Ubuntu-green.svg)](#-requirements)
[![Build](https://img.shields.io/github/actions/workflow/status/Z4rru/oss-executor/build.yml?branch=main)](https://github.com/Z4rru/oss-executor/actions)
[![LuaJIT](https://img.shields.io/badge/engine-LuaJIT%202.1-orange.svg)](https://luajit.org)

A transparent, open-source Roblox script executor built natively for Linux Mint. Powered by LuaJIT, GTK4, and the Quorum API.

---

## ⚡ Quick Install (Linux Mint / Ubuntu)

### One-Line Install

Copy and paste this into your terminal to download, build, and run automatically:

```bash
git clone https://github.com/Z4rru/oss-executor.git && cd oss-executor && chmod +x build.sh && ./build.sh && ./run.sh
```
Manual Install
If you prefer to run the steps individually:

```bash
# 1. Clone the repository
git clone https://github.com/Z4rru/oss-executor.git
cd oss-executor

# 2. Build (auto-installs dependencies)
chmod +x build.sh run.sh
./build.sh

# 3. Run
./run.sh
```
### Download Pre-Built Binary
[Go to Releases](https://github.com/Z4rru/oss-executor/releases) and download the latest `.tar.gz` for your system.

---

## ✨ Features

| Feature | Status |
| :--- | :---: |
| LuaJIT Script Execution | ✅ |
| GTK4 Native UI | ✅ |
| Syntax Highlighting | ✅ |
| Multi-Tab Editor | ✅ |
| Console Output | ✅ |
| Script Hub (ScriptBlox) | ✅ |
| File System Functions | ✅ |
| HTTP Requests | ✅ |
| Auto-Execute Scripts | ✅ |
| Theme Engine (JSON) | ✅ |
| Process Memory Access | ✅ |
| Auto Roblox Detection | ✅ |
| Keyboard Shortcuts | ✅ |
| Clipboard Access | ✅ |
| AES-256 Encryption | ✅ |
| Logging System | ✅ |

---

## ⌨️ Keybinds

| Action | Shortcut |
| :--- | :--- |
| Execute Script | `Ctrl`+`Enter` |
| Save Script | `Ctrl`+`S` |
| Open Script | `Ctrl`+`O` |
| New Tab | `Ctrl`+`T` |
| Close Tab | `Ctrl`+`W` |
| Clear Editor | `Ctrl`+`L` |
| Inject | `F5` |
| Toggle Console | `F12` |
| Undo | `Ctrl`+`Z` |
| Redo | `Ctrl`+`Y` |

---

## 📁 Project Structure
See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed explanations.

## 🔧 Requirements
*   **OS:** Linux Mint 21+ / Ubuntu 22.04+
*   **UI:** GTK4 development libraries
*   **Engine:** LuaJIT 2.1
*   **Network/Crypto:** libcurl, OpenSSL
*   **Build Tools:** CMake 3.20+, Ninja

## 📜 License
MIT License — See [LICENSE](LICENSE)



local line = Drawing.new("Line")
line.From = Vector2.new(100, 100)
line.To = Vector2.new(500, 500)
line.Color = Color3.fromRGB(255, 0, 0)
line.Thickness = 3
line.Visible = true

local text = Drawing.new("Text")
text.Text = "OSS Overlay Working"
text.Position = Vector2.new(200, 50)
text.Size = 24
text.Color = Color3.fromRGB(0, 255, 0)
text.Outline = true
text.Visible = true

local circle = Drawing.new("Circle")
circle.Position = Vector2.new(960, 540)
circle.Radius = 100
circle.Color = Color3.fromRGB(0, 150, 255)
circle.Thickness = 2
circle.Filled = false
circle.Visible = true

print("Drawing overlay test complete - 3 objects created")
