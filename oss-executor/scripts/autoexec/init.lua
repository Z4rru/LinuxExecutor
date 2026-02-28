local name, version = identifyexecutor()
print(string.format("[Init] %s %s loaded", name, version))
print("[Init] HWID: " .. gethwid():sub(1, 16) .. "...")
print("[Init] Environment ready")

makefolder("workspace")
makefolder("cache")
