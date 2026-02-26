-- OSS Executor Auto-Execute Init Script
-- This runs automatically when the executor starts

-- Verify environment
local name, version = identifyexecutor()
print(string.format("[Init] %s %s loaded", name, version))
print("[Init] HWID: " .. gethwid():sub(1, 16) .. "...")
print("[Init] Environment ready")

-- Create workspace if needed
makefolder("workspace")
makefolder("cache")