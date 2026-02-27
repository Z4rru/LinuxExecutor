// ═══════════════════════════════════════════════════════════════
// FIX #8: hooks.cpp is intentionally minimal.
//
// The Injection class handles process attachment and memory
// operations directly via /proc/pid/mem. The hooks system
// is a placeholder for future Roblox function hooking
// (e.g., intercepting Luau VM calls).
//
// This file exists because CMakeLists.txt lists it in SOURCES.
// If hooks.hpp has no non-inline methods, this compiles to
// an empty translation unit — which is valid C++.
// ═══════════════════════════════════════════════════════════════

#include "hooks.hpp"

// Placeholder — implement when Roblox hooking is added
