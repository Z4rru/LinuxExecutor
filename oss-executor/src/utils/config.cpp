// ═══════════════════════════════════════════════════════════════
// FIX #5: config.hpp is fully header-only (all methods inline).
// This translation unit exists solely because CMakeLists.txt
// lists it in SOURCES.
//
// BEFORE: Had ~40 lines of commented-out code that duplicated
// the header implementation — confusing, looked like a bug.
//
// If config.hpp ever moves implementations out of the header,
// put them here.
// ═══════════════════════════════════════════════════════════════

#include "config.hpp"

// Intentionally empty — all implementation is in config.hpp
// This file ensures the header compiles as a translation unit
// and satisfies the CMakeLists.txt source list.
