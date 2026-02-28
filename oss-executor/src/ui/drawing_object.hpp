// src/ui/drawing_object.hpp
#pragma once

#include <string>
#include <cstdint>

// Forward-declare so we don't pull in all of cairo.h
struct _cairo_surface;
typedef struct _cairo_surface cairo_surface_t;

struct DrawingObject {
    enum class Type {
        None = 0,
        Line,
        Text,
        Image,
        Circle,
        Square,
        Triangle,
        Quad
    };

    Type type = Type::None;

    // ── common properties ───────────────────────────────────────
    bool  visible      = true;
    int   z_index      = 0;
    float transparency = 0.0f;
    float thickness    = 1.0f;
    float rounding     = 0.0f;
    bool  filled       = false;
    bool  outline      = false;
    bool  center       = false;     // text center-alignment

    // ── generic position / size ─────────────────────────────────
    float pos_x  = 0.0f, pos_y  = 0.0f;
    float size_x = 0.0f, size_y = 0.0f;

    // ── line end-points ─────────────────────────────────────────
    float from_x = 0.0f, from_y = 0.0f;
    float to_x   = 0.0f, to_y   = 0.0f;

    // ── circle ──────────────────────────────────────────────────
    float radius    = 0.0f;
    int   num_sides = 0;

    // ── colour (RGB, 0-1) ───────────────────────────────────────
    float color_r   = 1.0f, color_g   = 1.0f, color_b   = 1.0f;
    float outline_r = 0.0f, outline_g = 0.0f, outline_b = 0.0f;

    // ── text ────────────────────────────────────────────────────
    std::string text;
    float       text_size = 14.0f;
    std::string font      = "monospace";

    // ── triangle vertices ───────────────────────────────────────
    float pa_x = 0.0f, pa_y = 0.0f;
    float pb_x = 0.0f, pb_y = 0.0f;
    float pc_x = 0.0f, pc_y = 0.0f;

    // ── quad vertices ───────────────────────────────────────────
    float qa_x = 0.0f, qa_y = 0.0f;
    float qb_x = 0.0f, qb_y = 0.0f;
    float qc_x = 0.0f, qc_y = 0.0f;
    float qd_x = 0.0f, qd_y = 0.0f;

    // ── image ───────────────────────────────────────────────────
    float            image_w       = 0.0f;
    float            image_h       = 0.0f;
    std::string      image_path;
    cairo_surface_t* image_surface = nullptr;
};
