// src/ui/drawing_object.hpp
#pragma once

#include <string>
#include <cairo.h>

namespace oss {

struct DrawingObject {
    enum class Type { Line, Text, Circle, Square, Triangle, Quad, Image };

    int id = 0;
    Type type = Type::Line;
    bool visible = true;
    int z_index = 0;

    double pos_x = 0, pos_y = 0;
    double from_x = 0, from_y = 0, to_x = 0, to_y = 0;
    double size_x = 0, size_y = 0;
    double radius = 0;
    double thickness = 1.0;
    double transparency = 0.0;
    double rounding = 0;
    int num_sides = 64;
    bool filled = true;
    bool center = false;
    bool outline = false;

    double color_r = 1.0, color_g = 1.0, color_b = 1.0;
    double outline_r = 0, outline_g = 0, outline_b = 0;

    double pa_x = 0, pa_y = 0;
    double pb_x = 0, pb_y = 0;
    double pc_x = 0, pc_y = 0;

    double qa_x = 0, qa_y = 0;
    double qb_x = 0, qb_y = 0;
    double qc_x = 0, qc_y = 0;
    double qd_x = 0, qd_y = 0;

    std::string text;
    double text_size = 16.0;
    int font = 0;

    std::string image_path;
    cairo_surface_t* image_surface = nullptr;
    double image_w = 0, image_h = 0;
};

} // namespace oss
