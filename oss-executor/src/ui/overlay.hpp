#pragma once

#include <string>
#include <cstdint>
#include <array>
#include <vector>
#include <cmath>
#include <algorithm>

namespace oss {

struct Color {
    double r = 1.0, g = 1.0, b = 1.0, a = 1.0;

    Color() = default;
    Color(double r_, double g_, double b_, double a_ = 1.0)
        : r(std::clamp(r_, 0.0, 1.0))
        , g(std::clamp(g_, 0.0, 1.0))
        , b(std::clamp(b_, 0.0, 1.0))
        , a(std::clamp(a_, 0.0, 1.0)) {}

    static Color from_hex(uint32_t hex, double alpha = 1.0) {
        return Color(
            ((hex >> 16) & 0xFF) / 255.0,
            ((hex >> 8) & 0xFF) / 255.0,
            (hex & 0xFF) / 255.0,
            alpha
        );
    }

    static Color from_rgba8(uint8_t r, uint8_t g, uint8_t b, uint8_t a = 255) {
        return Color(r / 255.0, g / 255.0, b / 255.0, a / 255.0);
    }

    bool operator==(const Color& o) const {
        return r == o.r && g == o.g && b == o.b && a == o.a;
    }
    bool operator!=(const Color& o) const { return !(*this == o); }
};

struct Vec2 {
    double x = 0.0, y = 0.0;
    Vec2() = default;
    Vec2(double x_, double y_) : x(x_), y(y_) {}

    Vec2 operator+(const Vec2& o) const { return {x + o.x, y + o.y}; }
    Vec2 operator-(const Vec2& o) const { return {x - o.x, y - o.y}; }
    Vec2 operator*(double s) const { return {x * s, y * s}; }
    double length() const { return std::sqrt(x * x + y * y); }
    double distance_to(const Vec2& o) const { return (*this - o).length(); }
};

struct Rect {
    double x = 0, y = 0, w = 0, h = 0;
    Rect() = default;
    Rect(double x_, double y_, double w_, double h_) : x(x_), y(y_), w(w_), h(h_) {}

    bool contains(double px, double py) const {
        return px >= x && px <= x + w && py >= y && py <= y + h;
    }
};

enum class DrawingType : uint8_t {
    None = 0,
    Line,
    Text,
    Circle,
    Rect,
    FilledRect,
    Triangle,
    Polygon,
    Arc,
    // Extensible
    Count
};

enum class FontFamily : uint8_t {
    Sans = 0,
    SansSerif = 1,
    Monospace = 2,
    Custom = 3
};

enum class TextAlign : uint8_t {
    Left = 0,
    Center = 1,
    Right = 2
};

enum class TextVAlign : uint8_t {
    Top = 0,
    Middle = 1,
    Bottom = 2
};

struct GradientStop {
    double offset;  // 0.0 - 1.0
    Color color;
};

struct Gradient {
    bool enabled = false;
    bool radial = false;       // false = linear
    Vec2 start{0, 0};
    Vec2 end{1, 0};           // for linear: direction; for radial: center
    double radius_inner = 0;   // radial only
    double radius_outer = 1;   // radial only
    std::vector<GradientStop> stops;
};

struct Shadow {
    bool enabled = false;
    Vec2 offset{2, 2};
    double blur = 4.0;
    Color color{0, 0, 0, 0.5};
};

struct DrawingObject {
    int32_t id = 0;
    DrawingType type = DrawingType::None;
    int32_t z_index = 0;
    bool visible = true;

    // Generation counter for change detection
    uint64_t generation = 0;

    // === Geometry ===
    // Position (used by most types)
    Vec2 pos{0, 0};

    // Line endpoints
    Vec2 from{0, 0};
    Vec2 to{0, 0};

    // Size (rect)
    Vec2 size{0, 0};

    // Circle/Arc
    double radius = 0;
    double arc_start = 0;      // radians
    double arc_end = 6.28318;  // 2*PI

    // Triangle vertices
    Vec2 pa{0, 0}, pb{0, 0}, pc{0, 0};

    // Polygon vertices
    std::vector<Vec2> vertices;

    // === Appearance ===
    Color color{1, 1, 1, 1};
    Color outline_color{0, 0, 0, 1};
    double thickness = 1.0;
    bool filled = false;
    bool outline = false;
    double outline_thickness = 1.0;
    double rounding = 0.0;     // corner rounding for rects
    int num_sides = 64;        // circle tessellation

    // === Text ===
    std::string text;
    double text_size = 14.0;
    FontFamily font = FontFamily::Sans;
    std::string custom_font;
    TextAlign align = TextAlign::Left;
    TextVAlign valign = TextVAlign::Top;
    bool bold = false;
    bool italic = false;

    // === Advanced ===
    Gradient gradient;
    Shadow shadow;
    double rotation = 0.0;    // radians, around pos
    double opacity = 1.0;     // master opacity multiplier

    // Effective alpha considering opacity
    double effective_alpha() const {
        return color.a * opacity;
    }

    // Dirty tracking helpers
    void mark_dirty() { generation++; }
};

// Sort comparator for z-ordering
struct DrawingObjectZSort {
    bool operator()(const DrawingObject& a, const DrawingObject& b) const {
        if (a.z_index != b.z_index) return a.z_index < b.z_index;
        return a.id < b.id;  // stable sort by creation order
    }
};

} // namespace oss
