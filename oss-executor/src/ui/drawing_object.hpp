// src/ui/drawing_object.hpp
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <mutex>
#include <algorithm>

struct Color {
    float r = 1.0f;
    float g = 1.0f;
    float b = 1.0f;
    float a = 1.0f;

    Color() = default;
    Color(float r, float g, float b, float a = 1.0f)
        : r(r), g(g), b(b), a(a) {}

    static Color fromHex(uint32_t hex, float alpha = 1.0f) {
        return Color(
            ((hex >> 16) & 0xFF) / 255.0f,
            ((hex >> 8)  & 0xFF) / 255.0f,
            ( hex        & 0xFF) / 255.0f,
            alpha
        );
    }
};

struct Vec2 {
    float x = 0.0f;
    float y = 0.0f;

    Vec2() = default;
    Vec2(float x, float y) : x(x), y(y) {}
};

struct DrawingObject {
    // Nested enum so lua_engine.hpp can use DrawingObject::Type
    enum class Type {
        None = 0,
        Line,
        Rectangle,
        FilledRectangle,
        Circle,
        FilledCircle,
        Triangle,
        Text,
        Image
    };

    Type        type      = Type::None;
    Vec2        pos       = {};          // primary position / top-left
    Vec2        pos2      = {};          // end-point (lines) or size (rects)
    float       radius    = 0.0f;       // circles
    float       thickness = 1.0f;
    Color       color     = {};
    Color       outline_color = {0, 0, 0, 1};
    bool        outlined  = false;
    std::string text;                   // for Type::Text
    std::string font      = "monospace";
    float       font_size = 14.0f;
    int         z_order   = 0;
    bool        visible   = true;

    // Unique identifier assigned by the engine
    uint64_t    id        = 0;
};

/// Thread-safe container that the Lua engine pushes into and the
/// overlay/renderer drains each frame.
class DrawingObjectList {
public:
    void add(const DrawingObject& obj) {
        std::lock_guard<std::mutex> lk(mtx_);
        objects_.push_back(obj);
    }

    void remove(uint64_t id) {
        std::lock_guard<std::mutex> lk(mtx_);
        objects_.erase(
            std::remove_if(objects_.begin(), objects_.end(),
                [id](const DrawingObject& o){ return o.id == id; }),
            objects_.end());
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mtx_);
        objects_.clear();
    }

    /// Snapshot for the renderer – returns a copy so the lock is brief.
    std::vector<DrawingObject> snapshot() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return objects_;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return objects_.size();
    }

private:
    mutable std::mutex           mtx_;
    std::vector<DrawingObject>   objects_;
};
