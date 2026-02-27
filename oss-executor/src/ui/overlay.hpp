#pragma once

#include <gtk/gtk.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>

namespace oss {

struct DrawingObject {
    enum class Type { Line, Text, Circle, Square, Triangle, Quad, Image };

    int id = 0;
    Type type = Type::Line;
    bool visible = false;

    float color_r = 1.0f, color_g = 1.0f, color_b = 1.0f;
    float transparency = 0.0f;
    float thickness = 1.0f;
    int z_index = 0;

    float from_x = 0, from_y = 0;
    float to_x = 0, to_y = 0;

    std::string text;
    float text_size = 14.0f;
    float pos_x = 0, pos_y = 0;
    bool center = false;
    bool outline = false;
    float outline_r = 0, outline_g = 0, outline_b = 0;
    int font = 0;

    float radius = 50.0f;
    int num_sides = 32;
    bool filled = false;

    float size_x = 100.0f, size_y = 100.0f;
    float rounding = 0;

    float pa_x = 0, pa_y = 0;
    float pb_x = 0, pb_y = 0;
    float pc_x = 0, pc_y = 0;
};

class Overlay {
public:
    static Overlay& instance();

    Overlay(const Overlay&) = delete;
    Overlay& operator=(const Overlay&) = delete;

    void init(GtkApplication* app);
    void shutdown();
    void show();
    void hide();
    void toggle();
    bool is_visible() const;

    int create_object(DrawingObject::Type type);
    void remove_object(int id);
    void clear_objects();
    void request_redraw();

    template<typename F>
    void update_object(int id, F&& func) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(id);
        if (it != objects_.end()) {
            func(it->second);
            dirty_ = true;
        }
    }

    int object_count() const;

private:
    Overlay() = default;
    ~Overlay() = default;

    static void draw_func(GtkDrawingArea* area, cairo_t* cr,
                          int width, int height, gpointer data);
    static gboolean tick_callback(gpointer data);

    void render(cairo_t* cr, int width, int height);
    void render_line(cairo_t* cr, const DrawingObject& obj);
    void render_text(cairo_t* cr, const DrawingObject& obj);
    void render_circle(cairo_t* cr, const DrawingObject& obj);
    void render_square(cairo_t* cr, const DrawingObject& obj);
    void render_triangle(cairo_t* cr, const DrawingObject& obj);
    void setup_passthrough();

    GtkWindow* window_ = nullptr;
    GtkWidget* drawing_area_ = nullptr;
    GtkCssProvider* css_provider_ = nullptr;

    std::unordered_map<int, DrawingObject> objects_;
    mutable std::mutex mutex_;
    int next_id_ = 1;
    guint tick_id_ = 0;
    std::atomic<bool> visible_{false};
    std::atomic<bool> dirty_{false};
    bool initialized_ = false;
};

} // namespace oss
