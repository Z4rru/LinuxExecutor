#pragma once

#include <gtk/gtk.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>
#include <vector>
#include "../core/lua_engine.hpp"

namespace oss {

class Overlay {
public:
    static Overlay& instance();
    Overlay(const Overlay&) = delete;
    Overlay& operator=(const Overlay&) = delete;

    void init();
    void shutdown();
    void show();
    void hide();
    void toggle();
    bool is_visible() const;

    int create_object(DrawingObject::Type type);
    void remove_object(int id);
    void clear_objects();
    void request_redraw();
    int object_count() const;

    template<typename F>
    void update_object(int id, F&& func) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(id);
        if (it != objects_.end()) {
            func(it->second);
            dirty_.store(true, std::memory_order_release);
        }
    }

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
