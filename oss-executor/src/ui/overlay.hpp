// src/ui/overlay.hpp
#pragma once

#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>

#include <gtk/gtk.h>
#include <cairo.h>

#include "drawing_object.hpp"

namespace oss {

class Overlay {
public:
    using RenderCallback = void(*)(cairo_t*, int, int, void*);

    static Overlay& instance();

    void init();
    void shutdown();

    void show();
    void hide();
    void toggle();
    bool is_visible() const;

    // Create with auto-assigned ID (returns new ID)
    int  create_object(DrawingObject::Type type);

    // Create with a caller-chosen ID (used by LuaEngine)
    void create_object_with_id(int id, DrawingObject::Type type);

    void remove_object(int id);
    void clear_objects();
    void request_redraw();

    int  object_count() const;
    DrawingObject* get_object(int id);

    template<typename F>
    void update_object(int id, F&& func) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(id);
        if (it != objects_.end()) {
            func(it->second);
            dirty_.store(true, std::memory_order_release);
        }
    }

    std::vector<DrawingObject> snapshot_objects() const;

    void set_custom_render(RenderCallback cb, void* ud);

    int screen_width()  const { return screen_w_; }
    int screen_height() const { return screen_h_; }

private:
    Overlay() = default;
    ~Overlay() = default;
    Overlay(const Overlay&) = delete;
    Overlay& operator=(const Overlay&) = delete;

    void detect_screen_size();
    void setup_passthrough();

    static gboolean tick_callback(gpointer data);
    static void draw_func(GtkDrawingArea*, cairo_t* cr,
                          int width, int height, gpointer data);

    void render(cairo_t* cr, int width, int height);
    void render_line(cairo_t* cr, const DrawingObject& obj);
    void render_text(cairo_t* cr, const DrawingObject& obj);
    void render_circle(cairo_t* cr, const DrawingObject& obj);
    void render_square(cairo_t* cr, const DrawingObject& obj);
    void render_triangle(cairo_t* cr, const DrawingObject& obj);
    void render_quad(cairo_t* cr, const DrawingObject& obj);
    void render_image(cairo_t* cr, const DrawingObject& obj);

    bool initialized_ = false;
    int  screen_w_ = 1920;
    int  screen_h_ = 1080;

    GtkWindow*       window_       = nullptr;
    GtkCssProvider*  css_provider_ = nullptr;
    GtkWidget*       drawing_area_ = nullptr;
    guint            tick_id_      = 0;

    std::atomic<bool> visible_{false};
    std::atomic<bool> dirty_{false};
    uint64_t          frame_count_ = 0;

    mutable std::mutex mutex_;
    std::unordered_map<int, DrawingObject> objects_;
    int next_id_ = 1;

    RenderCallback custom_render_    = nullptr;
    void*          custom_render_ud_ = nullptr;
};

} // namespace oss
