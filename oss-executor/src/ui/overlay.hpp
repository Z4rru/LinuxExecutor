#pragma once

#include <gtk/gtk.h>
#include <cairo.h>
#include <map>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <functional>
#include <unordered_map>
#include "drawing_object.hpp"

namespace oss {

struct GuiElement {
    int id = 0;
    int parent_id = -1;
    std::string class_name;
    std::string name;

    float x = 0, y = 0, w = 100, h = 100;

    float pos_x_scale = 0, pos_x_offset = 0;
    float pos_y_scale = 0, pos_y_offset = 0;
    float size_x_scale = 0, size_x_offset = 100;
    float size_y_scale = 0, size_y_offset = 100;

    float anchor_x = 0, anchor_y = 0;

    float bg_r = 1, bg_g = 1, bg_b = 1;
    float bg_transparency = 0;
    float border_r = 0.11f, border_g = 0.11f, border_b = 0.11f;
    int border_size = 0;

    std::string text;
    float text_size = 14;
    float text_r = 0, text_g = 0, text_b = 0;
    float text_transparency = 0;
    float text_stroke_transparency = 1;
    float text_stroke_r = 0, text_stroke_g = 0, text_stroke_b = 0;
    int text_x_alignment = 1;
    int text_y_alignment = 1;
    bool text_wrapped = false;
    bool text_scaled = false;
    bool rich_text = false;

    std::string image;
    float image_r = 1, image_g = 1, image_b = 1;
    float image_transparency = 0;
    cairo_surface_t* image_surface = nullptr;

    float rotation = 0;
    float corner_radius = 0;
    bool clips_descendants = false;
    bool visible = true;
    int z_index = 1;
    int layout_order = 0;

    bool has_stroke = false;
    float stroke_thickness = 1;
    float stroke_r = 0, stroke_g = 0, stroke_b = 0;
    float stroke_transparency = 0;

    bool has_gradient = false;
    float gradient_rotation = 0;

    float pad_top = 0, pad_bottom = 0, pad_left = 0, pad_right = 0;

    float canvas_size_y = 0;
    float scroll_position = 0;
    bool scrolling_enabled = true;

    bool is_screen_gui = false;
    bool is_gui_object = false;
    bool is_text_class = false;
    bool is_image_class = false;
    bool enabled = true;
    int display_order = 0;
    bool ignore_gui_inset = false;

    std::vector<int> children_ids;
};

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

    int  create_object(DrawingObject::Type type);
    void create_object_with_id(int id, DrawingObject::Type type);
    void remove_object(int id);
    void clear_objects();
    void request_redraw();
    int  object_count() const;
    DrawingObject* get_object(int id);
    std::vector<DrawingObject> snapshot_objects() const;

    template<typename Func>
    void update_object(int id, Func&& fn) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(id);
        if (it != objects_.end()) {
            fn(it->second);
            dirty_.store(true, std::memory_order_release);
        }
    }

    int  create_gui_element(const std::string& class_name, const std::string& name);
    void remove_gui_element(int id);
    void clear_gui_elements();
    void set_gui_parent(int child_id, int parent_id);
    int  gui_element_count() const;

    template<typename Func>
    void update_gui_element(int id, Func&& fn) {
        std::lock_guard<std::mutex> lock(gui_mutex_);
        auto it = gui_elements_.find(id);
        if (it != gui_elements_.end()) {
            fn(it->second);
            gui_dirty_.store(true, std::memory_order_release);
            dirty_.store(true, std::memory_order_release);
        }
    }

    void set_custom_render(RenderCallback cb, void* ud);

    int screen_width() const { return screen_w_; }
    int screen_height() const { return screen_h_; }

private:
    Overlay() = default;
    ~Overlay() { shutdown(); }
    Overlay(const Overlay&) = delete;
    Overlay& operator=(const Overlay&) = delete;

    void detect_screen_size();
    void setup_passthrough();

    static gboolean tick_callback(gpointer data);
    static void draw_func(GtkDrawingArea* area, cairo_t* cr,
                          int width, int height, gpointer data);

    void render(cairo_t* cr, int width, int height);

    void render_line(cairo_t* cr, const DrawingObject& obj);
    void render_text(cairo_t* cr, const DrawingObject& obj);
    void render_circle(cairo_t* cr, const DrawingObject& obj);
    void render_square(cairo_t* cr, const DrawingObject& obj);
    void render_triangle(cairo_t* cr, const DrawingObject& obj);
    void render_quad(cairo_t* cr, const DrawingObject& obj);
    void render_image(cairo_t* cr, const DrawingObject& obj);

    void render_gui(cairo_t* cr, int width, int height);
    void resolve_gui_layout(GuiElement& elem, float parent_x, float parent_y,
                            float parent_w, float parent_h);
    void render_gui_element(cairo_t* cr, const GuiElement& elem);
    void render_gui_children(cairo_t* cr, const GuiElement& elem);
    void render_gui_text(cairo_t* cr, const GuiElement& elem);
    void render_gui_rounded_rect(cairo_t* cr, float x, float y, float w, float h, float r);

    mutable std::mutex gui_mutex_;
    std::unordered_map<int, GuiElement> gui_elements_;
    int gui_next_id_ = 1;
    std::atomic<bool> gui_dirty_{false};

    mutable std::mutex mutex_;
    std::map<int, DrawingObject> objects_;
    int next_id_ = 1;

    GtkWindow* window_ = nullptr;
    GtkWidget* drawing_area_ = nullptr;
    GtkCssProvider* css_provider_ = nullptr;
    guint tick_id_ = 0;

    bool initialized_ = false;
    std::atomic<bool> visible_{false};
    std::atomic<bool> dirty_{false};
    int screen_w_ = 1920, screen_h_ = 1080;
    unsigned long frame_count_ = 0;

    RenderCallback custom_render_ = nullptr;
    void* custom_render_ud_ = nullptr;
};

} // namespace oss
