#pragma once

#include <gtk/gtk.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <vector>

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

    int screen_width() const { return screen_w_; }
    int screen_height() const { return screen_h_; }

    using RenderCallback = void(*)(cairo_t*, int, int, void*);
    void set_custom_render(RenderCallback cb, void* ud);

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
    void render_quad(cairo_t* cr, const DrawingObject& obj);
    void render_image(cairo_t* cr, const DrawingObject& obj);
    void setup_passthrough();
    void detect_screen_size();

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
    int screen_w_ = 1920;
    int screen_h_ = 1080;
    uint64_t frame_count_ = 0;

    RenderCallback custom_render_ = nullptr;
    void* custom_render_ud_ = nullptr;
};

} // namespace oss
