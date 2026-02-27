#include "overlay.hpp"
#include <cmath>
#include <algorithm>
#include <cstring>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace oss {

Overlay& Overlay::instance() {
    static Overlay inst;
    return inst;
}

void Overlay::detect_screen_size() {
    GdkDisplay* display = gdk_display_get_default();
    if (!display) return;
    GListModel* monitors = gdk_display_get_monitors(display);
    guint n = g_list_model_get_n_items(monitors);
    if (n > 0) {
        GdkMonitor* mon = GDK_MONITOR(g_list_model_get_item(monitors, 0));
        if (mon) {
            GdkRectangle geom;
            gdk_monitor_get_geometry(mon, &geom);
            screen_w_ = geom.width;
            screen_h_ = geom.height;
            g_object_unref(mon);
        }
    }
}

void Overlay::init() {
    if (initialized_) return;

    detect_screen_size();

    window_ = GTK_WINDOW(gtk_window_new());
    gtk_window_set_title(window_, "");
    gtk_window_set_decorated(window_, FALSE);
    gtk_window_set_resizable(window_, FALSE);
    gtk_window_set_default_size(window_, screen_w_, screen_h_);

    css_provider_ = gtk_css_provider_new();
    const char* css =
        "window.oss-overlay, window.oss-overlay > * {"
        "  background: none; background-color: transparent;"
        "}";
#if GTK_CHECK_VERSION(4, 12, 0)
    gtk_css_provider_load_from_string(css_provider_, css);
#else
    gtk_css_provider_load_from_data(css_provider_, css, -1);
#endif
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(css_provider_),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 10);
    gtk_widget_add_css_class(GTK_WIDGET(window_), "oss-overlay");

    drawing_area_ = gtk_drawing_area_new();
    gtk_drawing_area_set_draw_func(
        GTK_DRAWING_AREA(drawing_area_), draw_func, this, nullptr);
    gtk_widget_set_hexpand(drawing_area_, TRUE);
    gtk_widget_set_vexpand(drawing_area_, TRUE);
    gtk_window_set_child(window_, drawing_area_);

    g_signal_connect(window_, "realize",
        G_CALLBACK(+[](GtkWidget*, gpointer data) {
            static_cast<Overlay*>(data)->setup_passthrough();
        }), this);

    tick_id_ = g_timeout_add(16, tick_callback, this);
    initialized_ = true;
}

void Overlay::shutdown() {
    if (!initialized_) return;
    if (tick_id_ > 0) { g_source_remove(tick_id_); tick_id_ = 0; }
    if (css_provider_) {
        gtk_style_context_remove_provider_for_display(
            gdk_display_get_default(), GTK_STYLE_PROVIDER(css_provider_));
        g_object_unref(css_provider_);
        css_provider_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, obj] : objects_) {
            if (obj.image_surface) {
                cairo_surface_destroy(obj.image_surface);
                obj.image_surface = nullptr;
            }
        }
        objects_.clear();
    }
    if (window_) { gtk_window_destroy(window_); window_ = nullptr; }
    drawing_area_ = nullptr;
    initialized_ = false;
    visible_.store(false, std::memory_order_release);
    custom_render_ = nullptr;
    custom_render_ud_ = nullptr;
}

void Overlay::show() {
    if (!window_ || !initialized_) return;
    gtk_widget_set_visible(GTK_WIDGET(window_), TRUE);
    visible_.store(true, std::memory_order_release);
    dirty_.store(true, std::memory_order_release);
}

void Overlay::hide() {
    if (!window_) return;
    gtk_widget_set_visible(GTK_WIDGET(window_), FALSE);
    visible_.store(false, std::memory_order_release);
}

void Overlay::toggle() {
    if (visible_.load(std::memory_order_acquire)) hide(); else show();
}

bool Overlay::is_visible() const {
    return visible_.load(std::memory_order_acquire);
}

int Overlay::create_object(DrawingObject::Type type) {
    std::lock_guard<std::mutex> lock(mutex_);
    int id = next_id_++;
    DrawingObject obj;
    obj.id = id;
    obj.type = type;
    objects_[id] = std::move(obj);
    dirty_.store(true, std::memory_order_release);
    return id;
}

void Overlay::remove_object(int id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = objects_.find(id);
    if (it != objects_.end()) {
        if (it->second.image_surface) {
            cairo_surface_destroy(it->second.image_surface);
        }
        objects_.erase(it);
        dirty_.store(true, std::memory_order_release);
    }
}

void Overlay::clear_objects() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, obj] : objects_) {
        if (obj.image_surface) {
            cairo_surface_destroy(obj.image_surface);
            obj.image_surface = nullptr;
        }
    }
    objects_.clear();
    dirty_.store(true, std::memory_order_release);
}

void Overlay::request_redraw() {
    dirty_.store(true, std::memory_order_release);
}

int Overlay::object_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(objects_.size());
}

DrawingObject* Overlay::get_object(int id) {
    auto it = objects_.find(id);
    if (it != objects_.end()) return &it->second;
    return nullptr;
}

std::vector<DrawingObject> Overlay::snapshot_objects() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DrawingObject> result;
    result.reserve(objects_.size());
    for (const auto& [id, obj] : objects_) {
        result.push_back(obj);
        if (result.back().image_surface) {
            cairo_surface_reference(result.back().image_surface);
        }
    }
    return result;
}

void Overlay::set_custom_render(RenderCallback cb, void* ud) {
    custom_render_ = cb;
    custom_render_ud_ = ud;
    dirty_.store(true, std::memory_order_release);
}

void Overlay::setup_passthrough() {
    if (!window_) return;
    GdkSurface* surface = gtk_native_get_surface(GTK_NATIVE(window_));
    if (surface) {
        cairo_region_t* empty = cairo_region_create();
        gdk_surface_set_input_region(surface, empty);
        cairo_region_destroy(empty);
    }
}

gboolean Overlay::tick_callback(gpointer data) {
    auto* self = static_cast<Overlay*>(data);
    if (!self->visible_.load(std::memory_order_acquire)) return G_SOURCE_CONTINUE;

    self->frame_count_++;

    bool needs = self->dirty_.exchange(false, std::memory_order_acq_rel);
    if (!needs && (self->frame_count_ % 4 == 0)) {
        needs = true;
    }

    if (needs && self->drawing_area_) {
        gtk_widget_queue_draw(self->drawing_area_);
    }
    return G_SOURCE_CONTINUE;
}

void Overlay::draw_func(GtkDrawingArea*, cairo_t* cr,
                        int width, int height, gpointer data) {
    static_cast<Overlay*>(data)->render(cr, width, height);
}

void Overlay::render(cairo_t* cr, int width, int height) {
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, 0, 0, 0, 0);
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

    if (custom_render_) {
        custom_render_(cr, width, height, custom_render_ud_);
    }

    std::vector<DrawingObject> vis;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        vis.reserve(objects_.size());
        for (const auto& [id, obj] : objects_) {
            if (obj.visible) vis.push_back(obj);
        }
    }

    std::sort(vis.begin(), vis.end(),
        [](const DrawingObject& a, const DrawingObject& b) {
            return a.z_index < b.z_index;
        });

    for (const auto& obj : vis) {
        cairo_save(cr);
        switch (obj.type) {
            case DrawingObject::Type::Line:     render_line(cr, obj); break;
            case DrawingObject::Type::Text:     render_text(cr, obj); break;
            case DrawingObject::Type::Circle:   render_circle(cr, obj); break;
            case DrawingObject::Type::Square:   render_square(cr, obj); break;
            case DrawingObject::Type::Triangle: render_triangle(cr, obj); break;
            case DrawingObject::Type::Quad:     render_quad(cr, obj); break;
            case DrawingObject::Type::Image:    render_image(cr, obj); break;
        }
        cairo_restore(cr);
    }
}

void Overlay::render_line(cairo_t* cr, const DrawingObject& obj) {
    double a = 1.0 - obj.transparency;
    if (a <= 0) return;
    cairo_set_source_rgba(cr, obj.color_r, obj.color_g, obj.color_b, a);
    cairo_set_line_width(cr, obj.thickness);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_move_to(cr, obj.from_x, obj.from_y);
    cairo_line_to(cr, obj.to_x, obj.to_y);
    cairo_stroke(cr);
}

void Overlay::render_text(cairo_t* cr, const DrawingObject& obj) {
    if (obj.text.empty()) return;
    double a = 1.0 - obj.transparency;
    if (a <= 0) return;

    const char* face = "Sans";
    cairo_font_weight_t weight = CAIRO_FONT_WEIGHT_NORMAL;
    switch (obj.font) {
        case 0: face = "Sans"; break;
        case 1: face = "Sans"; weight = CAIRO_FONT_WEIGHT_BOLD; break;
        case 2: face = "IBM Plex Sans"; break;
        case 3: face = "Monospace"; break;
        case 4: face = "JetBrains Mono"; break;
        case 5: face = "Serif"; break;
        default: face = "Sans"; break;
    }
    cairo_select_font_face(cr, face, CAIRO_FONT_SLANT_NORMAL, weight);
    cairo_set_font_size(cr, obj.text_size);

    cairo_text_extents_t ext;
    cairo_text_extents(cr, obj.text.c_str(), &ext);
    double x = obj.pos_x;
    double y = obj.pos_y + obj.text_size;
    if (obj.center) {
        x -= ext.width / 2.0;
        y -= ext.height / 2.0;
    }

    if (obj.outline) {
        cairo_set_source_rgba(cr, obj.outline_r, obj.outline_g, obj.outline_b, a);
        for (int dx = -1; dx <= 1; dx++) {
            for (int dy = -1; dy <= 1; dy++) {
                if (dx == 0 && dy == 0) continue;
                cairo_move_to(cr, x + dx, y + dy);
                cairo_show_text(cr, obj.text.c_str());
            }
        }
    }
    cairo_set_source_rgba(cr, obj.color_r, obj.color_g, obj.color_b, a);
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, obj.text.c_str());
}

void Overlay::render_circle(cairo_t* cr, const DrawingObject& obj) {
    double a = 1.0 - obj.transparency;
    if (a <= 0) return;
    cairo_set_source_rgba(cr, obj.color_r, obj.color_g, obj.color_b, a);
    int sides = std::max(obj.num_sides, 3);
    if (sides >= 32) {
        cairo_arc(cr, obj.pos_x, obj.pos_y, obj.radius, 0, 2.0 * M_PI);
    } else {
        for (int i = 0; i <= sides; i++) {
            double angle = (2.0 * M_PI * i) / sides;
            double px = obj.pos_x + obj.radius * std::cos(angle);
            double py = obj.pos_y + obj.radius * std::sin(angle);
            if (i == 0) cairo_move_to(cr, px, py);
            else cairo_line_to(cr, px, py);
        }
        cairo_close_path(cr);
    }
    if (obj.filled) {
        cairo_fill(cr);
    } else {
        cairo_set_line_width(cr, obj.thickness);
        cairo_stroke(cr);
    }
}

void Overlay::render_square(cairo_t* cr, const DrawingObject& obj) {
    double a = 1.0 - obj.transparency;
    if (a <= 0) return;
    cairo_set_source_rgba(cr, obj.color_r, obj.color_g, obj.color_b, a);
    double x = obj.pos_x, y = obj.pos_y;
    double w = obj.size_x, h = obj.size_y;
    if (obj.rounding > 0) {
        double r = std::min(obj.rounding, std::min(w, h) / 2.0);
        cairo_new_sub_path(cr);
        cairo_arc(cr, x + w - r, y + r,     r, -M_PI / 2.0, 0);
        cairo_arc(cr, x + w - r, y + h - r, r, 0,            M_PI / 2.0);
        cairo_arc(cr, x + r,     y + h - r, r, M_PI / 2.0,   M_PI);
        cairo_arc(cr, x + r,     y + r,     r, M_PI,          3.0 * M_PI / 2.0);
        cairo_close_path(cr);
    } else {
        cairo_rectangle(cr, x, y, w, h);
    }
    if (obj.filled) {
        cairo_fill(cr);
    } else {
        cairo_set_line_width(cr, obj.thickness);
        cairo_stroke(cr);
    }
}

void Overlay::render_triangle(cairo_t* cr, const DrawingObject& obj) {
    double a = 1.0 - obj.transparency;
    if (a <= 0) return;
    cairo_set_source_rgba(cr, obj.color_r, obj.color_g, obj.color_b, a);
    cairo_move_to(cr, obj.pa_x, obj.pa_y);
    cairo_line_to(cr, obj.pb_x, obj.pb_y);
    cairo_line_to(cr, obj.pc_x, obj.pc_y);
    cairo_close_path(cr);
    if (obj.filled) {
        cairo_fill(cr);
    } else {
        cairo_set_line_width(cr, obj.thickness);
        cairo_stroke(cr);
    }
}

void Overlay::render_quad(cairo_t* cr, const DrawingObject& obj) {
    double a = 1.0 - obj.transparency;
    if (a <= 0) return;
    cairo_set_source_rgba(cr, obj.color_r, obj.color_g, obj.color_b, a);
    cairo_move_to(cr, obj.qa_x, obj.qa_y);
    cairo_line_to(cr, obj.qb_x, obj.qb_y);
    cairo_line_to(cr, obj.qc_x, obj.qc_y);
    cairo_line_to(cr, obj.qd_x, obj.qd_y);
    cairo_close_path(cr);
    if (obj.filled) {
        cairo_fill(cr);
    } else {
        cairo_set_line_width(cr, obj.thickness);
        cairo_stroke(cr);
    }
}

void Overlay::render_image(cairo_t* cr, const DrawingObject& obj) {
    if (!obj.image_surface) return;
    double a = 1.0 - obj.transparency;
    if (a <= 0) return;

    int iw = cairo_image_surface_get_width(obj.image_surface);
    int ih = cairo_image_surface_get_height(obj.image_surface);
    if (iw <= 0 || ih <= 0) return;

    double tw = obj.image_w > 0 ? obj.image_w : iw;
    double th = obj.image_h > 0 ? obj.image_h : ih;
    double sx = tw / iw;
    double sy = th / ih;

    cairo_save(cr);
    cairo_translate(cr, obj.pos_x, obj.pos_y);
    cairo_scale(cr, sx, sy);
    cairo_set_source_surface(cr, obj.image_surface, 0, 0);
    cairo_paint_with_alpha(cr, a);
    cairo_restore(cr);
}

} // namespace oss
