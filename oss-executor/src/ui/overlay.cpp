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
    {
        std::lock_guard<std::mutex> lock(gui_mutex_);
        for (auto& [id, elem] : gui_elements_) {
            if (elem.image_surface) {
                cairo_surface_destroy(elem.image_surface);
                elem.image_surface = nullptr;
            }
        }
        gui_elements_.clear();
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

// ── Drawing Object API ──

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

void Overlay::create_object_with_id(int id, DrawingObject::Type type) {
    std::lock_guard<std::mutex> lock(mutex_);
    DrawingObject obj;
    obj.id   = id;
    obj.type = type;
    objects_[id] = std::move(obj);
    if (id >= next_id_) next_id_ = id + 1;
    dirty_.store(true, std::memory_order_release);
}

void Overlay::remove_object(int id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = objects_.find(id);
    if (it != objects_.end()) {
        if (it->second.image_surface)
            cairo_surface_destroy(it->second.image_surface);
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
        if (result.back().image_surface)
            cairo_surface_reference(result.back().image_surface);
    }
    return result;
}

// ── GUI Element API ──

int Overlay::create_gui_element(const std::string& class_name, const std::string& name) {
    std::lock_guard<std::mutex> lock(gui_mutex_);
    int id = gui_next_id_++;
    GuiElement elem;
    elem.id = id;
    elem.class_name = class_name;
    elem.name = name;

    // Classify
    if (class_name == "ScreenGui" || class_name == "BillboardGui" || class_name == "SurfaceGui") {
        elem.is_screen_gui = true;
        elem.visible = true;
        elem.enabled = true;
    } else if (class_name == "Frame" || class_name == "TextLabel" || class_name == "TextButton" ||
               class_name == "TextBox" || class_name == "ImageLabel" || class_name == "ImageButton" ||
               class_name == "ScrollingFrame" || class_name == "ViewportFrame" ||
               class_name == "CanvasGroup") {
        elem.is_gui_object = true;
    } else if (class_name == "UICorner" || class_name == "UIStroke" || class_name == "UIGradient" ||
               class_name == "UIPadding" || class_name == "UIListLayout" || class_name == "UIGridLayout" ||
               class_name == "UIScale" || class_name == "UIAspectRatioConstraint" ||
               class_name == "UISizeConstraint" || class_name == "UITextSizeConstraint") {
        // UI modifiers — not directly rendered but affect parent
        elem.is_gui_object = false;
    }

    if (class_name == "TextLabel" || class_name == "TextButton" || class_name == "TextBox") {
        elem.is_text_class = true;
    }
    if (class_name == "ImageLabel" || class_name == "ImageButton") {
        elem.is_image_class = true;
    }

    // Defaults per class
    if (elem.is_gui_object) {
        elem.bg_r = 1; elem.bg_g = 1; elem.bg_b = 1;
        elem.bg_transparency = 0;
        elem.size_x_offset = 100; elem.size_y_offset = 100;
    }
    if (class_name == "Frame") {
        elem.bg_r = 1; elem.bg_g = 1; elem.bg_b = 1;
    }
    if (elem.is_text_class) {
        elem.text_r = 0; elem.text_g = 0; elem.text_b = 0;
        elem.text_size = 14;
        elem.bg_transparency = 0;
    }

    gui_elements_[id] = std::move(elem);
    gui_dirty_.store(true, std::memory_order_release);
    dirty_.store(true, std::memory_order_release);
    return id;
}

void Overlay::remove_gui_element(int id) {
    std::lock_guard<std::mutex> lock(gui_mutex_);
    auto it = gui_elements_.find(id);
    if (it == gui_elements_.end()) return;

    // Remove from parent's children list
    if (it->second.parent_id > 0) {
        auto pit = gui_elements_.find(it->second.parent_id);
        if (pit != gui_elements_.end()) {
            auto& cv = pit->second.children_ids;
            cv.erase(std::remove(cv.begin(), cv.end(), id), cv.end());
        }
    }

    // Recursively remove children
    std::vector<int> to_remove = it->second.children_ids;
    if (it->second.image_surface)
        cairo_surface_destroy(it->second.image_surface);
    gui_elements_.erase(it);

    for (int cid : to_remove) {
        auto cit = gui_elements_.find(cid);
        if (cit != gui_elements_.end()) {
            if (cit->second.image_surface)
                cairo_surface_destroy(cit->second.image_surface);
            // Collect grandchildren
            for (int gcid : cit->second.children_ids)
                to_remove.push_back(gcid);
            gui_elements_.erase(cit);
        }
    }

    gui_dirty_.store(true, std::memory_order_release);
    dirty_.store(true, std::memory_order_release);
}

void Overlay::clear_gui_elements() {
    std::lock_guard<std::mutex> lock(gui_mutex_);
    for (auto& [id, elem] : gui_elements_) {
        if (elem.image_surface) {
            cairo_surface_destroy(elem.image_surface);
            elem.image_surface = nullptr;
        }
    }
    gui_elements_.clear();
    gui_dirty_.store(true, std::memory_order_release);
    dirty_.store(true, std::memory_order_release);
}

void Overlay::set_gui_parent(int child_id, int parent_id) {
    std::lock_guard<std::mutex> lock(gui_mutex_);
    auto cit = gui_elements_.find(child_id);
    if (cit == gui_elements_.end()) return;

    // Remove from old parent
    if (cit->second.parent_id > 0) {
        auto opit = gui_elements_.find(cit->second.parent_id);
        if (opit != gui_elements_.end()) {
            auto& cv = opit->second.children_ids;
            cv.erase(std::remove(cv.begin(), cv.end(), child_id), cv.end());
        }
    }

    cit->second.parent_id = parent_id;

    // Add to new parent
    if (parent_id > 0) {
        auto pit = gui_elements_.find(parent_id);
        if (pit != gui_elements_.end()) {
            pit->second.children_ids.push_back(child_id);

            // If child is UICorner, apply corner radius to parent
            if (cit->second.class_name == "UICorner") {
                // Default UICorner radius is 8px
                pit->second.corner_radius = 8;
            }
            // If child is UIStroke, apply stroke to parent
            else if (cit->second.class_name == "UIStroke") {
                pit->second.has_stroke = true;
                pit->second.stroke_thickness = cit->second.stroke_thickness;
                pit->second.stroke_r = cit->second.stroke_r;
                pit->second.stroke_g = cit->second.stroke_g;
                pit->second.stroke_b = cit->second.stroke_b;
                pit->second.stroke_transparency = cit->second.stroke_transparency;
            }
            // If child is UIPadding, apply padding to parent
            else if (cit->second.class_name == "UIPadding") {
                pit->second.pad_top = cit->second.pad_top;
                pit->second.pad_bottom = cit->second.pad_bottom;
                pit->second.pad_left = cit->second.pad_left;
                pit->second.pad_right = cit->second.pad_right;
            }
        }
    }

    gui_dirty_.store(true, std::memory_order_release);
    dirty_.store(true, std::memory_order_release);
}

int Overlay::gui_element_count() const {
    std::lock_guard<std::mutex> lock(gui_mutex_);
    return static_cast<int>(gui_elements_.size());
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
    if (!needs && (self->frame_count_ % 4 == 0))
        needs = true;

    if (needs && self->drawing_area_)
        gtk_widget_queue_draw(self->drawing_area_);

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

    if (custom_render_)
        custom_render_(cr, width, height, custom_render_ud_);

    // Render GUI elements first (behind Drawing objects, matching Roblox layering)
    render_gui(cr, width, height);

    // Render Drawing objects on top
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

// ── GUI Rendering ──

void Overlay::render_gui(cairo_t* cr, int width, int height) {
    // Collect all ScreenGui roots, sorted by DisplayOrder
    std::vector<const GuiElement*> roots;
    {
        std::lock_guard<std::mutex> lock(gui_mutex_);

        // First resolve all layouts
        for (auto& [id, elem] : gui_elements_) {
            if (elem.is_screen_gui && elem.enabled && elem.visible) {
                // Resolve layout for this tree
                float inset_top = elem.ignore_gui_inset ? 0.0f : 36.0f;
                resolve_gui_layout(elem, 0, inset_top,
                    static_cast<float>(width),
                    static_cast<float>(height) - inset_top);
            }
        }

        for (const auto& [id, elem] : gui_elements_) {
            if (elem.is_screen_gui && elem.enabled && elem.visible)
                roots.push_back(&elem);
        }

        std::sort(roots.begin(), roots.end(),
            [](const GuiElement* a, const GuiElement* b) {
                return a->display_order < b->display_order;
            });

        // Render each tree
        for (const auto* root : roots) {
            render_gui_children(cr, *root);
        }
    }
}

void Overlay::resolve_gui_layout(GuiElement& elem,
                                  float parent_x, float parent_y,
                                  float parent_w, float parent_h) {
    if (elem.is_screen_gui) {
        // ScreenGui fills the screen
        elem.x = parent_x;
        elem.y = parent_y;
        elem.w = parent_w;
        elem.h = parent_h;
    } else if (elem.is_gui_object) {
        // Resolve UDim2 Size
        elem.w = elem.size_x_scale * parent_w + elem.size_x_offset;
        elem.h = elem.size_y_scale * parent_h + elem.size_y_offset;

        // Resolve UDim2 Position
        float px = elem.pos_x_scale * parent_w + elem.pos_x_offset;
        float py = elem.pos_y_scale * parent_h + elem.pos_y_offset;

        // Apply AnchorPoint
        px -= elem.anchor_x * elem.w;
        py -= elem.anchor_y * elem.h;

        elem.x = parent_x + px;
        elem.y = parent_y + py;
    }

    // Apply padding to children area
    float child_x = elem.x + elem.pad_left;
    float child_y = elem.y + elem.pad_top;
    float child_w = elem.w - elem.pad_left - elem.pad_right;
    float child_h = elem.h - elem.pad_top - elem.pad_bottom;
    if (child_w < 0) child_w = 0;
    if (child_h < 0) child_h = 0;

    // Check for UIListLayout among children
    bool has_list_layout = false;
    bool vertical_layout = true;
    float layout_padding = 0;
    for (int cid : elem.children_ids) {
        auto it = gui_elements_.find(cid);
        if (it != gui_elements_.end() && it->second.class_name == "UIListLayout") {
            has_list_layout = true;
            // FillDirection check (simplified)
            layout_padding = it->second.pad_top; // Reuse pad_top for Padding UDim offset
            break;
        }
    }

    float layout_offset = 0;

    // Collect and sort children by LayoutOrder/ZIndex for layout
    struct ChildSort { int id; int layout_order; int z_index; };
    std::vector<ChildSort> sorted_children;
    for (int cid : elem.children_ids) {
        auto it = gui_elements_.find(cid);
        if (it != gui_elements_.end() && it->second.is_gui_object)
            sorted_children.push_back({cid, it->second.layout_order, it->second.z_index});
    }
    if (has_list_layout) {
        std::sort(sorted_children.begin(), sorted_children.end(),
            [](const ChildSort& a, const ChildSort& b) {
                return a.layout_order < b.layout_order;
            });
    }

    // Resolve children
    for (const auto& cs : sorted_children) {
        auto it = gui_elements_.find(cs.id);
        if (it == gui_elements_.end()) continue;
        auto& child = it->second;

        if (has_list_layout && child.is_gui_object) {
            // Override position for list layout
            if (vertical_layout) {
                child.pos_x_scale = 0; child.pos_x_offset = 0;
                child.pos_y_scale = 0; child.pos_y_offset = layout_offset;
                resolve_gui_layout(child, child_x, child_y, child_w, child_h);
                layout_offset += child.h + layout_padding;
            } else {
                child.pos_x_offset = layout_offset;
                child.pos_y_scale = 0; child.pos_y_offset = 0;
                resolve_gui_layout(child, child_x, child_y, child_w, child_h);
                layout_offset += child.w + layout_padding;
            }
        } else {
            resolve_gui_layout(child, child_x, child_y, child_w, child_h);
        }
    }

    // Also resolve non-gui-object children (UICorner etc don't need layout but
    // their children might)
    for (int cid : elem.children_ids) {
        auto it = gui_elements_.find(cid);
        if (it != gui_elements_.end() && !it->second.is_gui_object) {
            // UI modifiers don't need layout resolution
        }
    }
}

void Overlay::render_gui_element(cairo_t* cr, const GuiElement& elem) {
    if (!elem.visible || !elem.is_gui_object) return;

    float alpha_bg = 1.0f - elem.bg_transparency;

    cairo_save(cr);

    // Clipping
    if (elem.clips_descendants) {
        if (elem.corner_radius > 0) {
            render_gui_rounded_rect(cr, elem.x, elem.y, elem.w, elem.h, elem.corner_radius);
            cairo_clip(cr);
        } else {
            cairo_rectangle(cr, elem.x, elem.y, elem.w, elem.h);
            cairo_clip(cr);
        }
    }

    // Rotation
    if (std::fabs(elem.rotation) > 0.01f) {
        float cx = elem.x + elem.w / 2.0f;
        float cy = elem.y + elem.h / 2.0f;
        cairo_translate(cr, cx, cy);
        cairo_rotate(cr, elem.rotation * M_PI / 180.0);
        cairo_translate(cr, -cx, -cy);
    }

    // Background
    if (alpha_bg > 0.001f) {
        cairo_set_source_rgba(cr, elem.bg_r, elem.bg_g, elem.bg_b, alpha_bg);
        if (elem.corner_radius > 0) {
            render_gui_rounded_rect(cr, elem.x, elem.y, elem.w, elem.h, elem.corner_radius);
            cairo_fill(cr);
        } else {
            cairo_rectangle(cr, elem.x, elem.y, elem.w, elem.h);
            cairo_fill(cr);
        }
    }

    // Border
    if (elem.border_size > 0) {
        float ba = 1.0f; // Border is always opaque in Roblox
        cairo_set_source_rgba(cr, elem.border_r, elem.border_g, elem.border_b, ba);
        cairo_set_line_width(cr, elem.border_size);
        if (elem.corner_radius > 0) {
            render_gui_rounded_rect(cr, elem.x, elem.y, elem.w, elem.h, elem.corner_radius);
            cairo_stroke(cr);
        } else {
            cairo_rectangle(cr, elem.x, elem.y, elem.w, elem.h);
            cairo_stroke(cr);
        }
    }

    // UIStroke
    if (elem.has_stroke && elem.stroke_thickness > 0) {
        float sa = 1.0f - elem.stroke_transparency;
        if (sa > 0.001f) {
            cairo_set_source_rgba(cr, elem.stroke_r, elem.stroke_g, elem.stroke_b, sa);
            cairo_set_line_width(cr, elem.stroke_thickness);
            if (elem.corner_radius > 0) {
                render_gui_rounded_rect(cr, elem.x, elem.y, elem.w, elem.h, elem.corner_radius);
                cairo_stroke(cr);
            } else {
                cairo_rectangle(cr, elem.x, elem.y, elem.w, elem.h);
                cairo_stroke(cr);
            }
        }
    }

    // Image
    if (elem.is_image_class && elem.image_surface) {
        float ia = 1.0f - elem.image_transparency;
        if (ia > 0.001f) {
            int iw = cairo_image_surface_get_width(elem.image_surface);
            int ih = cairo_image_surface_get_height(elem.image_surface);
            if (iw > 0 && ih > 0) {
                cairo_save(cr);
                if (elem.corner_radius > 0) {
                    render_gui_rounded_rect(cr, elem.x, elem.y, elem.w, elem.h, elem.corner_radius);
                    cairo_clip(cr);
                }
                double sx = elem.w / iw;
                double sy = elem.h / ih;
                cairo_translate(cr, elem.x, elem.y);
                cairo_scale(cr, sx, sy);
                cairo_set_source_surface(cr, elem.image_surface, 0, 0);
                cairo_paint_with_alpha(cr, ia);
                cairo_restore(cr);
            }
        }
    }

    // Text
    if (elem.is_text_class && !elem.text.empty()) {
        render_gui_text(cr, elem);
    }

    // Render children
    render_gui_children(cr, elem);

    cairo_restore(cr);
}

void Overlay::render_gui_children(cairo_t* cr, const GuiElement& elem) {
    // Sort children by ZIndex for rendering
    struct RenderChild { int id; int z_index; };
    std::vector<RenderChild> children;

    for (int cid : elem.children_ids) {
        auto it = gui_elements_.find(cid);
        if (it != gui_elements_.end() && it->second.is_gui_object)
            children.push_back({cid, it->second.z_index});
    }

    std::sort(children.begin(), children.end(),
        [](const RenderChild& a, const RenderChild& b) {
            return a.z_index < b.z_index;
        });

    for (const auto& rc : children) {
        auto it = gui_elements_.find(rc.id);
        if (it != gui_elements_.end())
            render_gui_element(cr, it->second);
    }
}

void Overlay::render_gui_text(cairo_t* cr, const GuiElement& elem) {
    float ta = 1.0f - elem.text_transparency;
    if (ta <= 0.001f) return;

    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, elem.text_size);

    cairo_text_extents_t ext;
    cairo_text_extents(cr, elem.text.c_str(), &ext);

    // Calculate text position based on alignment
    float tx = elem.x + elem.pad_left;
    float ty = elem.y + elem.pad_top;
    float content_w = elem.w - elem.pad_left - elem.pad_right;
    float content_h = elem.h - elem.pad_top - elem.pad_bottom;

    // X alignment
    switch (elem.text_x_alignment) {
        case 0: // Left
            tx += 2; // Small padding
            break;
        case 1: // Center
            tx += (content_w - static_cast<float>(ext.width)) / 2.0f;
            break;
        case 2: // Right
            tx += content_w - static_cast<float>(ext.width) - 2;
            break;
    }

    // Y alignment
    switch (elem.text_y_alignment) {
        case 0: // Top
            ty += elem.text_size;
            break;
        case 1: // Center
            ty += (content_h + elem.text_size) / 2.0f - 2;
            break;
        case 2: // Bottom
            ty += content_h - 2;
            break;
    }

    // Text stroke
    if (elem.text_stroke_transparency < 0.999f) {
        float sa = 1.0f - elem.text_stroke_transparency;
        cairo_set_source_rgba(cr, elem.text_stroke_r, elem.text_stroke_g, elem.text_stroke_b, sa);
        for (int dx = -1; dx <= 1; dx++) {
            for (int dy = -1; dy <= 1; dy++) {
                if (dx == 0 && dy == 0) continue;
                cairo_move_to(cr, tx + dx, ty + dy);
                cairo_show_text(cr, elem.text.c_str());
            }
        }
    }

    // Clip text to element bounds
    cairo_save(cr);
    cairo_rectangle(cr, elem.x, elem.y, elem.w, elem.h);
    cairo_clip(cr);

    cairo_set_source_rgba(cr, elem.text_r, elem.text_g, elem.text_b, ta);
    cairo_move_to(cr, tx, ty);
    cairo_show_text(cr, elem.text.c_str());

    cairo_restore(cr);
}

void Overlay::render_gui_rounded_rect(cairo_t* cr, float x, float y,
                                       float w, float h, float r) {
    r = std::min(r, std::min(w, h) / 2.0f);
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r,     r, -M_PI / 2.0, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0,            M_PI / 2.0);
    cairo_arc(cr, x + r,     y + h - r, r, M_PI / 2.0,   M_PI);
    cairo_arc(cr, x + r,     y + r,     r, M_PI,          3.0 * M_PI / 2.0);
    cairo_close_path(cr);
}

// ── Drawing Object Renderers (unchanged) ──

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
