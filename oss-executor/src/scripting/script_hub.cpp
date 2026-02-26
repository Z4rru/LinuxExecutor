#include "script_hub.hpp"
#include "utils/logger.hpp"
#include <cstring>

namespace oss {

// ── Plain structs replace std::pair to eliminate template commas ──
// Template commas inside preprocessor macros (G_CALLBACK, g_signal_connect_*)
// are parsed as macro argument separators, causing compilation failures.

struct SearchThreadData {
    ScriptHub* hub;
    std::string query;
};

struct ResultData {
    ScriptHub* hub;
    std::vector<ScriptInfo> scripts;
};

struct ButtonData {
    ScriptHub* hub;
    size_t index;
};

// ── Constructor ──────────────────────────────────────────────────

ScriptHub::ScriptHub() {
    container_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_start(container_, 4);
    gtk_widget_set_margin_end(container_, 4);
    gtk_widget_set_margin_top(container_, 4);

    // Header
    GtkWidget* header = gtk_label_new("Script Hub");
    gtk_widget_add_css_class(header, "heading");
    gtk_box_append(GTK_BOX(container_), header);

    // Search entry
    search_entry_ = gtk_search_entry_new();
    gtk_widget_add_css_class(search_entry_, "search-entry");
    gtk_widget_set_margin_bottom(search_entry_, 4);

    // NOTE: This g_signal_connect_swapped + G_CALLBACK is safe because
    // static_cast<ScriptHub*> has no comma in its template argument.
    g_signal_connect_swapped(search_entry_, "search-changed",
        G_CALLBACK(+[](gpointer data) {
            auto* self = static_cast<ScriptHub*>(data);
            const char* text = gtk_editable_get_text(
                GTK_EDITABLE(self->search_entry_));
            if (std::strlen(text) >= 2) {
                self->search(text);
            }
        }), this);

    gtk_box_append(GTK_BOX(container_), search_entry_);

    // Scrolled script list
    scroll_ = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll_, TRUE);

    list_box_ = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list_box_),
                                    GTK_SELECTION_NONE);
    gtk_widget_add_css_class(list_box_, "script-list");

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll_), list_box_);
    gtk_box_append(GTK_BOX(container_), scroll_);

    // Status bar
    status_label_ = gtk_label_new("Search for scripts or browse trending");
    gtk_widget_add_css_class(status_label_, "dim-label");
    gtk_box_append(GTK_BOX(container_), status_label_);

    load_trending();
}

ScriptHub::~ScriptHub() {}

// ── Async search ─────────────────────────────────────────────────

void ScriptHub::search(const std::string& query) {
    gtk_label_set_text(GTK_LABEL(status_label_), "Searching...");

    auto* data = new SearchThreadData{this, query};

    // g_thread_new is a function (not a macro), so template commas
    // inside the lambda body are harmless to the preprocessor.
    GThread* thread = g_thread_new("search", [](gpointer data) -> gpointer {
        auto* search_data = static_cast<SearchThreadData*>(data);
        auto results = QuorumAPI::instance().search_scripts(
            search_data->query);

        // Marshal results back to the main GTK thread
        auto* result = new ResultData{
            search_data->hub, std::move(results)};

        g_idle_add([](gpointer data) -> gboolean {
            auto* r = static_cast<ResultData*>(data);
            r->hub->populate_list(r->scripts);
            delete r;
            return G_SOURCE_REMOVE;
        }, result);

        delete search_data;
        return nullptr;
    }, data);

    // FIX: original leaked the GThread handle
    g_thread_unref(thread);
}

// ── Async trending ───────────────────────────────────────────────

void ScriptHub::load_trending() {
    gtk_label_set_text(GTK_LABEL(status_label_), "Loading trending...");

    GThread* thread = g_thread_new("trending", [](gpointer data) -> gpointer {
        auto* hub = static_cast<ScriptHub*>(data);
        auto results = QuorumAPI::instance().get_trending();

        auto* result = new ResultData{hub, std::move(results)};

        g_idle_add([](gpointer data) -> gboolean {
            auto* r = static_cast<ResultData*>(data);
            r->hub->populate_list(r->scripts);
            delete r;
            return G_SOURCE_REMOVE;
        }, result);

        return nullptr;
    }, this);

    // FIX: original leaked the GThread handle
    g_thread_unref(thread);
}

// ── Refresh ──────────────────────────────────────────────────────

void ScriptHub::refresh() {
    const char* text = gtk_editable_get_text(GTK_EDITABLE(search_entry_));
    if (std::strlen(text) >= 2) {
        search(text);
    } else {
        load_trending();
    }
}

// ── Populate list ────────────────────────────────────────────────

void ScriptHub::populate_list(const std::vector<ScriptInfo>& scripts) {
    current_scripts_ = scripts;

    // Clear existing rows
    GtkWidget* child = gtk_widget_get_first_child(list_box_);
    while (child) {
        GtkWidget* next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(list_box_), child);
        child = next;
    }

    if (scripts.empty()) {
        gtk_label_set_text(GTK_LABEL(status_label_), "No scripts found");
        return;
    }

    for (size_t i = 0; i < scripts.size(); i++) {
        const auto& script = scripts[i];

        GtkWidget* row = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_widget_set_margin_start(row, 8);
        gtk_widget_set_margin_end(row, 8);
        gtk_widget_set_margin_top(row, 4);
        gtk_widget_set_margin_bottom(row, 4);

        // Title
        GtkWidget* title = gtk_label_new(script.title.c_str());
        gtk_label_set_xalign(GTK_LABEL(title), 0);
        gtk_label_set_ellipsize(GTK_LABEL(title), PANGO_ELLIPSIZE_END);
        gtk_widget_add_css_class(title, "heading");
        gtk_box_append(GTK_BOX(row), title);

        // Info line
        std::string info = script.game + " • " + script.author + " • " +
                           std::to_string(script.views) + " views";
        if (script.verified) info += " ✓";

        GtkWidget* info_label = gtk_label_new(info.c_str());
        gtk_label_set_xalign(GTK_LABEL(info_label), 0);
        gtk_widget_add_css_class(info_label, "dim-label");
        gtk_box_append(GTK_BOX(row), info_label);

        // Load button
        GtkWidget* btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
        GtkWidget* load_btn = gtk_button_new_with_label("Load");
        gtk_widget_add_css_class(load_btn, "btn-secondary");

        auto* cb_data = new ButtonData{this, i};

        // FIX 1: Use g_signal_connect_data (a function, not a macro)
        //        instead of g_signal_connect_swapped (a macro).
        //        This eliminates the preprocessor comma problem entirely.
        //
        // FIX 2: G_CALLBACK body uses static_cast<ButtonData*> which
        //        contains zero template commas — safe inside the macro.
        //
        // FIX 3: destroy_data callback frees cb_data exactly once when
        //        the signal is disconnected or the widget is destroyed.
        //        Original code deleted on first click → use-after-free
        //        on any subsequent click.

        g_signal_connect_data(
            load_btn,
            "clicked",
            G_CALLBACK(+[](GtkButton*, gpointer data) {
                auto* info = static_cast<ButtonData*>(data);
                if (info->index < info->hub->current_scripts_.size()) {
                    if (info->hub->load_cb_) {
                        info->hub->load_cb_(
                            info->hub->current_scripts_[info->index].script);
                    }
                }
            }),
            cb_data,
            +[](gpointer data, GClosure*) {
                delete static_cast<ButtonData*>(data);
            },
            static_cast<GConnectFlags>(0)
        );

        gtk_box_append(GTK_BOX(btn_box), load_btn);
        gtk_box_append(GTK_BOX(row), btn_box);

        gtk_list_box_append(GTK_LIST_BOX(list_box_), row);
    }

    std::string status = std::to_string(scripts.size()) + " scripts found";
    gtk_label_set_text(GTK_LABEL(status_label_), status.c_str());
}

} // namespace oss
