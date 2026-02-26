#include "script_hub.hpp"
#include "utils/logger.hpp"

namespace oss {

ScriptHub::ScriptHub() {
    container_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_start(container_, 4);
    gtk_widget_set_margin_end(container_, 4);
    gtk_widget_set_margin_top(container_, 4);
    
    // Header
    GtkWidget* header = gtk_label_new("Script Hub");
    gtk_widget_add_css_class(header, "heading");
    gtk_box_append(GTK_BOX(container_), header);
    
    // Search
    search_entry_ = gtk_search_entry_new();
    gtk_widget_add_css_class(search_entry_, "search-entry");
    gtk_widget_set_margin_bottom(search_entry_, 4);
    
    g_signal_connect_swapped(search_entry_, "search-changed",
        G_CALLBACK(+[](gpointer data) {
            auto* self = static_cast<ScriptHub*>(data);
            const char* text = gtk_editable_get_text(GTK_EDITABLE(self->search_entry_));
            if (strlen(text) >= 2) {
                self->search(text);
            }
        }), this);
    
    gtk_box_append(GTK_BOX(container_), search_entry_);
    
    // Script list
    scroll_ = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll_, TRUE);
    
    list_box_ = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list_box_), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(list_box_, "script-list");
    
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll_), list_box_);
    gtk_box_append(GTK_BOX(container_), scroll_);
    
    // Status
    status_label_ = gtk_label_new("Search for scripts or browse trending");
    gtk_widget_add_css_class(status_label_, "dim-label");
    gtk_box_append(GTK_BOX(container_), status_label_);
    
    // Load trending on start
    load_trending();
}

ScriptHub::~ScriptHub() {}

void ScriptHub::search(const std::string& query) {
    gtk_label_set_text(GTK_LABEL(status_label_), "Searching...");
    
    // Run search async
    auto* self = this;
    auto* q = new std::string(query);
    
    g_thread_new("search", [](gpointer data) -> gpointer {
        auto* pair = static_cast<std::pair<ScriptHub*, std::string*>*>(data);
        auto results = QuorumAPI::instance().search_scripts(*pair->second);
        
        g_idle_add([](gpointer data) -> gboolean {
            auto* pair = static_cast<std::pair<ScriptHub*, std::vector<ScriptInfo>*>*>(data);
            pair->first->populate_list(*pair->second);
            delete pair->second;
            delete pair;
            return G_SOURCE_REMOVE;
        }, new std::pair<ScriptHub*, std::vector<ScriptInfo>*>(pair->first, new std::vector<ScriptInfo>(results)));
        
        delete pair->second;
        delete pair;
        return nullptr;
    }, new std::pair<ScriptHub*, std::string*>(self, q));
}

void ScriptHub::load_trending() {
    gtk_label_set_text(GTK_LABEL(status_label_), "Loading trending...");
    
    auto* self = this;
    g_thread_new("trending", [](gpointer data) -> gpointer {
        auto* hub = static_cast<ScriptHub*>(data);
        auto results = QuorumAPI::instance().get_trending();
        
        g_idle_add([](gpointer data) -> gboolean {
            auto* pair = static_cast<std::pair<ScriptHub*, std::vector<ScriptInfo>*>*>(data);
            pair->first->populate_list(*pair->second);
            delete pair->second;
            delete pair;
            return G_SOURCE_REMOVE;
        }, new std::pair<ScriptHub*, std::vector<ScriptInfo>*>(hub, new std::vector<ScriptInfo>(results)));
        
        return nullptr;
    }, self);
}

void ScriptHub::refresh() {
    const char* text = gtk_editable_get_text(GTK_EDITABLE(search_entry_));
    if (strlen(text) >= 2) {
        search(text);
    } else {
        load_trending();
    }
}

void ScriptHub::populate_list(const std::vector<ScriptInfo>& scripts) {
    current_scripts_ = scripts;
    
    // Clear existing items
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
        
        size_t idx = i;
        g_signal_connect_swapped(load_btn, "clicked", G_CALLBACK(+[](gpointer data) {
            auto* pair = static_cast<std::pair<ScriptHub*, size_t>*>(data);
            if (pair->second < pair->first->current_scripts_.size()) {
                if (pair->first->load_cb_) {
                    pair->first->load_cb_(pair->first->current_scripts_[pair->second].script);
                }
            }
            delete pair;
        }), new std::pair<ScriptHub*, size_t>(this, idx));
        
        gtk_box_append(GTK_BOX(btn_box), load_btn);
        gtk_box_append(GTK_BOX(row), btn_box);
        
        gtk_list_box_append(GTK_LIST_BOX(list_box_), row);
    }
    
    std::string status = std::to_string(scripts.size()) + " scripts found";
    gtk_label_set_text(GTK_LABEL(status_label_), status.c_str());
}

} // namespace oss