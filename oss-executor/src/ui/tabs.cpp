#include "tabs.hpp"

namespace oss {

TabManager::TabManager() {
    container_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_add_css_class(container_, "tab-bar");
    gtk_widget_set_hexpand(container_, TRUE);
    
    tab_box_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(tab_box_, TRUE);
    gtk_box_append(GTK_BOX(container_), tab_box_);
    
    // Add tab button
    add_btn_ = gtk_button_new_with_label("+");
    gtk_widget_add_css_class(add_btn_, "tab-button");
    gtk_widget_set_tooltip_text(add_btn_, "New Tab (Ctrl+T)");
    
    g_signal_connect_swapped(add_btn_, "clicked", G_CALLBACK(+[](gpointer data) {
        auto* self = static_cast<TabManager*>(data);
        int id = self->add_tab();
        self->set_active(id);
    }), this);
    
    gtk_box_append(GTK_BOX(container_), add_btn_);
}

TabManager::~TabManager() {}

int TabManager::add_tab(const std::string& title, const std::string& content) {
    Tab tab;
    tab.id = next_id_++;
    tab.title = title.empty() ? "Script " + std::to_string(tab.id) : title;
    tab.content = content;
    
    tabs_.push_back(tab);
    rebuild_ui();
    
    return tab.id;
}

void TabManager::remove_tab(int id) {
    if (tabs_.size() <= 1) return; // Keep at least one tab
    
    // Save current tab content before removing
    if (content_provider_ && active_id_ == id) {
        for (auto& tab : tabs_) {
            if (tab.id == id) {
                tab.content = content_provider_();
                break;
            }
        }
    }
    
    tabs_.erase(std::remove_if(tabs_.begin(), tabs_.end(),
        [id](const Tab& t) { return t.id == id; }), tabs_.end());
    
    if (active_id_ == id && !tabs_.empty()) {
        set_active(tabs_.back().id);
    }
    
    rebuild_ui();
}

void TabManager::set_active(int id) {
    // Save current tab content
    if (content_provider_ && active_id_ != -1) {
        for (auto& tab : tabs_) {
            if (tab.id == active_id_) {
                tab.content = content_provider_();
                break;
            }
        }
    }
    
    active_id_ = id;
    rebuild_ui();
    
    if (change_cb_) change_cb_(id);
}

Tab* TabManager::get_tab(int id) {
    for (auto& tab : tabs_) {
        if (tab.id == id) return &tab;
    }
    return nullptr;
}

Tab* TabManager::active_tab() {
    return get_tab(active_id_);
}

void TabManager::set_tab_content(int id, const std::string& content) {
    for (auto& tab : tabs_) {
        if (tab.id == id) {
            tab.content = content;
            break;
        }
    }
}

void TabManager::set_tab_title(int id, const std::string& title) {
    for (auto& tab : tabs_) {
        if (tab.id == id) {
            tab.title = title;
            break;
        }
    }
    rebuild_ui();
}

void TabManager::set_tab_modified(int id, bool modified) {
    for (auto& tab : tabs_) {
        if (tab.id == id) {
            tab.modified = modified;
            break;
        }
    }
    rebuild_ui();
}

void TabManager::rebuild_ui() {
    // Remove all children from tab_box
    GtkWidget* child = gtk_widget_get_first_child(tab_box_);
    while (child) {
        GtkWidget* next = gtk_widget_get_next_sibling(child);
        gtk_box_remove(GTK_BOX(tab_box_), child);
        child = next;
    }
    
    for (auto& tab : tabs_) {
        GtkWidget* btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
        
        std::string label = tab.title;
        if (tab.modified) label += " •";
        
        GtkWidget* btn_label = gtk_label_new(label.c_str());
        gtk_box_append(GTK_BOX(btn_box), btn_label);
        
        // Close button (only if more than 1 tab)
        if (tabs_.size() > 1) {
            GtkWidget* close_btn = gtk_button_new_with_label("×");
            gtk_widget_add_css_class(close_btn, "tab-close");
            gtk_widget_set_margin_start(close_btn, 4);
            
            int tab_id = tab.id;
            auto* close_data = new std::pair<TabManager*, int>(this, tab_id);
            g_signal_connect_swapped(close_btn, "clicked", G_CALLBACK(+[](gpointer data) {
                auto* pair = static_cast<std::pair<TabManager*, int>*>(data);
                pair->first->remove_tab(pair->second);
                delete pair;
            }), close_data);
            
            gtk_box_append(GTK_BOX(btn_box), close_btn);
        }
        
        GtkWidget* tab_btn = gtk_button_new();
        gtk_button_set_child(GTK_BUTTON(tab_btn), btn_box);
        gtk_widget_add_css_class(tab_btn, "tab-button");
        
        if (tab.id == active_id_) {
            gtk_widget_add_css_class(tab_btn, "active");
        }
        
        int tab_id = tab.id;
        auto* tab_data = new std::pair<TabManager*, int>(this, tab_id);
        g_signal_connect_swapped(tab_btn, "clicked", G_CALLBACK(+[](gpointer data) {
            auto* pair = static_cast<std::pair<TabManager*, int>*>(data);
            pair->first->set_active(pair->second);
            delete pair;
        }), tab_data);
        
        tab.button = tab_btn;
        gtk_box_append(GTK_BOX(tab_box_), tab_btn);
    }
}

} // namespace oss
