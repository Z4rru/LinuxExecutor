#pragma once

#include "api/quorum_api.hpp"
#include <gtk/gtk.h>
#include <vector>
#include <functional>

namespace oss {

class ScriptHub {
public:
    using LoadCallback = std::function<void(const std::string& script)>;

    ScriptHub();
    ~ScriptHub();

    GtkWidget* widget() { return container_; }
    
    void set_load_callback(LoadCallback cb) { load_cb_ = std::move(cb); }
    
    void search(const std::string& query);
    void load_trending();
    void refresh();

private:
    void populate_list(const std::vector<ScriptInfo>& scripts);
    
    GtkWidget* container_;
    GtkWidget* search_entry_;
    GtkWidget* list_box_;
    GtkWidget* scroll_;
    GtkWidget* status_label_;
    
    LoadCallback load_cb_;
    std::vector<ScriptInfo> current_scripts_;
};

} // namespace oss