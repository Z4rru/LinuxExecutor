#pragma once

#include <gtk/gtk.h>
#include <string>
#include <vector>
#include <functional>

namespace oss {

struct Tab {
    std::string title;
    std::string content;
    std::string file_path;
    bool modified = false;
    GtkWidget* button = nullptr;
    int id;
};

class TabManager {
public:
    using TabChangeCallback = std::function<void(int tab_id)>;
    using ContentProvider = std::function<std::string()>;

    TabManager();
    ~TabManager();

    GtkWidget* widget() { return container_; }

    int add_tab(const std::string& title = "Script", const std::string& content = "");
    void remove_tab(int id);
    void set_active(int id);
    int active_id() const { return active_id_; }
    
    Tab* get_tab(int id);
    Tab* active_tab();
    
    void set_tab_content(int id, const std::string& content);
    void set_tab_title(int id, const std::string& title);
    void set_tab_modified(int id, bool modified);
    
    void set_change_callback(TabChangeCallback cb) { change_cb_ = std::move(cb); }
    void set_content_provider(ContentProvider cp) { content_provider_ = std::move(cp); }
    
    const std::vector<Tab>& tabs() const { return tabs_; }

private:
    void rebuild_ui();
    
    GtkWidget* container_;
    GtkWidget* tab_box_;
    GtkWidget* add_btn_;
    
    std::vector<Tab> tabs_;
    int active_id_ = -1;
    int next_id_ = 1;
    
    TabChangeCallback change_cb_;
    ContentProvider content_provider_;
};

} // namespace oss