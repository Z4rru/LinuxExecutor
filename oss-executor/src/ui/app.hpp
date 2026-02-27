#pragma once

#include <gtk/gtk.h>
#include <string>
#include <memory>

#include "editor.hpp"
#include "console.hpp"
#include "tabs.hpp"
#include "theme.hpp"
#include "file_dialog.hpp"
#include "core/executor.hpp"
#include "scripting/script_manager.hpp"
#include "scripting/script_hub.hpp"

namespace oss {

class App {
public:
    App(int argc, char** argv);
    ~App();
    int run();

private:
    void build_ui(GtkApplication* app);
    void apply_theme();
    void setup_keybinds();
    void update_status_bar();

    void on_execute();
    void on_clear();
    void on_open_file();
    void on_save_file();
    void on_inject();
    void on_kill();
    void on_new_tab();
    void on_close_tab();
    void on_toggle_console();
    void on_toggle_hub();
    void on_toggle_overlay();

    static gboolean on_tick(gpointer data);

    GtkApplication* gtk_app_ = nullptr;
    GtkWindow* window_ = nullptr;

    std::unique_ptr<Editor> editor_;
    std::unique_ptr<Console> console_;
    std::unique_ptr<TabManager> tabs_;
    std::unique_ptr<ScriptHub> script_hub_;

    GtkWidget* main_box_ = nullptr;
    GtkWidget* toolbar_ = nullptr;
    GtkWidget* paned_ = nullptr;
    GtkWidget* status_bar_ = nullptr;
    GtkWidget* status_label_ = nullptr;
    GtkWidget* position_label_ = nullptr;
    GtkWidget* sidebar_paned_ = nullptr;
    GtkWidget* hub_revealer_ = nullptr;
    GtkWidget* console_revealer_ = nullptr;

    bool console_visible_ = true;
    bool hub_visible_ = false;

    int argc_;
    char** argv_;
};

} // namespace oss
