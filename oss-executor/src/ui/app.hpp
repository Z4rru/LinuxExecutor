#pragma once

#include <gtk/gtk.h>
#include <memory>
#include <string>

#include "console.hpp"
#include "editor.hpp"
#include "tabs.hpp"
#include "theme.hpp"
#include "file_dialog.hpp"
#include "scripting/script_hub.hpp"
#include "scripting/script_manager.hpp"
#include "core/executor.hpp"

#ifndef APP_VERSION
#define APP_VERSION "2.0.0"
#endif

namespace oss {

class App {
public:
    App(int argc, char** argv);
    ~App();

    App(const App&) = delete;
    App& operator=(const App&) = delete;

    int run();

private:
    void build_ui(GtkApplication* app);
    void apply_theme();
    void setup_keybinds();
    void connect_executor();
    void disconnect_executor();

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
    void update_status_bar();

    static gboolean on_tick(gpointer data);

    int argc_;
    char** argv_;
    GtkApplication* gtk_app_ = nullptr;
    GtkWindow* window_ = nullptr;

    GtkWidget* main_box_ = nullptr;
    GtkWidget* toolbar_ = nullptr;
    GtkWidget* paned_ = nullptr;
    GtkWidget* sidebar_paned_ = nullptr;
    GtkWidget* console_revealer_ = nullptr;
    GtkWidget* hub_revealer_ = nullptr;
    GtkWidget* status_bar_ = nullptr;
    GtkWidget* status_label_ = nullptr;
    GtkWidget* position_label_ = nullptr;

    std::unique_ptr<Editor> editor_;
    std::unique_ptr<Console> console_;
    std::unique_ptr<TabManager> tabs_;
    std::unique_ptr<ScriptHub> script_hub_;

    bool console_visible_ = true;
    bool hub_visible_ = false;
    bool injecting_ = false;  // guard against concurrent inject calls
    guint tick_id_ = 0;       // tracked so we can g_source_remove in dtor
};

} // namespace oss
