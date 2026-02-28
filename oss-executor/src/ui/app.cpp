#include "app.hpp"
#include "overlay.hpp"
#include "utils/logger.hpp"
#include "utils/config.hpp"
#include "api/environment.hpp"
#include "api/closures.hpp"

#include <fstream>
#include <filesystem>
#include <string>

namespace oss {

// ────────────────────── lifecycle ──────────────────────

App::App(int argc, char** argv) : argc_(argc), argv_(argv) {
#if GLIB_CHECK_VERSION(2, 74, 0)
    gtk_app_ = gtk_application_new("com.oss.executor", G_APPLICATION_DEFAULT_FLAGS);
#else
    gtk_app_ = gtk_application_new("com.oss.executor", G_APPLICATION_FLAGS_NONE);
#endif
    g_signal_connect(gtk_app_, "activate", G_CALLBACK(+[](GtkApplication* app, gpointer data) {
        static_cast<App*>(data)->build_ui(app);
    }), this);
}

App::~App() {
    // 1. Sever all executor→UI callbacks before any widget is gone
    disconnect_executor();

    // 2. Remove periodic tick so on_tick can't fire into dead members
    if (tick_id_ > 0) {
        g_source_remove(tick_id_);
        tick_id_ = 0;
    }

    // 3. Overlay is a singleton; shutdown is idempotent
    Overlay::instance().shutdown();

    // 4. unique_ptr<Editor/Console/TabManager/ScriptHub> destroy automatically

    // 5. Release GtkApplication ref
    if (gtk_app_) {
        g_object_unref(gtk_app_);
        gtk_app_ = nullptr;
    }
}

int App::run() {
    return g_application_run(G_APPLICATION(gtk_app_), argc_, argv_);
}

// ────────────────────── executor wiring ──────────────────────

void App::connect_executor() {
    auto& exec = Executor::instance();

    // Output from Lua print() → console Output pane
    exec.set_output_callback([this](const std::string& msg) {
        if (!console_) return;
        g_idle_add([](gpointer data) -> gboolean {
            auto* p = static_cast<std::pair<Console*, std::string>*>(data);
            p->first->print(p->second, Console::Level::Output);
            delete p;
            return G_SOURCE_REMOVE;
        }, new std::pair<Console*, std::string>(console_.get(), msg));
    });

    // Lua runtime errors → console Error pane
    exec.set_error_callback([this](const std::string& msg) {
        if (!console_) return;
        g_idle_add([](gpointer data) -> gboolean {
            auto* p = static_cast<std::pair<Console*, std::string>*>(data);
            p->first->print(p->second, Console::Level::Error);
            delete p;
            return G_SOURCE_REMOVE;
        }, new std::pair<Console*, std::string>(console_.get(), msg));
    });

    // Executor status changes → bottom status bar
    exec.set_status_callback([this](const std::string& msg) {
        if (!status_label_) return;
        g_idle_add([](gpointer data) -> gboolean {
            auto* p = static_cast<std::pair<GtkWidget*, std::string>*>(data);
            gtk_label_set_text(GTK_LABEL(p->first), p->second.c_str());
            delete p;
            return G_SOURCE_REMOVE;
        }, new std::pair<GtkWidget*, std::string>(status_label_, msg));
    });
}

void App::disconnect_executor() {
    auto& exec = Executor::instance();
    exec.set_output_callback(nullptr);
    exec.set_error_callback(nullptr);
    exec.set_status_callback(nullptr);
}

// ────────────────────── UI construction ──────────────────────

void App::build_ui(GtkApplication* app) {
    // --- subsystem init ---
    auto& config = Config::instance();
    std::string home = config.home_dir();

    Logger::init(home + "/logs");
    config.load(home + "/config.json");

    ThemeManager::instance().load_themes(home + "/themes");
    ThemeManager::instance().set_theme(config.get<std::string>("theme", "midnight"));
    ScriptManager::instance().set_directory(home + "/scripts");

    // --- real executor init (Lua VM, memory scanner, hooks) ---
    Executor::instance().init();

    if (Executor::instance().is_initialized()) {
        lua_State* L = Executor::instance().lua().state();
        if (L) {
            Environment::register_all(L);   // filesystem, http, drawing, etc.
            Closures::register_all(L);      // roblox closure wrappers
            LOG_INFO("Lua API registered (%d globals)", lua_gettop(L));
        } else {
            LOG_ERROR("Lua state is null — skipping API registration");
        }
    } else {
        LOG_ERROR("Executor failed to initialize — execution will be unavailable");
    }

    Overlay::instance().init();

    // --- window ---
    window_ = GTK_WINDOW(gtk_application_window_new(app));
    gtk_window_set_title(window_, "OSS Executor v" APP_VERSION);
    gtk_window_set_default_size(window_, 1400, 900);

    // FIX: pass `this` so we can disconnect executor before widgets die
    g_signal_connect(window_, "close-request",
        G_CALLBACK(+[](GtkWindow*, gpointer data) -> gboolean {
            auto* self = static_cast<App*>(data);
            self->disconnect_executor();
            Overlay::instance().shutdown();
            return FALSE;   // allow close to proceed
        }), this);

    main_box_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    // ═══════════════════ toolbar ═══════════════════
    toolbar_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_add_css_class(toolbar_, "header-bar");
    gtk_widget_set_margin_start(toolbar_, 8);
    gtk_widget_set_margin_end(toolbar_, 8);
    gtk_widget_set_margin_top(toolbar_, 6);
    gtk_widget_set_margin_bottom(toolbar_, 6);

    // title
    GtkWidget* title_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget* title = gtk_label_new("◈ OSS");
    gtk_widget_add_css_class(title, "title");
    PangoAttrList* attrs = pango_attr_list_new();
    pango_attr_list_insert(attrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
    pango_attr_list_insert(attrs, pango_attr_scale_new(1.2));
    gtk_label_set_attributes(GTK_LABEL(title), attrs);
    pango_attr_list_unref(attrs);
    gtk_box_append(GTK_BOX(title_box), title);
    gtk_box_append(GTK_BOX(toolbar_), title_box);

    gtk_box_append(GTK_BOX(toolbar_), gtk_separator_new(GTK_ORIENTATION_VERTICAL));

    // file buttons
    GtkWidget* open_btn = gtk_button_new_with_label("📂 Open");
    gtk_widget_add_css_class(open_btn, "btn-secondary");
    gtk_widget_set_tooltip_text(open_btn, "Open Script (Ctrl+O)");
    g_signal_connect_swapped(open_btn, "clicked", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_open_file();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), open_btn);

    GtkWidget* save_btn = gtk_button_new_with_label("💾 Save");
    gtk_widget_add_css_class(save_btn, "btn-secondary");
    gtk_widget_set_tooltip_text(save_btn, "Save Script (Ctrl+S)");
    g_signal_connect_swapped(save_btn, "clicked", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_save_file();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), save_btn);

    // spacer
    GtkWidget* spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(toolbar_), spacer);

    // action buttons
    GtkWidget* inject_btn = gtk_button_new_with_label("🔗 Inject");
    gtk_widget_add_css_class(inject_btn, "btn-secondary");
    gtk_widget_set_tooltip_text(inject_btn, "Inject into Roblox (F5)");
    g_signal_connect_swapped(inject_btn, "clicked", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_inject();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), inject_btn);

    GtkWidget* execute_btn = gtk_button_new_with_label("▶ Execute");
    gtk_widget_add_css_class(execute_btn, "btn-execute");
    gtk_widget_set_tooltip_text(execute_btn, "Execute Script (Ctrl+Enter)");
    g_signal_connect_swapped(execute_btn, "clicked", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_execute();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), execute_btn);

    GtkWidget* clear_btn = gtk_button_new_with_label("🗑 Clear");
    gtk_widget_add_css_class(clear_btn, "btn-secondary");
    gtk_widget_set_tooltip_text(clear_btn, "Clear Editor (Ctrl+L)");
    g_signal_connect_swapped(clear_btn, "clicked", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_clear();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), clear_btn);

    GtkWidget* kill_btn = gtk_button_new_with_label("⬛ Kill");
    gtk_widget_add_css_class(kill_btn, "btn-danger");
    gtk_widget_set_tooltip_text(kill_btn, "Cancel Execution");
    g_signal_connect_swapped(kill_btn, "clicked", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_kill();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), kill_btn);

    gtk_box_append(GTK_BOX(toolbar_), gtk_separator_new(GTK_ORIENTATION_VERTICAL));

    // toggle buttons
    GtkWidget* hub_toggle = gtk_toggle_button_new_with_label("📜 Hub");
    gtk_widget_add_css_class(hub_toggle, "btn-secondary");
    g_signal_connect_swapped(hub_toggle, "toggled", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_toggle_hub();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), hub_toggle);

    GtkWidget* console_toggle = gtk_toggle_button_new_with_label("🖥 Console");
    gtk_widget_add_css_class(console_toggle, "btn-secondary");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(console_toggle), TRUE);
    g_signal_connect_swapped(console_toggle, "toggled", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_toggle_console();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), console_toggle);

    GtkWidget* overlay_toggle = gtk_toggle_button_new_with_label("👁 Overlay");
    gtk_widget_add_css_class(overlay_toggle, "btn-secondary");
    gtk_widget_set_tooltip_text(overlay_toggle, "Toggle Drawing Overlay");
    g_signal_connect_swapped(overlay_toggle, "toggled", G_CALLBACK(+[](gpointer d) {
        static_cast<App*>(d)->on_toggle_overlay();
    }), this);
    gtk_box_append(GTK_BOX(toolbar_), overlay_toggle);

    gtk_box_append(GTK_BOX(main_box_), toolbar_);

    // ═══════════════════ tabs ═══════════════════
    tabs_ = std::make_unique<TabManager>();
    gtk_box_append(GTK_BOX(main_box_), tabs_->widget());

    // ═══════════════════ paned layout ═══════════════════
    sidebar_paned_ = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_vexpand(sidebar_paned_, TRUE);

    // script hub (left, hidden by default)
    script_hub_ = std::make_unique<ScriptHub>();
    hub_revealer_ = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(hub_revealer_),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_RIGHT);
    gtk_revealer_set_reveal_child(GTK_REVEALER(hub_revealer_), FALSE);
    gtk_widget_set_size_request(hub_revealer_, 300, -1);
    gtk_revealer_set_child(GTK_REVEALER(hub_revealer_), script_hub_->widget());
    gtk_paned_set_start_child(GTK_PANED(sidebar_paned_), hub_revealer_);

    // editor + console (right)
    paned_ = gtk_paned_new(GTK_ORIENTATION_VERTICAL);

    editor_ = std::make_unique<Editor>();
    gtk_paned_set_start_child(GTK_PANED(paned_), editor_->widget());
    gtk_paned_set_resize_start_child(GTK_PANED(paned_), TRUE);

    console_ = std::make_unique<Console>();
    console_revealer_ = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(console_revealer_),
                                     GTK_REVEALER_TRANSITION_TYPE_NONE);
    gtk_revealer_set_reveal_child(GTK_REVEALER(console_revealer_), TRUE);
    gtk_widget_set_size_request(console_revealer_, -1, 200);
    gtk_revealer_set_child(GTK_REVEALER(console_revealer_), console_->widget());
    gtk_paned_set_end_child(GTK_PANED(paned_), console_revealer_);
    gtk_paned_set_resize_end_child(GTK_PANED(paned_), FALSE);
    gtk_paned_set_position(GTK_PANED(paned_), 550);

    gtk_paned_set_end_child(GTK_PANED(sidebar_paned_), paned_);
    gtk_box_append(GTK_BOX(main_box_), sidebar_paned_);

    // ═══════════════════ status bar ═══════════════════
    status_bar_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_add_css_class(status_bar_, "status-bar");
    gtk_widget_set_margin_start(status_bar_, 12);
    gtk_widget_set_margin_end(status_bar_, 12);
    gtk_widget_set_margin_top(status_bar_, 2);
    gtk_widget_set_margin_bottom(status_bar_, 2);

    status_label_ = gtk_label_new("Ready");
    gtk_label_set_xalign(GTK_LABEL(status_label_), 0);
    gtk_widget_set_hexpand(status_label_, TRUE);
    gtk_box_append(GTK_BOX(status_bar_), status_label_);

    position_label_ = gtk_label_new("Ln 1, Col 1");
    gtk_box_append(GTK_BOX(status_bar_), position_label_);

    GtkWidget* version_label = gtk_label_new("v" APP_VERSION);
    gtk_widget_add_css_class(version_label, "dim-label");
    gtk_box_append(GTK_BOX(status_bar_), version_label);

    gtk_box_append(GTK_BOX(main_box_), status_bar_);

    // ═══════════════════ wire executor → UI ═══════════════════
    connect_executor();

    // ═══════════════════ wire tabs ↔ editor ═══════════════════
    int first_tab = tabs_->add_tab("Script 1",
        "-- OSS Executor v" APP_VERSION "\n"
        "-- Write your Lua script here\n\n"
        "print(\"Hello from OSS!\")\n");
    tabs_->set_active(first_tab);

    tabs_->set_change_callback([this](int id) {
        auto* tab = tabs_->get_tab(id);
        if (tab && editor_) editor_->set_text(tab->content);
    });

    // TabManager calls this to snapshot editor content before switching away
    tabs_->set_content_provider([this]() -> std::string {
        return editor_ ? editor_->get_text() : std::string{};
    });

    editor_->set_modified_callback([this](bool modified) {
        if (tabs_) tabs_->set_tab_modified(tabs_->active_id(), modified);
    });

    script_hub_->set_load_callback([this](const std::string& script) {
        int id = tabs_->add_tab("Hub Script");
        tabs_->set_active(id);
        editor_->set_text(script);
        console_->print("Script loaded from hub", Console::Level::System);
    });

    // ═══════════════════ final setup ═══════════════════
    apply_theme();
    setup_keybinds();

    gtk_window_set_child(window_, main_box_);
    tick_id_ = g_timeout_add(500, on_tick, this);

    console_->print("═══════════════════════════════════════", Console::Level::System);
    console_->print("  OSS Executor v" APP_VERSION " — Linux Native", Console::Level::System);
    console_->print("  Open Source Softworks", Console::Level::System);
    console_->print("═══════════════════════════════════════", Console::Level::System);

    if (Executor::instance().is_initialized()) {
        console_->print("Ready. Press Ctrl+Enter to execute.", Console::Level::Info);
    } else {
        console_->print("⚠ Executor offline — check logs", Console::Level::Warn);
    }

    Executor::instance().auto_execute();
    gtk_window_present(window_);

    // Enable animation only after the first frame so the console
    // doesn't slide in on startup
    g_idle_add([](gpointer data) -> gboolean {
        auto* rev = static_cast<GtkWidget*>(data);
        gtk_revealer_set_transition_type(GTK_REVEALER(rev),
                                         GTK_REVEALER_TRANSITION_TYPE_SLIDE_UP);
        gtk_revealer_set_transition_duration(GTK_REVEALER(rev), 200);
        return G_SOURCE_REMOVE;
    }, console_revealer_);

    LOG_INFO("UI initialized — executor %s",
             Executor::instance().is_initialized() ? "online" : "OFFLINE");
}

// ────────────────────── theme / keybinds ──────────────────────

void App::apply_theme() {
    auto& theme = ThemeManager::instance().current();
    std::string css = theme.generate_css();
    GtkCssProvider* provider = gtk_css_provider_new();
#if GTK_CHECK_VERSION(4, 12, 0)
    gtk_css_provider_load_from_string(provider, css.c_str());
#else
    gtk_css_provider_load_from_data(provider, css.c_str(), -1);
#endif
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

void App::setup_keybinds() {
    GtkEventController* kc = gtk_event_controller_key_new();
    g_signal_connect(kc, "key-pressed",
        G_CALLBACK(+[](GtkEventControllerKey*, guint keyval, guint,
                       GdkModifierType state, gpointer data) -> gboolean {
            auto* a = static_cast<App*>(data);
            bool ctrl = (state & GDK_CONTROL_MASK) != 0;
            if (ctrl && keyval == GDK_KEY_Return) { a->on_execute();    return TRUE; }
            if (ctrl && keyval == GDK_KEY_l)      { a->on_clear();      return TRUE; }
            if (ctrl && keyval == GDK_KEY_s)      { a->on_save_file();  return TRUE; }
            if (ctrl && keyval == GDK_KEY_o)      { a->on_open_file();  return TRUE; }
            if (ctrl && keyval == GDK_KEY_t)      { a->on_new_tab();    return TRUE; }
            if (ctrl && keyval == GDK_KEY_w)      { a->on_close_tab();  return TRUE; }
            if (keyval == GDK_KEY_F5)             { a->on_inject();     return TRUE; }
            if (keyval == GDK_KEY_F12)            { a->on_toggle_console(); return TRUE; }
            if (ctrl && keyval == GDK_KEY_z)      { a->editor_->undo(); return TRUE; }
            if (ctrl && keyval == GDK_KEY_y)      { a->editor_->redo(); return TRUE; }
            return FALSE;
        }), this);
    gtk_widget_add_controller(GTK_WIDGET(window_), kc);
}

// ────────────────────── actions ──────────────────────

void App::on_execute() {
    if (!Executor::instance().is_initialized()) {
        console_->print("✗ Executor is not initialized", Console::Level::Error);
        return;
    }
    std::string script = editor_->get_text();
    if (script.empty()) return;

    console_->print("▶ Executing script...", Console::Level::System);
    Executor::instance().execute_script(script);
}

void App::on_clear() {
    if (editor_) editor_->clear();
}

void App::on_open_file() {
    FileDialog::open(window_, [this](const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            console_->print("Failed to open: " + path, Console::Level::Error);
            return;
        }
        std::string content((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
        std::string name = std::filesystem::path(path).filename().string();

        int id = tabs_->add_tab(name, content);
        tabs_->set_active(id);
        // set_active triggers the change_callback which loads content into editor,
        // but we also store the file_path on the tab
        auto* tab = tabs_->get_tab(id);
        if (tab) tab->file_path = path;

        console_->print("Opened: " + name, Console::Level::Info);
    });
}

void App::on_save_file() {
    auto* tab = tabs_->active_tab();
    if (!tab) return;

    // snapshot current editor content into the tab
    tab->content = editor_->get_text();

    if (!tab->file_path.empty()) {
        // direct save — path already known
        std::ofstream file(tab->file_path);
        if (file.is_open()) {
            file << tab->content;
            tabs_->set_tab_modified(tab->id, false);
            console_->print("Saved: " + tab->file_path, Console::Level::Info);
        } else {
            console_->print("Failed to save: " + tab->file_path, Console::Level::Error);
        }
        return;
    }

    // FIX: capture tab->id and content by value — not the raw pointer.
    // The pointer can dangle if the tab is closed while the dialog is open.
    int tab_id            = tab->id;
    std::string suggested = tab->title + ".lua";
    std::string content   = tab->content;

    FileDialog::save(window_, suggested,
        [this, tab_id, content](const std::string& path) {
            std::ofstream file(path);
            if (!file.is_open()) {
                console_->print("Failed to save: " + path, Console::Level::Error);
                return;
            }
            file << content;

            // re-fetch the tab — it may have been removed
            auto* t = tabs_->get_tab(tab_id);
            if (t) {
                t->file_path = path;
                t->title = std::filesystem::path(path).filename().string();
                tabs_->set_tab_modified(tab_id, false);
                tabs_->set_tab_title(tab_id, t->title);
            }
            console_->print("Saved: " + path, Console::Level::Info);
        });
}

void App::on_inject() {
    // FIX: prevent overlapping injection threads
    if (injecting_) {
        console_->print("⚠ Injection already in progress", Console::Level::Warn);
        return;
    }
    if (!Executor::instance().is_initialized()) {
        console_->print("✗ Executor not initialized — cannot inject", Console::Level::Error);
        return;
    }

    injecting_ = true;
    console_->print("🔗 Scanning for Roblox...", Console::Level::System);

    // Data block passed to the thread → idle → main thread
    struct InjectCtx {
        Console* console;
        App*     app;
        bool     success;
    };
    auto* ctx = new InjectCtx{ console_.get(), this, false };

    GThread* t = g_thread_new("inject", [](gpointer data) -> gpointer {
        auto* c = static_cast<InjectCtx*>(data);
        c->success = Executor::instance().injection().inject();

        g_idle_add([](gpointer d) -> gboolean {
            auto* c = static_cast<InjectCtx*>(d);
            auto& inj = Executor::instance().injection();
            if (c->success) {
                if (inj.vm_found()) {
                    c->console->print("✓ Injection successful — Luau VM detected",
                                      Console::Level::Info);
                } else {
                    c->console->print("⚠ Attached to Roblox — local execution mode",
                                      Console::Level::Warn);
                }
            } else {
                c->console->print("✗ Injection failed — Is Roblox running?",
                                  Console::Level::Error);
            }
            c->app->injecting_ = false;
            delete c;
            return G_SOURCE_REMOVE;
        }, c);

        return nullptr;
    }, ctx);
    g_thread_unref(t);
}

void App::on_kill() {
    Executor::instance().cancel_execution();
    console_->print("⬛ Execution cancelled", Console::Level::Warn);
}

void App::on_new_tab() {
    int id = tabs_->add_tab();
    tabs_->set_active(id);
    editor_->clear();
}

void App::on_close_tab() {
    tabs_->remove_tab(tabs_->active_id());
}

void App::on_toggle_console() {
    console_visible_ = !console_visible_;
    gtk_revealer_set_reveal_child(GTK_REVEALER(console_revealer_), console_visible_);
}

void App::on_toggle_hub() {
    hub_visible_ = !hub_visible_;
    gtk_revealer_set_reveal_child(GTK_REVEALER(hub_revealer_), hub_visible_);
    if (hub_visible_) script_hub_->refresh();
}

void App::on_toggle_overlay() {
    Overlay::instance().toggle();
}

// ────────────────────── periodic tick ──────────────────────

void App::update_status_bar() {
    if (!editor_ || !position_label_) return;
    int line = editor_->get_cursor_line();
    int col  = editor_->get_cursor_column();
    std::string pos = "Ln " + std::to_string(line) + ", Col " + std::to_string(col);
    gtk_label_set_text(GTK_LABEL(position_label_), pos.c_str());
}

gboolean App::on_tick(gpointer data) {
    static_cast<App*>(data)->update_status_bar();
    return G_SOURCE_CONTINUE;
}

} // namespace oss
