// In build_ui(), replace the console revealer setup:

    // Console
    console_ = std::make_unique<Console>();
    console_revealer_ = gtk_revealer_new();

    // ═══════════════════════════════════════════════════════
    // FIX #2: GtkGizmo SNAPSHOT WARNING
    //
    // BEFORE:
    //   gtk_revealer_set_transition_type(..., SLIDE_UP);
    //   gtk_revealer_set_reveal_child(..., TRUE);
    //   // ← revealer starts animating BEFORE window is mapped
    //   // ← internal GtkGizmo (scrollbar) gets snapshot request
    //   //    before GTK has allocated geometry → WARNING
    //
    // AFTER:
    //   Start with transition NONE + reveal TRUE (instant, no animation)
    //   After window is mapped, switch to SLIDE_UP for future toggles.
    // ═══════════════════════════════════════════════════════
    gtk_revealer_set_transition_type(GTK_REVEALER(console_revealer_),
        GTK_REVEALER_TRANSITION_TYPE_NONE);     // ← no animation initially
    gtk_revealer_set_reveal_child(GTK_REVEALER(console_revealer_), TRUE);
    gtk_widget_set_size_request(console_revealer_, -1, 200);
    gtk_revealer_set_child(GTK_REVEALER(console_revealer_), console_->widget());
    gtk_paned_set_end_child(GTK_PANED(paned_), console_revealer_);
    gtk_paned_set_resize_end_child(GTK_PANED(paned_), FALSE);
    gtk_paned_set_position(GTK_PANED(paned_), 550);

    gtk_paned_set_end_child(GTK_PANED(sidebar_paned_), paned_);
    gtk_box_append(GTK_BOX(main_box_), sidebar_paned_);

    // ... (status bar, callbacks, etc. — unchanged) ...

    gtk_window_set_child(window_, main_box_);

    // Enable slide animation AFTER window is presented
    // so the first reveal doesn't trigger GtkGizmo warning
    g_idle_add([](gpointer data) -> gboolean {
        auto* revealer = static_cast<GtkWidget*>(data);
        gtk_revealer_set_transition_type(GTK_REVEALER(revealer),
            GTK_REVEALER_TRANSITION_TYPE_SLIDE_UP);
        gtk_revealer_set_transition_duration(GTK_REVEALER(revealer), 200);
        return G_SOURCE_REMOVE;
    }, console_revealer_);

    gtk_window_present(window_);


// ═══════════════════════════════════════════════════════════════
// In on_inject(), update the success message to show injection mode:
// ═══════════════════════════════════════════════════════════════

void App::on_inject() {
    console_->print("🔗 Scanning for Roblox...", Console::Level::System);

    auto* console = console_.get();
    g_thread_new("inject", [](gpointer data) -> gpointer {
        auto* c = static_cast<Console*>(data);
        auto& inj = Executor::instance().injection();
        bool success = inj.inject();

        g_idle_add([](gpointer data) -> gboolean {
            auto* pair = static_cast<std::pair<Console*, bool>*>(data);
            auto& inj = Executor::instance().injection();

            if (pair->second) {
                if (inj.vm_found()) {
                    pair->first->print(
                        "✓ Injection successful — Luau VM detected",
                        Console::Level::Info);
                } else {
                    pair->first->print(
                        "⚠ Attached to Roblox — local execution mode "
                        "(Luau VM not located, scripts run in sandbox)",
                        Console::Level::Warn);
                }
            } else {
                pair->first->print(
                    "✗ Injection failed — Is Roblox running?",
                    Console::Level::Error);
            }
            delete pair;
            return G_SOURCE_REMOVE;
        }, new std::pair<Console*, bool>(c, success));

        return nullptr;
    }, console);
}
