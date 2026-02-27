#include "console.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace oss {

Console::Console() {
    container_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(container_, "console-view");

    // Console header
    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_margin_start(header, 8);
    gtk_widget_set_margin_end(header, 8);
    gtk_widget_set_margin_top(header, 4);
    gtk_widget_set_margin_bottom(header, 4);

    GtkWidget* label = gtk_label_new("Console");
    gtk_widget_add_css_class(label, "console-title");
    gtk_box_append(GTK_BOX(header), label);

    GtkWidget* spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(header), spacer);

    GtkWidget* clear_btn = gtk_button_new_with_label("Clear");
    gtk_widget_add_css_class(clear_btn, "btn-secondary");
    g_signal_connect_swapped(clear_btn, "clicked", G_CALLBACK(+[](gpointer data) {
        static_cast<Console*>(data)->clear();
    }), this);
    gtk_box_append(GTK_BOX(header), clear_btn);

    gtk_box_append(GTK_BOX(container_), header);

    // Text view
    scroll_ = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll_, TRUE);

    text_view_ = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_editable(text_view_, FALSE);
    gtk_text_view_set_cursor_visible(text_view_, FALSE);
    gtk_text_view_set_wrap_mode(text_view_, GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(text_view_, 8);
    gtk_text_view_set_right_margin(text_view_, 8);
    gtk_text_view_set_top_margin(text_view_, 4);
    gtk_text_view_set_bottom_margin(text_view_, 4);
    gtk_text_view_set_monospace(text_view_, TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(text_view_), "console-text");

    buffer_ = gtk_text_view_get_buffer(text_view_);

    gtk_text_buffer_create_tag(buffer_, "output",    "foreground", "#e6edf3", NULL);
    gtk_text_buffer_create_tag(buffer_, "error",     "foreground", "#f85149", NULL);
    gtk_text_buffer_create_tag(buffer_, "warn",      "foreground", "#d29922", NULL);
    gtk_text_buffer_create_tag(buffer_, "info",      "foreground", "#58a6ff", NULL);
    gtk_text_buffer_create_tag(buffer_, "system",    "foreground", "#8b949e",
                               "style", PANGO_STYLE_ITALIC, NULL);
    gtk_text_buffer_create_tag(buffer_, "timestamp", "foreground", "#484f58",
                               "scale", 0.85, NULL);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll_),
                                  GTK_WIDGET(text_view_));
    gtk_box_append(GTK_BOX(container_), scroll_);
}

Console::~Console() {}

// ═══════════════════════════════════════════════════════════════
// FIX #1: DEADLOCK
//
// BEFORE:
//   print() locks mutex_
//     → detects "\x1B[CLEAR]"
//     → calls clear()
//     → clear() tries to lock mutex_   ← DEADLOCK (std::mutex)
//
// AFTER:
//   print() locks mutex_
//     → detects "\x1B[CLEAR]"
//     → calls clear_unlocked()         ← no second lock
//   clear() is the PUBLIC entry point  ← locks once, calls _unlocked
// ═══════════════════════════════════════════════════════════════
void Console::print(const std::string& msg, Level level) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Handle rconsole.clear() signal without re-locking
    if (msg == "\x1B[CLEAR]") {
        clear_unlocked();
        return;
    }

    Entry entry{msg, level, get_timestamp()};
    entries_.push_back(entry);

    while (static_cast<int>(entries_.size()) > max_lines_) {
        entries_.pop_front();
    }

    // ═══════════════════════════════════════════════════════
    // FIX #1b: REMOVED the pointless g_idle_add that allocated
    // an Entry, then immediately deleted it without using it.
    //
    // BEFORE:
    //   auto* data = new Entry(entry);
    //   g_idle_add([](gpointer ud) -> gboolean {
    //       delete static_cast<Entry*>(ud);   // ← does nothing useful
    //       return G_SOURCE_REMOVE;
    //   }, data);
    //
    // The actual rendering was already done by append_entry()
    // called directly below.  The idle callback was pure waste
    // (and leaked if the main loop was blocked).
    // ═══════════════════════════════════════════════════════

    append_entry(entry);
}

// PUBLIC clear — locks mutex, then delegates
void Console::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    clear_unlocked();
}

// PRIVATE clear — called with mutex_ already held
void Console::clear_unlocked() {
    entries_.clear();
    gtk_text_buffer_set_text(buffer_, "", 0);
}

void Console::append_entry(const Entry& entry) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer_, &end);

    std::string ts = "[" + entry.timestamp + "] ";
    gtk_text_buffer_insert_with_tags_by_name(
        buffer_, &end, ts.c_str(), -1, "timestamp", NULL);

    gtk_text_buffer_get_end_iter(buffer_, &end);
    std::string msg = entry.message + "\n";
    gtk_text_buffer_insert_with_tags_by_name(
        buffer_, &end, msg.c_str(), -1, level_tag(entry.level), NULL);

    scroll_to_bottom();
}

void Console::scroll_to_bottom() {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer_, &end);
    GtkTextMark* mark = gtk_text_buffer_create_mark(buffer_, NULL, &end, FALSE);
    gtk_text_view_scroll_mark_onscreen(text_view_, mark);
    gtk_text_buffer_delete_mark(buffer_, mark);
}

std::string Console::get_timestamp() {
    auto now  = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms   = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

const char* Console::level_tag(Level level) {
    switch (level) {
        case Level::Info:   return "info";
        case Level::Warn:   return "warn";
        case Level::Error:  return "error";
        case Level::Output: return "output";
        case Level::System: return "system";
    }
    return "output";
}

} // namespace oss
