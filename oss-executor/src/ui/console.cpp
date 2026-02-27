#include "console.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace oss {

static void load_css_string(GtkCssProvider* provider, const std::string& css) {
#if GTK_CHECK_VERSION(4, 12, 0)
    gtk_css_provider_load_from_string(provider, css.c_str());
#else
    gtk_css_provider_load_from_data(provider, css.c_str(), -1);
#endif
}

Console::Console() {
    container_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(container_, "console-view");

    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_margin_start(header, 8);
    gtk_widget_set_margin_end(header, 8);
    gtk_widget_set_margin_top(header, 4);
    gtk_widget_set_margin_bottom(header, 4);

    header_label_ = gtk_label_new("Console");
    gtk_widget_add_css_class(header_label_, "console-title");
    gtk_box_append(GTK_BOX(header), header_label_);

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

    gtk_text_buffer_create_tag(buffer_, "output", "foreground", "#e6edf3", NULL);
    gtk_text_buffer_create_tag(buffer_, "error", "foreground", "#f85149", NULL);
    gtk_text_buffer_create_tag(buffer_, "warn", "foreground", "#d29922", NULL);
    gtk_text_buffer_create_tag(buffer_, "info", "foreground", "#58a6ff", NULL);
    gtk_text_buffer_create_tag(buffer_, "system", "foreground", "#8b949e",
                               "style", PANGO_STYLE_ITALIC, NULL);
    gtk_text_buffer_create_tag(buffer_, "timestamp", "foreground", "#484f58",
                               "scale", 0.85, NULL);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll_),
                                  GTK_WIDGET(text_view_));
    gtk_box_append(GTK_BOX(container_), scroll_);

    setup_input_bar();
}

Console::~Console() {
    input_waiting_.store(false);
    input_cv_.notify_all();
}

void Console::setup_input_bar() {
    input_bar_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_margin_start(input_bar_, 8);
    gtk_widget_set_margin_end(input_bar_, 8);
    gtk_widget_set_margin_top(input_bar_, 4);
    gtk_widget_set_margin_bottom(input_bar_, 4);

    input_prompt_label_ = gtk_label_new(">");
    gtk_widget_add_css_class(input_prompt_label_, "console-prompt");
    gtk_box_append(GTK_BOX(input_bar_), input_prompt_label_);

    input_entry_ = gtk_entry_new();
    gtk_widget_set_hexpand(input_entry_, TRUE);
    gtk_widget_add_css_class(input_entry_, "console-input");
    gtk_entry_set_placeholder_text(GTK_ENTRY(input_entry_), "Enter input...");

    g_signal_connect_swapped(input_entry_, "activate", G_CALLBACK(+[](gpointer data) {
        auto* self = static_cast<Console*>(data);
        const char* text = gtk_editable_get_text(GTK_EDITABLE(self->input_entry_));
        if (text && text[0] != '\0') {
            std::string input(text);
            gtk_editable_set_text(GTK_EDITABLE(self->input_entry_), "");
            self->submit_input(input);
        }
    }), this);
    gtk_box_append(GTK_BOX(input_bar_), input_entry_);

    gtk_widget_set_visible(input_bar_, FALSE);
    gtk_box_append(GTK_BOX(container_), input_bar_);
}

void Console::print(const std::string& msg, Level level) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (msg == "\x1B[CLEAR]") {
        clear_unlocked();
        return;
    }

    Entry entry{msg, level, get_timestamp()};
    entries_.push_back(entry);

    while (static_cast<int>(entries_.size()) > max_lines_) {
        entries_.pop_front();
    }

    append_entry(entry);
}

void Console::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    clear_unlocked();
}

void Console::clear_unlocked() {
    entries_.clear();
    gtk_text_buffer_set_text(buffer_, "", 0);
}

void Console::create_console(const std::string& title) {
    console_name_ = title;
    gtk_label_set_text(GTK_LABEL(header_label_), title.c_str());
    console_visible_.store(true, std::memory_order_release);
    gtk_widget_set_visible(container_, TRUE);

    std::lock_guard<std::mutex> lock(mutex_);
    Entry entry{"Console created: " + title, Level::System, get_timestamp()};
    entries_.push_back(entry);
    append_entry(entry);
}

void Console::destroy_console() {
    console_visible_.store(false, std::memory_order_release);

    input_waiting_.store(false);
    input_cv_.notify_all();

    std::lock_guard<std::mutex> lock(mutex_);
    clear_unlocked();
}

bool Console::is_console_visible() const {
    return console_visible_.load(std::memory_order_acquire);
}

void Console::set_console_name(const std::string& name) {
    console_name_ = name;
    gtk_label_set_text(GTK_LABEL(header_label_), name.c_str());
}

std::string Console::get_console_name() const {
    return console_name_;
}

std::string Console::request_input(const std::string& prompt) {
    if (!prompt.empty()) {
        gtk_label_set_text(GTK_LABEL(input_prompt_label_), prompt.c_str());
    } else {
        gtk_label_set_text(GTK_LABEL(input_prompt_label_), ">");
    }

    gtk_widget_set_visible(input_bar_, TRUE);
    gtk_widget_grab_focus(input_entry_);

    input_waiting_.store(true, std::memory_order_release);

    std::unique_lock<std::mutex> lock(input_mutex_);
    input_cv_.wait(lock, [this] {
        return !input_waiting_.load(std::memory_order_acquire);
    });

    gtk_widget_set_visible(input_bar_, FALSE);

    return pending_input_;
}

void Console::submit_input(const std::string& text) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Entry entry{"> " + text, Level::Info, get_timestamp()};
        entries_.push_back(entry);
        append_entry(entry);
    }

    if (input_cb_) {
        input_cb_(text);
    }

    if (input_waiting_.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(input_mutex_);
        pending_input_ = text;
        input_waiting_.store(false, std::memory_order_release);
        input_cv_.notify_one();
    }
}

void Console::set_input_callback(InputCallback cb) {
    input_cb_ = std::move(cb);
}

void Console::set_word_wrap(bool enabled) {
    gtk_text_view_set_wrap_mode(text_view_,
        enabled ? GTK_WRAP_WORD_CHAR : GTK_WRAP_NONE);
}

void Console::set_font_size(int size) {
    std::string css = ".console-font-override { font-size: " + std::to_string(size) + "pt; }";
    GtkCssProvider* provider = gtk_css_provider_new();
    load_css_string(provider, css);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
    gtk_widget_add_css_class(GTK_WIDGET(text_view_), "console-font-override");
}

void Console::set_show_timestamps(bool show) {
    show_timestamps_ = show;
    rebuild_display();
}

void Console::rebuild_display() {
    std::lock_guard<std::mutex> lock(mutex_);
    gtk_text_buffer_set_text(buffer_, "", 0);
    for (const auto& entry : entries_) {
        append_entry(entry);
    }
}

void Console::append_entry(const Entry& entry) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer_, &end);

    if (show_timestamps_) {
        std::string ts = "[" + entry.timestamp + "] ";
        gtk_text_buffer_insert_with_tags_by_name(
            buffer_, &end, ts.c_str(), -1, "timestamp", NULL);
        gtk_text_buffer_get_end_iter(buffer_, &end);
    }

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
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
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
