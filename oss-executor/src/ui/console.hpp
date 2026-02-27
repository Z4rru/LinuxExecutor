#pragma once

#include <gtk/gtk.h>
#include <string>
#include <mutex>
#include <deque>
#include <functional>
#include <atomic>
#include <condition_variable>
#include <thread>

namespace oss {

class Console {
public:
    enum class Level { Info, Warn, Error, Output, System };

    struct Entry {
        std::string message;
        Level level;
        std::string timestamp;
    };

    Console();
    ~Console();

    GtkWidget* widget() { return container_; }

    void print(const std::string& msg, Level level = Level::Output);
    void clear();
    void scroll_to_bottom();

    void set_max_lines(int max) { max_lines_ = max; }

    void create_console(const std::string& title = "Console");
    void destroy_console();
    bool is_console_visible() const;
    void set_console_name(const std::string& name);
    std::string get_console_name() const;

    std::string request_input(const std::string& prompt = "");
    void submit_input(const std::string& text);

    using InputCallback = std::function<void(const std::string&)>;
    void set_input_callback(InputCallback cb);

    void set_word_wrap(bool enabled);
    void set_font_size(int size);
    void set_show_timestamps(bool show);

    const std::deque<Entry>& get_entries() const { return entries_; }

private:
    void clear_unlocked();
    void append_entry(const Entry& entry);
    void rebuild_display();
    std::string get_timestamp();
    const char* level_tag(Level level);
    void setup_input_bar();

    GtkWidget* container_;
    GtkWidget* scroll_;
    GtkTextView* text_view_;
    GtkTextBuffer* buffer_;
    GtkWidget* input_bar_;
    GtkWidget* input_entry_;
    GtkWidget* input_prompt_label_;
    GtkWidget* header_label_;

    std::deque<Entry> entries_;
    int max_lines_ = 5000;
    std::mutex mutex_;

    std::string console_name_ = "Console";
    std::atomic<bool> console_visible_{true};
    bool show_timestamps_ = true;

    InputCallback input_cb_;
    std::string pending_input_;
    std::mutex input_mutex_;
    std::condition_variable input_cv_;
    std::atomic<bool> input_waiting_{false};
};

} // namespace oss
