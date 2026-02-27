#pragma once

#include <gtk/gtk.h>
#include <string>
#include <mutex>
#include <deque>

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

    void set_max_lines(int max) { max_lines_ = max; }
    void scroll_to_bottom();

private:
    // ═══════════════════════════════════════════════════════
    // FIX #1: Split into locked (public) and unlocked (private)
    // versions to prevent recursive lock deadlock.
    // ═══════════════════════════════════════════════════════
    void clear_unlocked();          // called while mutex_ is already held
    void append_entry(const Entry& entry);
    std::string get_timestamp();
    const char* level_tag(Level level);

    GtkWidget*     container_;
    GtkWidget*     scroll_;
    GtkTextView*   text_view_;
    GtkTextBuffer* buffer_;

    std::deque<Entry> entries_;
    int                max_lines_ = 5000;
    std::mutex         mutex_;
};

} // namespace oss
