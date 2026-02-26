#pragma once

#include <gtk/gtk.h>
#include <string>
#include <vector>
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
    void append_entry(const Entry& entry);
    std::string get_timestamp();
    const char* level_tag(Level level);

    GtkWidget* container_;
    GtkWidget* scroll_;
    GtkTextView* text_view_;
    GtkTextBuffer* buffer_;
    
    std::deque<Entry> entries_;
    int max_lines_ = 5000;
    std::mutex mutex_;
};

} // namespace oss