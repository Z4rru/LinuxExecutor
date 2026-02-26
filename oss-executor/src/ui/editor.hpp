#pragma once

#include <gtk/gtk.h>
#include <string>
#include <functional>
#include <vector>
#include <regex>

namespace oss {

class Editor {
public:
    using ModifiedCallback = std::function<void(bool)>;

    Editor();
    ~Editor();

    GtkWidget* widget() { return container_; }

    void set_text(const std::string& text);
    std::string get_text() const;
    
    void clear();
    void insert_text(const std::string& text);
    
    void set_font(const std::string& family, int size);
    void set_modified_callback(ModifiedCallback cb) { modified_cb_ = std::move(cb); }
    
    void undo();
    void redo();
    
    int get_line_count() const;
    int get_cursor_line() const;
    int get_cursor_column() const;

private:
    void setup_highlighting();
    void apply_highlighting();
    void on_text_changed();
    void handle_auto_indent(GtkTextBuffer* buffer, GtkTextIter* location, const char* text);

    GtkWidget* container_;
    GtkWidget* scroll_;
    GtkTextView* text_view_;
    GtkTextBuffer* buffer_;
    GtkWidget* line_numbers_;
    
    ModifiedCallback modified_cb_;
    bool highlighting_ = false;
    
    struct HighlightRule {
        std::string pattern;
        std::string tag;
    };
    std::vector<HighlightRule> rules_;
    
    gulong changed_handler_id_ = 0;
};

} // namespace oss