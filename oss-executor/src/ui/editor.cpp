#include "editor.hpp"
#include "utils/config.hpp"

namespace oss {

Editor::Editor() {
    container_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_add_css_class(container_, "editor-container");
    
    // Line numbers
    line_numbers_ = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(line_numbers_), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(line_numbers_), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(line_numbers_), TRUE);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(line_numbers_), 8);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(line_numbers_), 8);
    gtk_widget_set_size_request(line_numbers_, 50, -1);
    gtk_widget_add_css_class(line_numbers_, "line-numbers");
    gtk_box_append(GTK_BOX(container_), line_numbers_);
    
    // Scrolled window for editor
    scroll_ = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(scroll_, TRUE);
    gtk_widget_set_vexpand(scroll_, TRUE);
    
    // Text view
    text_view_ = GTK_TEXT_VIEW(gtk_text_view_new());
    buffer_ = gtk_text_view_get_buffer(text_view_);
    
    gtk_text_view_set_monospace(text_view_, TRUE);
    gtk_text_view_set_left_margin(text_view_, 8);
    gtk_text_view_set_right_margin(text_view_, 8);
    gtk_text_view_set_top_margin(text_view_, 8);
    gtk_text_view_set_bottom_margin(text_view_, 8);
    gtk_text_view_set_wrap_mode(text_view_, GTK_WRAP_NONE);
    gtk_widget_add_css_class(GTK_WIDGET(text_view_), "editor-view");
    
    // Enable undo
    gtk_text_buffer_set_enable_undo(buffer_, TRUE);
    
    setup_highlighting();
    
    // Connect signals
    changed_handler_id_ = g_signal_connect_swapped(buffer_, "changed", 
        G_CALLBACK(+[](gpointer data) {
            static_cast<Editor*>(data)->on_text_changed();
        }), this);
    
    // Auto-indent on Enter
    g_signal_connect(buffer_, "insert-text",
        G_CALLBACK(+[](GtkTextBuffer* buf, GtkTextIter* loc, 
                       const char* text, int len, gpointer data) {
            (void)len;
            static_cast<Editor*>(data)->handle_auto_indent(buf, loc, text);
        }), this);
    
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll_), GTK_WIDGET(text_view_));
    gtk_box_append(GTK_BOX(container_), scroll_);
    
    // Set default font
    auto& config = Config::instance();
    set_font(config.get<std::string>("editor.font_family", "JetBrains Mono"),
             config.get<int>("editor.font_size", 14));
}

Editor::~Editor() {}

void Editor::setup_highlighting() {
    // Create syntax highlighting tags
    gtk_text_buffer_create_tag(buffer_, "keyword",
        "foreground", "#ff7b72", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buffer_, "string",
        "foreground", "#a5d6ff", NULL);
    gtk_text_buffer_create_tag(buffer_, "number",
        "foreground", "#79c0ff", NULL);
    gtk_text_buffer_create_tag(buffer_, "comment",
        "foreground", "#8b949e", "style", PANGO_STYLE_ITALIC, NULL);
    gtk_text_buffer_create_tag(buffer_, "function",
        "foreground", "#d2a8ff", NULL);
    gtk_text_buffer_create_tag(buffer_, "builtin",
        "foreground", "#ffa657", NULL);
    gtk_text_buffer_create_tag(buffer_, "boolean",
        "foreground", "#79c0ff", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buffer_, "operator",
        "foreground", "#ff7b72", NULL);
    
    // Lua keyword rules
    rules_ = {
        {"\\b(and|break|do|else|elseif|end|for|function|if|in|local|not|or|repeat|return|then|until|while)\\b", "keyword"},
        {"\\b(true|false|nil)\\b", "boolean"},
        {"\\b(print|warn|error|assert|type|typeof|tostring|tonumber|select|pairs|ipairs|next|unpack|pcall|xpcall|require|setmetatable|getmetatable|rawget|rawset|rawequal|rawlen|setfenv|getfenv|coroutine|table|string|math|bit32|utf8)\\b", "builtin"},
        {"\\b(game|workspace|script|Instance|Vector3|CFrame|Color3|UDim2|UDim|Enum|wait|spawn|delay|tick|time|task)\\b", "builtin"},
        {"\\b(readfile|writefile|appendfile|isfile|listfiles|makefolder|delfolder|getclipboard|setclipboard|identifyexecutor|getexecutorname|http|syn|Drawing|hookfunction|newcclosure|getgenv|getrenv|getreg|getgc|fireclickdetector|firetouchinterest|fireproximityprompt|checkcaller|islclosure|iscclosure|getrawmetatable|setrawmetatable|setreadonly|isreadonly)\\b", "builtin"},
        {"\\b\\d+\\.?\\d*([eE][+-]?\\d+)?\\b", "number"},
        {"0[xX][0-9a-fA-F]+", "number"},
    };
}

void Editor::apply_highlighting() {
    if (highlighting_) return;
    highlighting_ = true;
    
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer_, &start, &end);
    
    // Remove all existing tags
    gtk_text_buffer_remove_all_tags(buffer_, &start, &end);
    
    char* text = gtk_text_buffer_get_text(buffer_, &start, &end, FALSE);
    std::string source(text);
    g_free(text);
    
    // Apply regex-based highlighting
    for (const auto& rule : rules_) {
        try {
            std::regex re(rule.pattern);
            auto words_begin = std::sregex_iterator(source.begin(), source.end(), re);
            auto words_end = std::sregex_iterator();
            
            for (auto i = words_begin; i != words_end; ++i) {
                GtkTextIter match_start, match_end;
                gtk_text_buffer_get_iter_at_offset(buffer_, &match_start, 
                    static_cast<int>(i->position()));
                gtk_text_buffer_get_iter_at_offset(buffer_, &match_end, 
                    static_cast<int>(i->position() + i->length()));
                gtk_text_buffer_apply_tag_by_name(buffer_, rule.tag.c_str(), 
                    &match_start, &match_end);
            }
        } catch (...) {}
    }
    
    // String highlighting (handles multi-char properly)
    {
        size_t pos = 0;
        while (pos < source.size()) {
            if (source[pos] == '"' || source[pos] == '\'') {
                char quote = source[pos];
                size_t start_pos = pos;
                pos++;
                while (pos < source.size() && source[pos] != quote) {
                    if (source[pos] == '\\') pos++; // Skip escaped char
                    pos++;
                }
                if (pos < source.size()) pos++; // Skip closing quote
                
                GtkTextIter s, e;
                gtk_text_buffer_get_iter_at_offset(buffer_, &s, static_cast<int>(start_pos));
                gtk_text_buffer_get_iter_at_offset(buffer_, &e, static_cast<int>(pos));
                gtk_text_buffer_apply_tag_by_name(buffer_, "string", &s, &e);
            }
            // Multi-line strings [[...]]
            else if (pos + 1 < source.size() && source[pos] == '[' && source[pos+1] == '[') {
                size_t start_pos = pos;
                pos += 2;
                while (pos + 1 < source.size() && !(source[pos] == ']' && source[pos+1] == ']')) {
                    pos++;
                }
                if (pos + 1 < source.size()) pos += 2;
                
                GtkTextIter s, e;
                gtk_text_buffer_get_iter_at_offset(buffer_, &s, static_cast<int>(start_pos));
                gtk_text_buffer_get_iter_at_offset(buffer_, &e, static_cast<int>(pos));
                gtk_text_buffer_apply_tag_by_name(buffer_, "string", &s, &e);
            }
            else {
                pos++;
            }
        }
    }
    
    // Comment highlighting (must be after strings to override)
    {
        size_t pos = 0;
        while (pos < source.size()) {
            if (pos + 1 < source.size() && source[pos] == '-' && source[pos+1] == '-') {
                size_t start_pos = pos;
                
                // Multi-line comment --[[...]]
                if (pos + 3 < source.size() && source[pos+2] == '[' && source[pos+3] == '[') {
                    pos += 4;
                    while (pos + 1 < source.size() && !(source[pos] == ']' && source[pos+1] == ']')) {
                        pos++;
                    }
                    if (pos + 1 < source.size()) pos += 2;
                } else {
                    // Single line comment
                    while (pos < source.size() && source[pos] != '\n') pos++;
                }
                
                GtkTextIter s, e;
                gtk_text_buffer_get_iter_at_offset(buffer_, &s, static_cast<int>(start_pos));
                gtk_text_buffer_get_iter_at_offset(buffer_, &e, static_cast<int>(pos));
                gtk_text_buffer_apply_tag_by_name(buffer_, "comment", &s, &e);
            } else {
                pos++;
            }
        }
    }
    
    // Function calls: word followed by (
    {
        std::regex func_re("\\b([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\(");
        auto it = std::sregex_iterator(source.begin(), source.end(), func_re);
        auto end_it = std::sregex_iterator();
        
        for (; it != end_it; ++it) {
            auto match = *it;
            std::string name = match[1].str();
            
            // Skip keywords and builtins
            static const std::vector<std::string> skip = {
                "if", "for", "while", "function", "return", "and", "or", "not",
                "repeat", "until", "do", "end", "then", "else", "elseif", "in",
                "local", "break"
            };
            
            bool is_skip = false;
            for (const auto& s : skip) {
                if (name == s) { is_skip = true; break; }
            }
            if (is_skip) continue;
            
            GtkTextIter s, e;
            int offset = static_cast<int>(match.position(1));
            gtk_text_buffer_get_iter_at_offset(buffer_, &s, offset);
            gtk_text_buffer_get_iter_at_offset(buffer_, &e, 
                offset + static_cast<int>(match[1].length()));
            gtk_text_buffer_apply_tag_by_name(buffer_, "function", &s, &e);
        }
    }
    
    highlighting_ = false;
}

void Editor::on_text_changed() {
    // Update line numbers
    int lines = get_line_count();
    std::string line_text;
    for (int i = 1; i <= lines; i++) {
        line_text += std::to_string(i) + "\n";
    }
    
    GtkTextBuffer* ln_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(line_numbers_));
    gtk_text_buffer_set_text(ln_buf, line_text.c_str(), -1);
    
    // Debounced highlighting (apply after a short delay)
    g_timeout_add(50, [](gpointer data) -> gboolean {
        static_cast<Editor*>(data)->apply_highlighting();
        return G_SOURCE_REMOVE;
    }, this);
    
    if (modified_cb_) modified_cb_(true);
}

void Editor::handle_auto_indent(GtkTextBuffer* buffer, GtkTextIter* location, const char* text) {
    if (std::string(text) != "\n") return;
    
    // Get previous line's indentation
    GtkTextIter line_start = *location;
    gtk_text_iter_set_line_offset(&line_start, 0);
    
    char* line_text = gtk_text_buffer_get_text(buffer, &line_start, location, FALSE);
    std::string line(line_text);
    g_free(line_text);
    
    // Calculate indent
    std::string indent;
    for (char c : line) {
        if (c == ' ' || c == '\t') indent += c;
        else break;
    }
    
    // Check if we should increase indent
    std::string trimmed = line;
    while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t'))
        trimmed.pop_back();
    
    static const std::vector<std::string> indent_keywords = {
        "then", "do", "else", "function", "repeat", "{"
    };
    
    for (const auto& kw : indent_keywords) {
        if (trimmed.size() >= kw.size() && 
            trimmed.substr(trimmed.size() - kw.size()) == kw) {
            indent += "    ";
            break;
        }
    }
    
    // Insert indent after the newline
    if (!indent.empty()) {
        g_signal_handler_block(buffer, changed_handler_id_);
        // We'll insert the indent on the next idle to avoid recursion
        auto* indent_data = new std::pair<GtkTextBuffer*, std::string>(buffer, indent);
        g_idle_add([](gpointer data) -> gboolean {
            auto* d = static_cast<std::pair<GtkTextBuffer*, std::string>*>(data);
            GtkTextIter iter;
            GtkTextMark* insert_mark = gtk_text_buffer_get_insert(d->first);
            gtk_text_buffer_get_iter_at_mark(d->first, &iter, insert_mark);
            gtk_text_buffer_insert(d->first, &iter, d->second.c_str(), -1);
            delete d;
            return G_SOURCE_REMOVE;
        }, indent_data);
        g_signal_handler_unblock(buffer, changed_handler_id_);
    }
}

void Editor::set_text(const std::string& text) {
    g_signal_handler_block(buffer_, changed_handler_id_);
    gtk_text_buffer_set_text(buffer_, text.c_str(), -1);
    g_signal_handler_unblock(buffer_, changed_handler_id_);
    on_text_changed();
}

std::string Editor::get_text() const {
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer_, &start, &end);
    char* text = gtk_text_buffer_get_text(buffer_, &start, &end, FALSE);
    std::string result(text);
    g_free(text);
    return result;
}

void Editor::clear() {
    set_text("");
}

void Editor::insert_text(const std::string& text) {
    gtk_text_buffer_insert_at_cursor(buffer_, text.c_str(), -1);
}

void Editor::set_font(const std::string& family, int size) {
    std::string css = "textview { font-family: \"" + family + "\"; font-size: " + 
                      std::to_string(size) + "px; }";
    
    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_string(provider, css.c_str());
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_USER
    );
    g_object_unref(provider);
}

void Editor::undo() {
    gtk_text_buffer_undo(buffer_);
}

void Editor::redo() {
    gtk_text_buffer_redo(buffer_);
}

int Editor::get_line_count() const {
    return gtk_text_buffer_get_line_count(buffer_);
}

int Editor::get_cursor_line() const {
    GtkTextIter iter;
    GtkTextMark* mark = gtk_text_buffer_get_insert(buffer_);
    gtk_text_buffer_get_iter_at_mark(buffer_, &iter, mark);
    return gtk_text_iter_get_line(&iter) + 1;
}

int Editor::get_cursor_column() const {
    GtkTextIter iter;
    GtkTextMark* mark = gtk_text_buffer_get_insert(buffer_);
    gtk_text_buffer_get_iter_at_mark(buffer_, &iter, mark);
    return gtk_text_iter_get_line_offset(&iter) + 1;
}

} // namespace oss