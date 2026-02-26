#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <filesystem>
#include <fstream>

namespace oss {

using json = nlohmann::json;

struct Color {
    float r, g, b, a;
    
    Color() : r(0), g(0), b(0), a(1) {}
    Color(float r, float g, float b, float a = 1.0f) : r(r), g(g), b(b), a(a) {}
    
    static Color from_hex(const std::string& hex) {
        Color c;
        unsigned int val = 0;
        std::string h = hex;
        if (h[0] == '#') h = h.substr(1);
        
        if (h.size() == 6) h += "ff";
        
        sscanf(h.c_str(), "%08x", &val);
        c.r = ((val >> 24) & 0xFF) / 255.0f;
        c.g = ((val >> 16) & 0xFF) / 255.0f;
        c.b = ((val >> 8) & 0xFF) / 255.0f;
        c.a = (val & 0xFF) / 255.0f;
        return c;
    }

    std::string to_css() const {
        char buf[32];
        snprintf(buf, sizeof(buf), "rgba(%d,%d,%d,%.2f)",
                (int)(r*255), (int)(g*255), (int)(b*255), a);
        return buf;
    }
    
    std::string to_hex() const {
        char buf[10];
        snprintf(buf, sizeof(buf), "#%02x%02x%02x",
                (int)(r*255), (int)(g*255), (int)(b*255));
        return buf;
    }
};

struct Theme {
    std::string name;
    
    // Window
    Color bg_primary;
    Color bg_secondary;
    Color bg_tertiary;
    Color bg_editor;
    
    // Text
    Color text_primary;
    Color text_secondary;
    Color text_muted;
    
    // Accents
    Color accent;
    Color accent_hover;
    Color success;
    Color warning;
    Color error;
    
    // Editor syntax colors
    Color syn_keyword;
    Color syn_string;
    Color syn_number;
    Color syn_comment;
    Color syn_function;
    Color syn_builtin;
    Color syn_operator;
    
    // Borders
    Color border;
    Color border_focus;
    
    // Console
    Color console_bg;
    Color console_output;
    Color console_error;
    Color console_warn;
    Color console_info;

    // Tab bar
    Color tab_bg;
    Color tab_active;
    Color tab_hover;
    
    float border_radius = 8.0f;
    float padding = 8.0f;

    static Theme load(const std::string& path) {
        Theme t;
        try {
            std::ifstream f(path);
            json j = json::parse(f);
            
            t.name = j.value("name", "Custom");
            
            auto c = [&](const std::string& key, const std::string& def) {
                return Color::from_hex(j.value(key, def));
            };
            
            t.bg_primary    = c("bg_primary", "#0d1117");
            t.bg_secondary  = c("bg_secondary", "#161b22");
            t.bg_tertiary   = c("bg_tertiary", "#1c2128");
            t.bg_editor     = c("bg_editor", "#0d1117");
            
            t.text_primary   = c("text_primary", "#e6edf3");
            t.text_secondary = c("text_secondary", "#8b949e");
            t.text_muted     = c("text_muted", "#484f58");
            
            t.accent       = c("accent", "#58a6ff");
            t.accent_hover = c("accent_hover", "#79c0ff");
            t.success      = c("success", "#3fb950");
            t.warning      = c("warning", "#d29922");
            t.error        = c("error", "#f85149");
            
            t.syn_keyword  = c("syn_keyword", "#ff7b72");
            t.syn_string   = c("syn_string", "#a5d6ff");
            t.syn_number   = c("syn_number", "#79c0ff");
            t.syn_comment  = c("syn_comment", "#8b949e");
            t.syn_function = c("syn_function", "#d2a8ff");
            t.syn_builtin  = c("syn_builtin", "#ffa657");
            t.syn_operator = c("syn_operator", "#ff7b72");
            
            t.border       = c("border", "#30363d");
            t.border_focus = c("border_focus", "#58a6ff");
            
            t.console_bg     = c("console_bg", "#0d1117");
            t.console_output = c("console_output", "#e6edf3");
            t.console_error  = c("console_error", "#f85149");
            t.console_warn   = c("console_warn", "#d29922");
            t.console_info   = c("console_info", "#58a6ff");
            
            t.tab_bg     = c("tab_bg", "#161b22");
            t.tab_active = c("tab_active", "#0d1117");
            t.tab_hover  = c("tab_hover", "#1c2128");
            
            t.border_radius = j.value("border_radius", 8.0f);
            t.padding = j.value("padding", 8.0f);
        } catch (...) {
            t = midnight();
        }
        return t;
    }
    
    static Theme midnight() {
        Theme t;
        t.name = "Midnight";
        
        t.bg_primary    = Color::from_hex("#0a0e14");
        t.bg_secondary  = Color::from_hex("#0f131a");
        t.bg_tertiary   = Color::from_hex("#151a23");
        t.bg_editor     = Color::from_hex("#0a0e14");
        
        t.text_primary   = Color::from_hex("#e6edf3");
        t.text_secondary = Color::from_hex("#7a828e");
        t.text_muted     = Color::from_hex("#444c56");
        
        t.accent       = Color::from_hex("#6e40c9");
        t.accent_hover = Color::from_hex("#8957e5");
        t.success      = Color::from_hex("#238636");
        t.warning      = Color::from_hex("#d29922");
        t.error        = Color::from_hex("#da3633");
        
        t.syn_keyword  = Color::from_hex("#ff7b72");
        t.syn_string   = Color::from_hex("#a5d6ff");
        t.syn_number   = Color::from_hex("#79c0ff");
        t.syn_comment  = Color::from_hex("#8b949e");
        t.syn_function = Color::from_hex("#d2a8ff");
        t.syn_builtin  = Color::from_hex("#ffa657");
        t.syn_operator = Color::from_hex("#ff7b72");
        
        t.border       = Color::from_hex("#1c2128");
        t.border_focus = Color::from_hex("#6e40c9");
        
        t.console_bg     = Color::from_hex("#0a0e14");
        t.console_output = Color::from_hex("#e6edf3");
        t.console_error  = Color::from_hex("#f85149");
        t.console_warn   = Color::from_hex("#d29922");
        t.console_info   = Color::from_hex("#58a6ff");
        
        t.tab_bg     = Color::from_hex("#0f131a");
        t.tab_active = Color::from_hex("#0a0e14");
        t.tab_hover  = Color::from_hex("#151a23");
        
        return t;
    }
    
    std::string generate_css() const;
};

class ThemeManager {
public:
    static ThemeManager& instance() {
        static ThemeManager inst;
        return inst;
    }
    
    void load_themes(const std::string& dir);
    Theme& current() { return current_; }
    void set_theme(const std::string& name);
    std::vector<std::string> available() const;

private:
    ThemeManager() : current_(Theme::midnight()) {}
    
    Theme current_;
    std::unordered_map<std::string, Theme> themes_;
};

} // namespace oss