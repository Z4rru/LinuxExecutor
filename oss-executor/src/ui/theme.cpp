#include "theme.hpp"
#include "utils/logger.hpp"

namespace oss {

std::string Theme::generate_css() const {
    std::string css = R"(
        window, .background {
            background-color: )" + bg_primary.to_css() + R"(;
            color: )" + text_primary.to_css() + R"(;
        }
        
        .header-bar {
            background-color: )" + bg_secondary.to_css() + R"(;
            border-bottom: 1px solid )" + border.to_css() + R"(;
            padding: 4px 8px;
        }
        
        .editor-view {
            background-color: )" + bg_editor.to_css() + R"(;
            color: )" + text_primary.to_css() + R"(;
            font-family: "JetBrains Mono", "Fira Code", "Source Code Pro", monospace;
            border: 1px solid )" + border.to_css() + R"(;
            border-radius: )" + std::to_string(static_cast<int>(border_radius)) + R"(px;
        }
        
        .editor-view:focus {
            border-color: )" + border_focus.to_css() + R"(;
        }
        
        textview, textview text {
            background-color: )" + bg_editor.to_css() + R"(;
            color: )" + text_primary.to_css() + R"(;
            caret-color: )" + accent.to_css() + R"(;
        }
        
        .console-view {
            background-color: )" + console_bg.to_css() + R"(;
            color: )" + console_output.to_css() + R"(;
            font-family: "JetBrains Mono", monospace;
            font-size: 12px;
            border-top: 1px solid )" + border.to_css() + R"(;
        }
        
        .btn-execute {
            background: linear-gradient(135deg, )" + accent.to_css() + R"(, )" + accent_hover.to_css() + R"();
            color: white;
            border: none;
            border-radius: 6px;
            padding: 8px 20px;
            font-weight: bold;
            font-size: 13px;
            min-width: 100px;
        }
        
        .btn-execute:hover {
            background: )" + accent_hover.to_css() + R"(;
            box-shadow: 0 0 12px )" + Color(accent.r, accent.g, accent.b, 0.4f).to_css() + R"(;
        }
        
        .btn-secondary {
            background-color: )" + bg_tertiary.to_css() + R"(;
            color: )" + text_primary.to_css() + R"(;
            border: 1px solid )" + border.to_css() + R"(;
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 13px;
        }
        
        .btn-secondary:hover {
            background-color: )" + Color(accent.r, accent.g, accent.b, 0.15f).to_css() + R"(;
            border-color: )" + accent.to_css() + R"(;
        }
        
        .btn-danger {
            background-color: )" + error.to_css() + R"(;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
        }
        
        .tab-bar {
            background-color: )" + tab_bg.to_css() + R"(;
            border-bottom: 1px solid )" + border.to_css() + R"(;
        }
        
        .tab-button {
            background-color: transparent;
            color: )" + text_secondary.to_css() + R"(;
            border: none;
            padding: 8px 16px;
            border-bottom: 2px solid transparent;
            font-size: 13px;
        }
        
        .tab-button:hover {
            background-color: )" + tab_hover.to_css() + R"(;
            color: )" + text_primary.to_css() + R"(;
        }
        
        .tab-button.active {
            background-color: )" + tab_active.to_css() + R"(;
            color: )" + accent.to_css() + R"(;
            border-bottom-color: )" + accent.to_css() + R"(;
        }
        
        .status-bar {
            background-color: )" + bg_secondary.to_css() + R"(;
            color: )" + text_muted.to_css() + R"(;
            font-size: 12px;
            padding: 2px 12px;
            border-top: 1px solid )" + border.to_css() + R"(;
        }
        
        .status-connected {
            color: )" + success.to_css() + R"(;
        }
        
        .status-disconnected {
            color: )" + error.to_css() + R"(;
        }
        
        .sidebar {
            background-color: )" + bg_secondary.to_css() + R"(;
            border-right: 1px solid )" + border.to_css() + R"(;
        }
        
        .script-list row {
            padding: 8px 12px;
            border-bottom: 1px solid )" + Color(border.r, border.g, border.b, 0.3f).to_css() + R"(;
        }
        
        .script-list row:hover {
            background-color: )" + tab_hover.to_css() + R"(;
        }
        
        .search-entry {
            background-color: )" + bg_tertiary.to_css() + R"(;
            color: )" + text_primary.to_css() + R"(;
            border: 1px solid )" + border.to_css() + R"(;
            border-radius: 6px;
            padding: 6px 12px;
        }
        
        .search-entry:focus {
            border-color: )" + border_focus.to_css() + R"(;
        }
        
        .error-text { color: )" + console_error.to_css() + R"(; }
        .warn-text { color: )" + console_warn.to_css() + R"(; }
        .info-text { color: )" + console_info.to_css() + R"(; }

        tooltip {
            background-color: )" + bg_tertiary.to_css() + R"(;
            color: )" + text_primary.to_css() + R"(;
            border: 1px solid )" + border.to_css() + R"(;
            border-radius: 4px;
        }
        
        scrollbar slider {
            background-color: )" + Color(text_muted.r, text_muted.g, text_muted.b, 0.3f).to_css() + R"(;
            border-radius: 4px;
            min-width: 6px;
        }
        
        scrollbar slider:hover {
            background-color: )" + Color(text_muted.r, text_muted.g, text_muted.b, 0.5f).to_css() + R"(;
        }
    )";
    
    return css;
}

void ThemeManager::load_themes(const std::string& dir) {
    // Always have built-in themes
    themes_["midnight"] = Theme::midnight();
    
    // Load custom themes from directory
    if (std::filesystem::exists(dir)) {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.path().extension() == ".json") {
                try {
                    Theme t = Theme::load(entry.path().string());
                    themes_[t.name] = t;
                    LOG_INFO("Loaded theme: {}", t.name);
                } catch (const std::exception& e) {
                    LOG_WARN("Failed to load theme {}: {}", 
                             entry.path().string(), e.what());
                }
            }
        }
    }
}

void ThemeManager::set_theme(const std::string& name) {
    auto it = themes_.find(name);
    if (it != themes_.end()) {
        current_ = it->second;
    } else {
        current_ = Theme::midnight();
    }
}

std::vector<std::string> ThemeManager::available() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : themes_) {
        names.push_back(name);
    }
    return names;
}

} // namespace oss