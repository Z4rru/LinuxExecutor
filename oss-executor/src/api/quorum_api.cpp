#include "quorum_api.hpp"
#include "utils/http.hpp"
#include "utils/logger.hpp"

namespace oss {

json QuorumAPI::api_request(const std::string& endpoint,
                             const std::map<std::string, std::string>& params) {
    std::string url = base_url_ + endpoint;
    
    if (!params.empty()) {
        url += "?";
        bool first = true;
        for (const auto& [key, value] : params) {
            if (!first) url += "&";
            url += key + "=" + value;
            first = false;
        }
    }

    std::map<std::string, std::string> headers;
    headers["Accept"] = "application/json";
    if (!api_key_.empty()) {
        headers["Authorization"] = "Bearer " + api_key_;
    }

    auto response = Http::instance().get(url, headers);
    
    if (!response.success()) {
        LOG_WARN("API request failed: {} - {}", response.status_code, response.error);
        return json{};
    }

    try {
        return json::parse(response.body);
    } catch (const json::parse_error& e) {
        LOG_ERROR("JSON parse error: {}", e.what());
        return json{};
    }
}

std::vector<ScriptInfo> QuorumAPI::search_scripts(const std::string& query, int page) {
    std::vector<ScriptInfo> results;
    
    auto data = api_request("/script/search", {
        {"q", query},
        {"page", std::to_string(page)},
        {"max", "20"}
    });
    
    if (data.is_null() || !data.contains("result")) return results;
    
    try {
        auto& scripts = data["result"]["scripts"];
        for (const auto& s : scripts) {
            ScriptInfo info;
            info.title = s.value("title", "Unknown");
            info.script = s.value("script", "");
            info.game = s.value("game", json{}).value("name", "Universal");
            info.author = s.value("owner", json{}).value("username", "Anonymous");
            info.views = s.value("views", 0);
            info.verified = s.value("verified", false);
            info.created_at = s.value("createdAt", "");
            results.push_back(info);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Error parsing scripts: {}", e.what());
    }
    
    return results;
}

std::vector<ScriptInfo> QuorumAPI::get_trending(int page) {
    std::vector<ScriptInfo> results;
    
    auto data = api_request("/script/fetch", {
        {"page", std::to_string(page)},
        {"max", "20"}
    });
    
    if (data.is_null() || !data.contains("result")) return results;
    
    try {
        auto& scripts = data["result"]["scripts"];
        for (const auto& s : scripts) {
            ScriptInfo info;
            info.title = s.value("title", "Unknown");
            info.script = s.value("script", "");
            info.game = s.value("game", json{}).value("name", "Universal");
            info.author = s.value("owner", json{}).value("username", "Anonymous");
            info.views = s.value("views", 0);
            info.verified = s.value("verified", false);
            results.push_back(info);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Error parsing trending: {}", e.what());
    }
    
    return results;
}

std::vector<ScriptInfo> QuorumAPI::get_scripts_for_game(const std::string& game_id, int page) {
    return search_scripts(game_id, page);
}

std::optional<ScriptInfo> QuorumAPI::get_script(const std::string& id) {
    auto data = api_request("/script/" + id);
    
    if (data.is_null() || !data.contains("script")) return std::nullopt;
    
    try {
        auto& s = data["script"];
        ScriptInfo info;
        info.title = s.value("title", "Unknown");
        info.script = s.value("script", "");
        info.game = s.value("game", json{}).value("name", "Universal");
        info.author = s.value("owner", json{}).value("username", "Anonymous");
        info.views = s.value("views", 0);
        info.verified = s.value("verified", false);
        return info;
    } catch (...) {}
    
    return std::nullopt;
}

QuorumAPI::UpdateInfo QuorumAPI::check_for_updates(const std::string& current_version) {
    UpdateInfo info;
    
    auto response = Http::instance().get(
        "https://api.github.com/repos/oss-executor/oss-executor/releases/latest"
    );
    
    if (!response.success()) return info;
    
    try {
        auto data = json::parse(response.body);
        info.version = data.value("tag_name", current_version);
        info.changelog = data.value("body", "");
        
        if (info.version != current_version && info.version > current_version) {
            info.available = true;
            auto& assets = data["assets"];
            for (const auto& asset : assets) {
                std::string name = asset.value("name", "");
                if (name.find("linux") != std::string::npos) {
                    info.download_url = asset.value("browser_download_url", "");
                    break;
                }
            }
        }
    } catch (...) {}
    
    return info;
}

} // namespace oss