#include "quorum_api.hpp"
#include "utils/http.hpp"
#include "utils/logger.hpp"
#include "core/executor.hpp"

namespace oss {

static std::string safe_nested_string(const json& obj,
                                       const std::string& outer_key,
                                       const std::string& inner_key,
                                       const std::string& fallback) {
    if (!obj.contains(outer_key) || obj[outer_key].is_null() || !obj[outer_key].is_object())
        return fallback;
    const auto& inner = obj[outer_key];
    if (!inner.contains(inner_key) || inner[inner_key].is_null() || !inner[inner_key].is_string())
        return fallback;
    return inner[inner_key].get<std::string>();
}

template<typename T>
static T safe_value(const json& obj, const std::string& key, const T& fallback) {
    if (!obj.is_object() || !obj.contains(key) || obj[key].is_null()) return fallback;
    try { return obj[key].get<T>(); }
    catch (...) { return fallback; }
}

ScriptInfo QuorumAPI::parse_script(const json& s) {
    ScriptInfo info;
    info.title       = safe_value<std::string>(s, "title", "Unknown");
    info.script      = safe_value<std::string>(s, "script", "");
    info.id          = safe_value<std::string>(s, "_id", "");
    info.description = safe_value<std::string>(s, "description", "");
    info.views       = safe_value<int>(s, "views", 0);
    info.likes       = safe_value<int>(s, "likes", 0);
    info.verified    = safe_value<bool>(s, "verified", false);
    info.universal   = safe_value<bool>(s, "isUniversal", false);
    info.created_at  = safe_value<std::string>(s, "createdAt", "");
    info.updated_at  = safe_value<std::string>(s, "updatedAt", "");
    info.game        = safe_nested_string(s, "game", "name", "Universal");
    info.author      = safe_nested_string(s, "owner", "username", "Anonymous");

    if (s.contains("tags") && s["tags"].is_array()) {
        for (const auto& tag : s["tags"]) {
            if (tag.is_string())
                info.tags.push_back(tag.get<std::string>());
        }
    }

    if (info.game == "Universal") info.universal = true;

    return info;
}

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

    auto cache_key = url;
    auto now = std::chrono::steady_clock::now();
    auto it = cache_.find(cache_key);
    if (it != cache_.end()) {
        if (now - it->second.second < cache_ttl_)
            return it->second.first;
        cache_.erase(it);
    }

    std::map<std::string, std::string> headers;
    headers["Accept"] = "application/json";
    if (!api_key_.empty())
        headers["Authorization"] = "Bearer " + api_key_;

    auto response = Http::instance().get(url, headers);

    if (!response.success()) {
        LOG_WARN("API request failed: {} - {}", response.status_code, response.error);
        return json{};
    }

    try {
        auto data = json::parse(response.body);
        cache_[cache_key] = {data, now};
        return data;
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

    if (data.is_null() || !data.contains("result") || data["result"].is_null())
        return results;

    try {
        const auto& result = data["result"];

        if (!result.contains("scripts") || result["scripts"].is_null()
            || !result["scripts"].is_array()) {
            LOG_WARN("Search response missing scripts array");
            return results;
        }

        for (const auto& s : result["scripts"]) {
            if (s.is_null() || !s.is_object()) continue;
            results.push_back(parse_script(s));
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

    if (data.is_null() || !data.contains("result") || data["result"].is_null()) {
        LOG_WARN("Trending response is null or missing result");
        return results;
    }

    try {
        const auto& result = data["result"];

        if (!result.contains("scripts") || result["scripts"].is_null()
            || !result["scripts"].is_array()) {
            LOG_WARN("Trending result missing scripts array");
            return results;
        }

        for (const auto& s : result["scripts"]) {
            if (s.is_null() || !s.is_object()) continue;
            results.push_back(parse_script(s));
        }

        LOG_INFO("Loaded {} trending scripts", results.size());
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

    if (data.is_null() || !data.contains("script") || data["script"].is_null())
        return std::nullopt;

    try {
        const auto& s = data["script"];
        if (!s.is_object()) return std::nullopt;
        return parse_script(s);
    } catch (...) {}

    return std::nullopt;
}

std::string QuorumAPI::get_script_content(const std::string& id) {
    auto script = get_script(id);
    if (script.has_value())
        return script->script;
    return "";
}

QuorumAPI::UpdateInfo QuorumAPI::check_for_updates(const std::string& current_version) {
    UpdateInfo info;

    auto response = Http::instance().get(
        "https://api.github.com/repos/oss-executor/oss-executor/releases/latest"
    );

    if (!response.success()) return info;

    try {
        auto data = json::parse(response.body);
        if (data.is_null() || !data.is_object()) return info;

        info.version   = safe_value<std::string>(data, "tag_name", current_version);
        info.changelog = safe_value<std::string>(data, "body", "");

        if (info.version != current_version && info.version > current_version) {
            info.available = true;

            if (data.contains("assets") && data["assets"].is_array()) {
                for (const auto& asset : data["assets"]) {
                    if (asset.is_null() || !asset.is_object()) continue;
                    std::string name = safe_value<std::string>(asset, "name", "");
                    if (name.find("linux") != std::string::npos) {
                        info.download_url = safe_value<std::string>(
                            asset, "browser_download_url", "");
                        break;
                    }
                }
            }
        }
    } catch (...) {}

    return info;
}

bool QuorumAPI::is_available() {
    auto response = Http::instance().get(base_url_ + "/script/fetch?page=1&max=1");
    return response.success();
}

void QuorumAPI::clear_cache() {
    cache_.clear();
}

} // namespace oss
