#pragma once

#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <map>
#include <nlohmann/json.hpp>

namespace oss {

using json = nlohmann::json;

struct ScriptInfo {
    std::string title;
    std::string script;
    std::string game;
    std::string author;
    std::string id;
    std::string description;
    std::string created_at;
    std::string updated_at;
    int views = 0;
    int likes = 0;
    bool verified = false;
    bool universal = false;
    std::vector<std::string> tags;
};

class QuorumAPI {
public:
    static QuorumAPI& instance() {
        static QuorumAPI inst;
        return inst;
    }

    std::vector<ScriptInfo> search_scripts(const std::string& query, int page = 1);
    std::vector<ScriptInfo> get_trending(int page = 1);
    std::vector<ScriptInfo> get_scripts_for_game(const std::string& game_id, int page = 1);
    std::optional<ScriptInfo> get_script(const std::string& id);
    std::string get_script_content(const std::string& id);

    struct UpdateInfo {
        std::string version;
        std::string download_url;
        std::string changelog;
        bool available = false;
    };

    UpdateInfo check_for_updates(const std::string& current_version);

    void set_base_url(const std::string& url) { base_url_ = url; }
    void set_api_key(const std::string& key) { api_key_ = key; }
    const std::string& base_url() const { return base_url_; }

    bool is_available();
    void clear_cache();

private:
    QuorumAPI() = default;

    json api_request(const std::string& endpoint,
                     const std::map<std::string, std::string>& params = {});
    ScriptInfo parse_script(const json& s);

    std::string base_url_ = "https://scriptblox.com/api";
    std::string api_key_;

    std::map<std::string, std::pair<json, std::chrono::steady_clock::time_point>> cache_;
    std::chrono::seconds cache_ttl_{300};
};

} // namespace oss
