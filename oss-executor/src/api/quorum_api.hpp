#pragma once

#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <nlohmann/json.hpp>

namespace oss {

using json = nlohmann::json;

struct ScriptInfo {
    std::string title;
    std::string script;
    std::string game;
    std::string author;
    int views = 0;
    bool verified = false;
    std::string created_at;
};

class QuorumAPI {
public:
    static QuorumAPI& instance() {
        static QuorumAPI inst;
        return inst;
    }

    // Script Hub
    std::vector<ScriptInfo> search_scripts(const std::string& query, int page = 1);
    std::vector<ScriptInfo> get_trending(int page = 1);
    std::vector<ScriptInfo> get_scripts_for_game(const std::string& game_id, int page = 1);
    std::optional<ScriptInfo> get_script(const std::string& id);

    // Update checking
    struct UpdateInfo {
        std::string version;
        std::string download_url;
        std::string changelog;
        bool available = false;
    };
    
    UpdateInfo check_for_updates(const std::string& current_version);

    // API configuration
    void set_base_url(const std::string& url) { base_url_ = url; }
    void set_api_key(const std::string& key) { api_key_ = key; }

private:
    QuorumAPI() = default;
    
    json api_request(const std::string& endpoint, 
                     const std::map<std::string, std::string>& params = {});
    
    std::string base_url_ = "https://scriptblox.com/api";
    std::string api_key_;
};

} // namespace oss