#include "lua_engine.hpp"
#include "utils/http.hpp"
#include "utils/crypto.hpp"
#include "utils/config.hpp"

#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <array>

namespace oss {

// Store engine pointer for static callbacks
static thread_local LuaEngine* current_engine = nullptr;

LuaEngine::LuaEngine() = default;

LuaEngine::~LuaEngine() {
    shutdown();
}

bool LuaEngine::init() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (L_) shutdown();
    
    L_ = luaL_newstate();
    if (!L_) {
        LOG_ERROR("Failed to create Lua state");
        return false;
    }

    luaL_openlibs(L_);
    setup_environment();
    register_custom_libs();
    sandbox();
    
    running_ = true;
    LOG_INFO("Lua engine initialized (LuaJIT)");
    return true;
}

void LuaEngine::shutdown() {
    running_ = false;
    if (L_) {
        lua_close(L_);
        L_ = nullptr;
    }
}

void LuaEngine::reset() {
    shutdown();
    init();
}

bool LuaEngine::execute(const std::string& script, const std::string& chunk_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!L_ || !running_) {
        if (error_cb_) {
            error_cb_({"Engine not initialized", -1, chunk_name});
        }
        return false;
    }

    current_engine = this;

    // Set up timeout hook
    lua_sethook(L_, [](lua_State* L, lua_Debug*) {
        if (current_engine && !current_engine->is_running()) {
            luaL_error(L, "Script execution cancelled");
        }
    }, LUA_MASKCOUNT, 1000000);

    int status = luaL_loadbuffer(L_, script.c_str(), script.size(), chunk_name.c_str());
    
    if (status != 0) {
        std::string err = lua_tostring(L_, -1);
        lua_pop(L_, 1);
        
        LuaError error;
        error.message = err;
        error.source = chunk_name;
        
        // Parse line number from error
        auto colon1 = err.find(':');
        if (colon1 != std::string::npos) {
            auto colon2 = err.find(':', colon1 + 1);
            if (colon2 != std::string::npos) {
                try {
                    error.line = std::stoi(err.substr(colon1 + 1, colon2 - colon1 - 1));
                } catch (...) {}
            }
        }
        
        if (error_cb_) error_cb_(error);
        LOG_ERROR("Lua compile error: {}", err);
        return false;
    }

    // Push error handler
    lua_pushcfunction(L_, lua_pcall_handler);
    lua_insert(L_, -2);

    status = lua_pcall(L_, 0, LUA_MULTRET, -2);
    
    if (status != 0) {
        std::string err = lua_tostring(L_, -1);
        lua_pop(L_, 2); // error + handler
        
        LuaError error;
        error.message = err;
        error.source = chunk_name;
        
        if (error_cb_) error_cb_(error);
        LOG_ERROR("Lua runtime error: {}", err);
        return false;
    }

    // Remove error handler
    lua_remove(L_, 1);
    
    lua_sethook(L_, nullptr, 0, 0);
    current_engine = nullptr;
    
    return true;
}

bool LuaEngine::execute_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (error_cb_) {
            error_cb_({"Cannot open file: " + path, -1, path});
        }
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    return execute(content, "@" + path);
}

void LuaEngine::register_function(const std::string& name, lua_CFunction func) {
    if (L_) {
        lua_pushcfunction(L_, func);
        lua_setglobal(L_, name.c_str());
    }
}

void LuaEngine::register_library(const std::string& name, const luaL_Reg* funcs) {
    if (L_) {
        luaL_register(L_, name.c_str(), funcs);
        lua_pop(L_, 1);
    }
}

void LuaEngine::set_global_string(const std::string& name, const std::string& value) {
    if (L_) {
        lua_pushstring(L_, value.c_str());
        lua_setglobal(L_, name.c_str());
    }
}

void LuaEngine::set_global_number(const std::string& name, double value) {
    if (L_) {
        lua_pushnumber(L_, value);
        lua_setglobal(L_, name.c_str());
    }
}

void LuaEngine::set_global_bool(const std::string& name, bool value) {
    if (L_) {
        lua_pushboolean(L_, value);
        lua_setglobal(L_, name.c_str());
    }
}

std::optional<std::string> LuaEngine::get_global_string(const std::string& name) {
    if (!L_) return std::nullopt;
    lua_getglobal(L_, name.c_str());
    if (lua_isstring(L_, -1)) {
        std::string val = lua_tostring(L_, -1);
        lua_pop(L_, 1);
        return val;
    }
    lua_pop(L_, 1);
    return std::nullopt;
}

void LuaEngine::setup_environment() {
    // Override print
    lua_pushcfunction(L_, lua_print);
    lua_setglobal(L_, "print");
    
    lua_pushcfunction(L_, lua_warn_handler);
    lua_setglobal(L_, "warn");
}

void LuaEngine::register_custom_libs() {
    // File system functions
    register_function("readfile", lua_readfile);
    register_function("writefile", lua_writefile);
    register_function("appendfile", lua_appendfile);
    register_function("isfile", lua_isfile);
    register_function("listfiles", lua_listfiles);
    register_function("delfolder", lua_delfolder);
    register_function("makefolder", lua_makefolder);

    // HTTP functions
    static const luaL_Reg http_lib[] = {
        {"get", lua_http_get},
        {"post", lua_http_post},
        {nullptr, nullptr}
    };
    register_library("http", http_lib);
    
    // Also register as request synonym
    lua_getglobal(L_, "http");
    lua_getfield(L_, -1, "get");
    lua_setglobal(L_, "http_get");
    lua_pop(L_, 1);

    // Utility functions
    register_function("wait", lua_wait);
    register_function("spawn", lua_spawn);
    register_function("getclipboard", lua_getclipboard);
    register_function("setclipboard", lua_setclipboard);
    register_function("identifyexecutor", lua_identifyexecutor);
    register_function("getexecutorname", lua_getexecutorname);
    register_function("gethwid", lua_get_hwid);
    
    // Console functions
    static const luaL_Reg console_lib[] = {
        {"print", lua_rconsole_print},
        {"clear", lua_rconsole_clear},
        {nullptr, nullptr}
    };
    register_library("rconsole", console_lib);

    // Crypto functions
    static const luaL_Reg crypt_lib[] = {
        {"base64encode", lua_base64_encode},
        {"base64decode", lua_base64_decode},
        {"sha256", lua_sha256},
        {nullptr, nullptr}
    };
    register_library("crypt", crypt_lib);

    // Set executor identity globals
    set_global_string("_EXECUTOR", "OSS Executor");
    set_global_string("_EXECUTOR_VERSION", "2.0.0");
    set_global_number("_EXECUTOR_LEVEL", 8);
    set_global_bool("_OSS", true);
    
    // Compatibility aliases
    execute(R"(
        task = task or {}
        task.wait = wait
        task.spawn = spawn
        
        syn = syn or {}
        syn.request = function(opts)
            if opts.Method == "POST" then
                return http.post(opts.Url, opts.Body or "", opts.Headers or {})
            else
                return http.get(opts.Url, opts.Headers or {})
            end
        end
        
        request = syn.request
        http_request = syn.request
        
        game = game or {HttpGet = function(_, url) return http.get(url).Body end}
    )", "=env_setup");
}

void LuaEngine::sandbox() {
    // Remove dangerous functions but keep useful ones
    execute(R"(
        -- Sandboxing: remove dangerous os functions
        local safe_os = {
            time = os.time,
            clock = os.clock,
            date = os.date,
            difftime = os.difftime
        }
        os = safe_os
        
        -- Remove loadfile/dofile (use readfile + loadstring instead)
        loadfile = nil
        dofile = nil
    )", "=sandbox");
}

// Static callback implementations

int LuaEngine::lua_print(lua_State* L) {
    int nargs = lua_gettop(L);
    std::string output;
    
    for (int i = 1; i <= nargs; i++) {
        if (i > 1) output += "\t";
        
        if (lua_isstring(L, i)) {
            output += lua_tostring(L, i);
        } else if (lua_isnil(L, i)) {
            output += "nil";
        } else if (lua_isboolean(L, i)) {
            output += lua_toboolean(L, i) ? "true" : "false";
        } else if (lua_isnumber(L, i)) {
            output += std::to_string(lua_tonumber(L, i));
        } else {
            output += luaL_typename(L, i);
            output += ": 0x";
            char buf[32];
            snprintf(buf, sizeof(buf), "%p", lua_topointer(L, i));
            output += buf;
        }
    }
    
    if (current_engine && current_engine->output_cb_) {
        current_engine->output_cb_(output);
    }
    
    LOG_INFO("[Lua] {}", output);
    return 0;
}

int LuaEngine::lua_warn_handler(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);
    if (current_engine && current_engine->output_cb_) {
        current_engine->output_cb_(std::string("[WARN] ") + msg);
    }
    LOG_WARN("[Lua] {}", msg);
    return 0;
}

int LuaEngine::lua_pcall_handler(lua_State* L) {
    const char* msg = lua_tostring(L, -1);
    if (!msg) msg = "Unknown error";
    
    luaL_traceback(L, L, msg, 1);
    return 1;
}

int LuaEngine::lua_http_get(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    
    auto response = Http::instance().get(url);
    
    lua_newtable(L);
    lua_pushstring(L, response.body.c_str());
    lua_setfield(L, -2, "Body");
    lua_pushinteger(L, response.status_code);
    lua_setfield(L, -2, "StatusCode");
    lua_pushboolean(L, response.success());
    lua_setfield(L, -2, "Success");
    
    if (!response.error.empty()) {
        lua_pushstring(L, response.error.c_str());
        lua_setfield(L, -2, "Error");
    }
    
    // Headers table
    lua_newtable(L);
    for (const auto& [k, v] : response.headers) {
        lua_pushstring(L, v.c_str());
        lua_setfield(L, -2, k.c_str());
    }
    lua_setfield(L, -2, "Headers");
    
    return 1;
}

int LuaEngine::lua_http_post(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    const char* body = luaL_optstring(L, 2, "");
    
    std::map<std::string, std::string> headers;
    if (lua_istable(L, 3)) {
        lua_pushnil(L);
        while (lua_next(L, 3)) {
            if (lua_isstring(L, -2) && lua_isstring(L, -1)) {
                headers[lua_tostring(L, -2)] = lua_tostring(L, -1);
            }
            lua_pop(L, 1);
        }
    }
    
    auto response = Http::instance().post(url, body, headers);
    
    lua_newtable(L);
    lua_pushstring(L, response.body.c_str());
    lua_setfield(L, -2, "Body");
    lua_pushinteger(L, response.status_code);
    lua_setfield(L, -2, "StatusCode");
    lua_pushboolean(L, response.success());
    lua_setfield(L, -2, "Success");
    
    return 1;
}

int LuaEngine::lua_wait(lua_State* L) {
    double seconds = luaL_optnumber(L, 1, 0.03);
    auto ms = std::chrono::milliseconds(static_cast<int>(seconds * 1000));
    std::this_thread::sleep_for(ms);
    lua_pushnumber(L, seconds);
    return 1;
}

int LuaEngine::lua_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    
    // Create a coroutine
    lua_State* co = lua_newthread(L);
    lua_pushvalue(L, 1);
    lua_xmove(L, co, 1);
    
    int status = lua_resume(co, 0);
    if (status != 0 && status != LUA_YIELD) {
        const char* err = lua_tostring(co, -1);
        if (current_engine && current_engine->error_cb_) {
            current_engine->error_cb_({err ? err : "spawn error", -1, "spawn"});
        }
    }
    
    return 1; // Return thread
}

int LuaEngine::lua_readfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;
    
    // Security: prevent directory traversal
    auto canonical = std::filesystem::weakly_canonical(full_path);
    auto base_canonical = std::filesystem::weakly_canonical(base);
    if (canonical.string().find(base_canonical.string()) != 0) {
        return luaL_error(L, "Access denied: path traversal detected");
    }
    
    std::ifstream file(full_path);
    if (!file.is_open()) {
        return luaL_error(L, "Cannot open file: %s", path);
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    lua_pushstring(L, content.c_str());
    return 1;
}

int LuaEngine::lua_writefile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* content = luaL_checkstring(L, 2);
    
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;
    
    auto canonical = std::filesystem::weakly_canonical(full_path);
    auto base_canonical = std::filesystem::weakly_canonical(base);
    if (canonical.string().find(base_canonical.string()) != 0) {
        return luaL_error(L, "Access denied: path traversal detected");
    }
    
    std::filesystem::create_directories(std::filesystem::path(full_path).parent_path());
    
    std::ofstream file(full_path);
    if (!file.is_open()) {
        return luaL_error(L, "Cannot write file: %s", path);
    }
    
    file << content;
    return 0;
}

int LuaEngine::lua_appendfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* content = luaL_checkstring(L, 2);
    
    std::string full_path = Config::instance().home_dir() + "/workspace/" + path;
    std::ofstream file(full_path, std::ios::app);
    if (!file.is_open()) {
        return luaL_error(L, "Cannot append to file: %s", path);
    }
    
    file << content;
    return 0;
}

int LuaEngine::lua_isfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string full_path = Config::instance().home_dir() + "/workspace/" + path;
    lua_pushboolean(L, std::filesystem::exists(full_path));
    return 1;
}

int LuaEngine::lua_listfiles(lua_State* L) {
    const char* path = luaL_optstring(L, 1, "");
    std::string full_path = Config::instance().home_dir() + "/workspace/" + path;
    
    lua_newtable(L);
    int index = 1;
    
    if (std::filesystem::exists(full_path) && std::filesystem::is_directory(full_path)) {
        for (const auto& entry : std::filesystem::directory_iterator(full_path)) {
            lua_pushstring(L, entry.path().filename().string().c_str());
            lua_rawseti(L, -2, index++);
        }
    }
    
    return 1;
}

int LuaEngine::lua_delfolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string full_path = Config::instance().home_dir() + "/workspace/" + path;
    std::filesystem::remove_all(full_path);
    return 0;
}

int LuaEngine::lua_makefolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string full_path = Config::instance().home_dir() + "/workspace/" + path;
    std::filesystem::create_directories(full_path);
    return 0;
}

int LuaEngine::lua_getclipboard(lua_State* L) {
    // Use xclip on Linux
    std::array<char, 4096> buffer;
    std::string result;
    
    FILE* pipe = popen("xclip -selection clipboard -o 2>/dev/null || xsel --clipboard --output 2>/dev/null", "r");
    if (pipe) {
        while (fgets(buffer.data(), buffer.size(), pipe)) {
            result += buffer.data();
        }
        pclose(pipe);
    }
    
    lua_pushstring(L, result.c_str());
    return 1;
}

int LuaEngine::lua_setclipboard(lua_State* L) {
    const char* text = luaL_checkstring(L, 1);
    
    std::string cmd = "echo -n '" + std::string(text) + "' | xclip -selection clipboard 2>/dev/null || echo -n '" + std::string(text) + "' | xsel --clipboard --input 2>/dev/null";
        (void)system(cmd.c_str());
    
    return 0;
}

int LuaEngine::lua_identifyexecutor(lua_State* L) {
    lua_pushstring(L, "OSS Executor");
    lua_pushstring(L, "2.0.0");
    return 2;
}

int LuaEngine::lua_getexecutorname(lua_State* L) {
    lua_pushstring(L, "OSS Executor");
    return 1;
}

int LuaEngine::lua_get_hwid(lua_State* L) {
    std::string hwid;
    std::ifstream f("/etc/machine-id");
    if (f.is_open()) {
        std::getline(f, hwid);
    } else {
        hwid = "linux-unknown";
    }
    
    lua_pushstring(L, Crypto::sha256(hwid).c_str());
    return 1;
}

int LuaEngine::lua_rconsole_print(lua_State* L) {
    return lua_print(L);
}

int LuaEngine::lua_rconsole_clear(lua_State* L) {
    (void)L;
    if (current_engine && current_engine->output_cb_) {
        current_engine->output_cb_("\x1B[CLEAR]"); // Special clear signal
    }
    return 0;
}

int LuaEngine::lua_base64_encode(lua_State* L) {
    size_t len;
    const char* data = luaL_checklstring(L, 1, &len);
    std::vector<uint8_t> input(data, data + len);
    std::string encoded = Crypto::base64_encode(input);
    lua_pushstring(L, encoded.c_str());
    return 1;
}

int LuaEngine::lua_base64_decode(lua_State* L) {
    const char* encoded = luaL_checkstring(L, 1);
    
      // Base64 decode lookup table (C++ compatible)
    static const auto table = []() {
        std::array<unsigned char, 256> t{};
        t.fill(0);
        const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (size_t i = 0; i < 64; ++i) {
            t[static_cast<unsigned char>(chars[i])] = static_cast<unsigned char>(i);
        }
        return t;
    }();
    
    std::string input(encoded);
    std::string output;
    
    size_t i = 0;
    while (i < input.size()) {
        uint32_t n = 0;
        int pad = 0;
        for (int j = 0; j < 4 && i < input.size(); j++, i++) {
            if (input[i] == '=') { pad++; n <<= 6; }
            else { n = (n << 6) | table[(unsigned char)input[i]]; }
        }
        output += static_cast<char>((n >> 16) & 0xFF);
        if (pad < 2) output += static_cast<char>((n >> 8) & 0xFF);
        if (pad < 1) output += static_cast<char>(n & 0xFF);
    }
    
    lua_pushlstring(L, output.c_str(), output.size());
    return 1;
}

int LuaEngine::lua_sha256(lua_State* L) {
    const char* input = luaL_checkstring(L, 1);
    std::string hash = Crypto::sha256(input);
    lua_pushstring(L, hash.c_str());
    return 1;
}


} // namespace oss
