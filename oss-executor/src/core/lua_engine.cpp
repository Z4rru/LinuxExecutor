#include "lua_engine.hpp"
#include "ui/overlay.hpp"
#include "utils/http.hpp"
#include "utils/crypto.hpp"
#include "utils/config.hpp"
#include "api/environment.hpp"

#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <array>

namespace oss {

// ---------------------------------------------------------------------------
// Engine pointer retrieval
// ---------------------------------------------------------------------------

static thread_local LuaEngine* current_engine = nullptr;

static LuaEngine* get_engine(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "__oss_engine");
    auto* eng = static_cast<LuaEngine*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return eng ? eng : current_engine;
}

// ---------------------------------------------------------------------------
// Drawing helpers (file-scope)
// ---------------------------------------------------------------------------

static const char* DRAWING_OBJ_MT = "DrawingObject";

struct DrawingHandle { int id; };

static DrawingObject::Type parse_drawing_type(const char* s) {
    if (strcmp(s, "Line") == 0)      return DrawingObject::Type::Line;
    if (strcmp(s, "Text") == 0)      return DrawingObject::Type::Text;
    if (strcmp(s, "Circle") == 0)    return DrawingObject::Type::Circle;
    if (strcmp(s, "Square") == 0)    return DrawingObject::Type::Square;
    if (strcmp(s, "Rectangle") == 0) return DrawingObject::Type::Square;
    if (strcmp(s, "Triangle") == 0)  return DrawingObject::Type::Triangle;
    if (strcmp(s, "Quad") == 0)      return DrawingObject::Type::Quad;
    if (strcmp(s, "Image") == 0)     return DrawingObject::Type::Image;
    return DrawingObject::Type::Line;
}

// Reads {X=,Y=} or {[1],[2]} into x,y
static void read_vec2(lua_State* L, int idx, double& x, double& y) {
    if (!lua_istable(L, idx)) return;
    lua_getfield(L, idx, "X");
    if (lua_isnumber(L, -1)) {
        x = lua_tonumber(L, -1); lua_pop(L, 1);
        lua_getfield(L, idx, "Y");
        if (lua_isnumber(L, -1)) y = lua_tonumber(L, -1);
        lua_pop(L, 1);
        return;
    }
    lua_pop(L, 1);
    lua_rawgeti(L, idx, 1); if (lua_isnumber(L, -1)) x = lua_tonumber(L, -1); lua_pop(L, 1);
    lua_rawgeti(L, idx, 2); if (lua_isnumber(L, -1)) y = lua_tonumber(L, -1); lua_pop(L, 1);
}

// Reads {R=,G=,B=} or {[1],[2],[3]} into r,g,b
static void read_color(lua_State* L, int idx, double& r, double& g, double& b) {
    if (!lua_istable(L, idx)) return;
    lua_getfield(L, idx, "R");
    if (lua_isnumber(L, -1)) {
        r = lua_tonumber(L, -1); lua_pop(L, 1);
        lua_getfield(L, idx, "G");
        if (lua_isnumber(L, -1)) g = lua_tonumber(L, -1); lua_pop(L, 1);
        lua_getfield(L, idx, "B");
        if (lua_isnumber(L, -1)) b = lua_tonumber(L, -1); lua_pop(L, 1);
        return;
    }
    lua_pop(L, 1);
    lua_rawgeti(L, idx, 1); if (lua_isnumber(L, -1)) r = lua_tonumber(L, -1); lua_pop(L, 1);
    lua_rawgeti(L, idx, 2); if (lua_isnumber(L, -1)) g = lua_tonumber(L, -1); lua_pop(L, 1);
    lua_rawgeti(L, idx, 3); if (lua_isnumber(L, -1)) b = lua_tonumber(L, -1); lua_pop(L, 1);
}

static void push_vec2(lua_State* L, double x, double y) {
    lua_newtable(L);
    lua_pushnumber(L, x); lua_setfield(L, -2, "X");
    lua_pushnumber(L, y); lua_setfield(L, -2, "Y");
}

static void push_color3(lua_State* L, double r, double g, double b) {
    lua_newtable(L);
    lua_pushnumber(L, r); lua_setfield(L, -2, "R");
    lua_pushnumber(L, g); lua_setfield(L, -2, "G");
    lua_pushnumber(L, b); lua_setfield(L, -2, "B");
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

LuaEngine::LuaEngine() = default;

LuaEngine::~LuaEngine() { shutdown_internal(); }

bool LuaEngine::init() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (L_) shutdown_internal();

    L_ = luaL_newstate();
    if (!L_) { LOG_ERROR("Failed to create Lua state"); return false; }

    luaL_openlibs(L_);

    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__oss_engine");

    setup_environment();
    register_custom_libs();
    register_task_lib();
    register_drawing_lib();
    register_signal_lib();
    Environment::setup(*this);
    sandbox();

    running_ = true;
    LOG_INFO("Lua engine initialized (LuaJIT)");
    return true;
}

void LuaEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    shutdown_internal();
}

void LuaEngine::shutdown_internal() {
    running_ = false;

    for (auto& task : tasks_) {
        if (L_) {
            if (task.thread_ref != LUA_NOREF)
                luaL_unref(L_, LUA_REGISTRYINDEX, task.thread_ref);
            if (task.func_ref != LUA_NOREF)
                luaL_unref(L_, LUA_REGISTRYINDEX, task.func_ref);
            for (int r : task.arg_refs)
                if (r != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, r);
        }
    }
    tasks_.clear();
    signals_.clear();

    if (L_) { lua_close(L_); L_ = nullptr; }
}

void LuaEngine::reset() { shutdown(); init(); }

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

bool LuaEngine::execute(const std::string& script, const std::string& chunk_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return execute_internal(script, chunk_name);
}

bool LuaEngine::execute_internal(const std::string& script,
                                  const std::string& chunk_name) {
    if (!L_) {
        if (error_cb_) error_cb_({"Engine not initialized", -1, chunk_name});
        return false;
    }

    running_.store(true, std::memory_order_release);
    current_engine = this;
    int base_top = lua_gettop(L_);

    lua_sethook(L_, [](lua_State* L, lua_Debug*) {
        auto* eng = get_engine(L);
        if (eng && !eng->is_running())
            luaL_error(L, "Script execution cancelled");
    }, LUA_MASKCOUNT, 1000000);

    int status = luaL_loadbuffer(L_, script.c_str(), script.size(),
                                 chunk_name.c_str());
    if (status != 0) {
        std::string err = lua_tostring(L_, -1);
        lua_settop(L_, base_top);
        LuaError error;
        error.message = err;
        error.source = chunk_name;
        auto c1 = err.find(':');
        if (c1 != std::string::npos) {
            auto c2 = err.find(':', c1 + 1);
            if (c2 != std::string::npos)
                try { error.line = std::stoi(err.substr(c1+1, c2-c1-1)); } catch (...) {}
        }
        if (error_cb_) error_cb_(error);
        LOG_ERROR("Lua compile error: {}", err);
        lua_sethook(L_, nullptr, 0, 0);
        current_engine = nullptr;
        return false;
    }

    lua_pushcfunction(L_, lua_pcall_handler);
    lua_insert(L_, -2);
    int handler_index = lua_gettop(L_) - 1;

    status = lua_pcall(L_, 0, LUA_MULTRET, handler_index);
    if (status != 0) {
        std::string err = lua_tostring(L_, -1);
        lua_settop(L_, base_top);
        LuaError error;
        error.message = err;
        error.source = chunk_name;
        if (error_cb_) error_cb_(error);
        LOG_ERROR("Lua runtime error: {}", err);
        lua_sethook(L_, nullptr, 0, 0);
        current_engine = nullptr;
        return false;
    }

    lua_settop(L_, base_top);
    lua_sethook(L_, nullptr, 0, 0);
    current_engine = nullptr;
    return true;
}

bool LuaEngine::execute_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (error_cb_) error_cb_({"Cannot open file: " + path, -1, path});
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    return execute(content, "@" + path);
}

// ---------------------------------------------------------------------------
// Tick / task scheduler
// ---------------------------------------------------------------------------

void LuaEngine::tick() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!L_ || !running_) return;
    current_engine = this;
    process_tasks();
    current_engine = nullptr;
}

void LuaEngine::process_tasks() {
    auto now = std::chrono::steady_clock::now();
    std::vector<ScheduledTask> ready, remaining;

    for (auto& task : tasks_) {
        if (task.cancelled) {
            if (task.thread_ref != LUA_NOREF)
                luaL_unref(L_, LUA_REGISTRYINDEX, task.thread_ref);
            if (task.func_ref != LUA_NOREF)
                luaL_unref(L_, LUA_REGISTRYINDEX, task.func_ref);
            for (int r : task.arg_refs)
                if (r != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, r);
            continue;
        }
        if (now >= task.resume_at) ready.push_back(std::move(task));
        else remaining.push_back(std::move(task));
    }
    tasks_ = std::move(remaining);

    for (auto& task : ready) {
        lua_State* co = nullptr;
        if (task.thread_ref != LUA_NOREF) {
            lua_rawgeti(L_, LUA_REGISTRYINDEX, task.thread_ref);
            co = lua_tothread(L_, -1);
            lua_pop(L_, 1);
        }
        if (!co && task.func_ref != LUA_NOREF) {
            co = lua_newthread(L_);
            task.thread_ref = luaL_ref(L_, LUA_REGISTRYINDEX);
            lua_rawgeti(L_, LUA_REGISTRYINDEX, task.func_ref);
            lua_xmove(L_, co, 1);
        }
        if (!co) continue;

        int nargs = 0;
        for (int ref : task.arg_refs) {
            if (ref != LUA_NOREF) {
                lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
                lua_xmove(L_, co, 1);
                luaL_unref(L_, LUA_REGISTRYINDEX, ref);
                ++nargs;
            }
        }
        task.arg_refs.clear();

        if (task.type == ScheduledTask::Type::Delay) {
            double elapsed = std::chrono::duration<double>(
                now - (task.resume_at -
                       std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                           std::chrono::duration<double>(task.delay_seconds)))).count();
            lua_pushnumber(co, elapsed);
            ++nargs;
        }

        int status = lua_resume(co, nargs);
        if (status != 0 && status != LUA_YIELD) {
            const char* err = lua_tostring(co, -1);
            if (error_cb_)
                error_cb_({err ? err : "task error", -1, "task"});
            LOG_ERROR("[Task] {}", err ? err : "unknown error");
        }

        if (task.thread_ref != LUA_NOREF)
            luaL_unref(L_, LUA_REGISTRYINDEX, task.thread_ref);
        if (task.func_ref != LUA_NOREF)
            luaL_unref(L_, LUA_REGISTRYINDEX, task.func_ref);
    }
}

int LuaEngine::schedule_task(ScheduledTask task) {
    task.id = next_task_id_++;
    tasks_.push_back(std::move(task));
    return tasks_.back().id;
}

void LuaEngine::cancel_task(int task_id) {
    for (auto& t : tasks_)
        if (t.id == task_id) { t.cancelled = true; return; }
}

size_t LuaEngine::pending_task_count() const {
    size_t c = 0;
    for (auto& t : tasks_) if (!t.cancelled) ++c;
    return c;
}

// ---------------------------------------------------------------------------
// Global registration helpers
// ---------------------------------------------------------------------------

void LuaEngine::register_function(const std::string& name, lua_CFunction func) {
    if (L_) { lua_pushcfunction(L_, func); lua_setglobal(L_, name.c_str()); }
}

void LuaEngine::register_library(const std::string& name, const luaL_Reg* funcs) {
    if (L_) { luaL_register(L_, name.c_str(), funcs); lua_pop(L_, 1); }
}

void LuaEngine::set_global_string(const std::string& n, const std::string& v) {
    if (L_) { lua_pushstring(L_, v.c_str()); lua_setglobal(L_, n.c_str()); }
}
void LuaEngine::set_global_number(const std::string& n, double v) {
    if (L_) { lua_pushnumber(L_, v); lua_setglobal(L_, n.c_str()); }
}
void LuaEngine::set_global_bool(const std::string& n, bool v) {
    if (L_) { lua_pushboolean(L_, v); lua_setglobal(L_, n.c_str()); }
}
std::optional<std::string> LuaEngine::get_global_string(const std::string& n) {
    if (!L_) return std::nullopt;
    lua_getglobal(L_, n.c_str());
    if (lua_isstring(L_, -1)) {
        std::string v = lua_tostring(L_, -1); lua_pop(L_, 1); return v;
    }
    lua_pop(L_, 1); return std::nullopt;
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

int LuaEngine::fire_signal(const std::string& name, int nargs) {
    auto it = signals_.find(name);
    if (it == signals_.end()) return 0;
    int fired = 0;
    for (auto& conn : it->second.connections) {
        if (!conn.connected || conn.callback_ref == LUA_NOREF) continue;
        lua_rawgeti(L_, LUA_REGISTRYINDEX, conn.callback_ref);
        for (int i = 0; i < nargs; ++i) lua_pushvalue(L_, -(nargs + 1));
        if (lua_pcall(L_, nargs, 0, 0) != 0) {
            LOG_ERROR("[Signal:{}] {}", name, lua_tostring(L_, -1));
            lua_pop(L_, 1);
        }
        ++fired;
    }
    if (nargs > 0) lua_pop(L_, nargs);
    return fired;
}

Signal* LuaEngine::get_signal(const std::string& n) {
    auto it = signals_.find(n);
    return it != signals_.end() ? &it->second : nullptr;
}

Signal& LuaEngine::get_or_create_signal(const std::string& n) {
    auto& s = signals_[n]; s.name = n; return s;
}

// ---------------------------------------------------------------------------
// Sandbox helpers
// ---------------------------------------------------------------------------

bool LuaEngine::is_sandboxed(const std::string& full_path,
                              const std::string& base_dir) {
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(full_path, ec);
    if (ec) return false;
    auto base_canonical = std::filesystem::weakly_canonical(base_dir, ec);
    if (ec) return false;
    std::string bs = base_canonical.string();
    if (!bs.empty() && bs.back() != '/') bs += '/';
    return canonical.string().find(bs) == 0;
}

// ---------------------------------------------------------------------------
// Environment / library setup
// ---------------------------------------------------------------------------

void LuaEngine::setup_environment() {
    lua_pushcfunction(L_, lua_print);   lua_setglobal(L_, "print");
    lua_pushcfunction(L_, lua_warn_handler); lua_setglobal(L_, "warn");
}

void LuaEngine::register_task_lib() {
    static const luaL_Reg funcs[] = {
        {"spawn",         lua_task_spawn},
        {"delay",         lua_task_delay},
        {"defer",         lua_task_defer},
        {"wait",          lua_task_wait},
        {"cancel",        lua_task_cancel},
        {"desynchronize", lua_task_desynchronize},
        {"synchronize",   lua_task_synchronize},
        {nullptr, nullptr}
    };
    register_library("task", funcs);
}

void LuaEngine::register_drawing_lib() {
    // Metatable for drawing userdata
    luaL_newmetatable(L_, DRAWING_OBJ_MT);

    lua_pushcfunction(L_, lua_drawing_index);
    lua_setfield(L_, -2, "__index");

    lua_pushcfunction(L_, lua_drawing_newindex);
    lua_setfield(L_, -2, "__newindex");

    lua_pushcfunction(L_, lua_drawing_gc);
    lua_setfield(L_, -2, "__gc");

    lua_pushcfunction(L_, lua_drawing_tostring);
    lua_setfield(L_, -2, "__tostring");

    lua_pop(L_, 1);

    // Drawing library table
    lua_newtable(L_);

    lua_pushcfunction(L_, lua_drawing_new);
    lua_setfield(L_, -2, "new");

    lua_pushcfunction(L_, lua_drawing_clear);
    lua_setfield(L_, -2, "clear");

    lua_pushcfunction(L_, lua_drawing_is_rendered);
    lua_setfield(L_, -2, "isRendered");

    lua_pushcfunction(L_, lua_drawing_get_screen_size);
    lua_setfield(L_, -2, "getScreenSize");

    lua_setglobal(L_, "Drawing");
}

void LuaEngine::register_signal_lib() {
    luaL_newmetatable(L_, "SignalObject");
    lua_pushstring(L_, "__index");
    lua_newtable(L_);
    lua_pushcfunction(L_, lua_signal_connect); lua_setfield(L_, -2, "Connect");
    lua_pushcfunction(L_, lua_signal_fire);    lua_setfield(L_, -2, "Fire");
    lua_pushcfunction(L_, lua_signal_wait);    lua_setfield(L_, -2, "Wait");
    lua_pushcfunction(L_, lua_signal_destroy); lua_setfield(L_, -2, "Destroy");
    lua_settable(L_, -3);
    lua_pushcfunction(L_, lua_signal_gc);
    lua_setfield(L_, -2, "__gc");
    lua_pop(L_, 1);

    luaL_newmetatable(L_, "SignalConnection");
    lua_pushstring(L_, "__index");
    lua_newtable(L_);
    lua_pushcfunction(L_, lua_signal_disconnect);
    lua_setfield(L_, -2, "Disconnect");
    lua_settable(L_, -3);
    lua_pop(L_, 1);

    register_function("Signal", lua_signal_new);
}

void LuaEngine::register_custom_libs() {
    register_function("readfile",    lua_readfile);
    register_function("writefile",   lua_writefile);
    register_function("appendfile",  lua_appendfile);
    register_function("isfile",      lua_isfile);
    register_function("listfiles",   lua_listfiles);
    register_function("delfolder",   lua_delfolder);
    register_function("makefolder",  lua_makefolder);

    static const luaL_Reg http_lib[] = {
        {"get",  lua_http_get},
        {"post", lua_http_post},
        {nullptr, nullptr}
    };
    register_library("http", http_lib);
    lua_getglobal(L_, "http");
    lua_getfield(L_, -1, "get");
    lua_setglobal(L_, "http_get");
    lua_pop(L_, 1);

    register_function("wait",              lua_wait);
    register_function("spawn",             lua_spawn);
    register_function("getclipboard",      lua_getclipboard);
    register_function("setclipboard",      lua_setclipboard);
    register_function("identifyexecutor",  lua_identifyexecutor);
    register_function("getexecutorname",   lua_getexecutorname);
    register_function("gethwid",           lua_get_hwid);

    static const luaL_Reg console_lib[] = {
        {"print", lua_rconsole_print},
        {"clear", lua_rconsole_clear},
        {nullptr, nullptr}
    };
    register_library("rconsole", console_lib);

    static const luaL_Reg crypt_lib[] = {
        {"base64encode", lua_base64_encode},
        {"base64decode", lua_base64_decode},
        {"sha256",       lua_sha256},
        {nullptr, nullptr}
    };
    register_library("crypt", crypt_lib);

    set_global_string("_EXECUTOR",         "OSS Executor");
    set_global_string("_EXECUTOR_VERSION", "2.0.0");
    set_global_number("_EXECUTOR_LEVEL",   8);
    set_global_bool  ("_OSS",             true);

    execute_internal(R"(
        syn = syn or {}
        syn.request = syn.request or function(opts)
            if opts.Method == "POST" then
                return http.post(opts.Url, opts.Body or "", opts.Headers or {})
            else
                return http.get(opts.Url, opts.Headers or {})
            end
        end
        request = request or syn.request
        http_request = http_request or syn.request
        game = game or {HttpGet = function(_, url) return http.get(url).Body end}
    )", "=env_setup");
}

void LuaEngine::sandbox() {
    execute_internal(R"(
        local safe_os = {
            time = os.time, clock = os.clock,
            date = os.date, difftime = os.difftime
        }
        os = safe_os
        loadfile = nil
        dofile = nil
    )", "=sandbox");
}

// ===========================================================================
//  Drawing API  — all objects live in Overlay::instance()
// ===========================================================================

int LuaEngine::lua_drawing_new(lua_State* L) {
    const char* ts = luaL_checkstring(L, 1);
    auto type = parse_drawing_type(ts);
    int id = Overlay::instance().create_object(type);

    auto* h = static_cast<DrawingHandle*>(lua_newuserdata(L, sizeof(DrawingHandle)));
    h->id = id;
    luaL_getmetatable(L, DRAWING_OBJ_MT);
    lua_setmetatable(L, -2);
    return 1;
}

int LuaEngine::lua_drawing_index(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    const char* key = luaL_checkstring(L, 2);

    // Methods
    if (strcmp(key, "Remove") == 0 || strcmp(key, "Destroy") == 0) {
        lua_pushcfunction(L, lua_drawing_remove);
        return 1;
    }

    // Snapshot the object under lock, then push Lua values without lock
    DrawingObject copy;
    bool found = false;
    Overlay::instance().update_object(h->id, [&](DrawingObject& obj) {
        copy = obj; found = true;
    });
    if (!found) { lua_pushnil(L); return 1; }

    if      (strcmp(key, "Visible") == 0)      lua_pushboolean(L, copy.visible);
    else if (strcmp(key, "ZIndex") == 0)       lua_pushinteger(L, copy.z_index);
    else if (strcmp(key, "Transparency") == 0) lua_pushnumber(L, copy.transparency);
    else if (strcmp(key, "Thickness") == 0)    lua_pushnumber(L, copy.thickness);
    else if (strcmp(key, "Filled") == 0)       lua_pushboolean(L, copy.filled);
    else if (strcmp(key, "Radius") == 0)       lua_pushnumber(L, copy.radius);
    else if (strcmp(key, "NumSides") == 0)     lua_pushinteger(L, copy.num_sides);
    else if (strcmp(key, "Center") == 0)       lua_pushboolean(L, copy.center);
    else if (strcmp(key, "Outline") == 0)      lua_pushboolean(L, copy.outline);
    else if (strcmp(key, "Text") == 0)         lua_pushstring(L, copy.text.c_str());
    else if (strcmp(key, "Font") == 0)         lua_pushinteger(L, copy.font);
    else if (strcmp(key, "Rounding") == 0)     lua_pushnumber(L, copy.rounding);
    else if (strcmp(key, "TextSize") == 0)     lua_pushnumber(L, copy.text_size);
    else if (strcmp(key, "ImageWidth") == 0)   lua_pushnumber(L, copy.image_w);
    else if (strcmp(key, "ImageHeight") == 0)  lua_pushnumber(L, copy.image_h);
    else if (strcmp(key, "Size") == 0) {
        if (copy.type == DrawingObject::Type::Text)
            lua_pushnumber(L, copy.text_size);
        else
            push_vec2(L, copy.size_x, copy.size_y);
    }
    else if (strcmp(key, "SizeXY") == 0)       push_vec2(L, copy.size_x, copy.size_y);
    else if (strcmp(key, "Position") == 0)     push_vec2(L, copy.pos_x, copy.pos_y);
    else if (strcmp(key, "From") == 0)         push_vec2(L, copy.from_x, copy.from_y);
    else if (strcmp(key, "To") == 0)           push_vec2(L, copy.to_x, copy.to_y);
    else if (strcmp(key, "Color") == 0)        push_color3(L, copy.color_r, copy.color_g, copy.color_b);
    else if (strcmp(key, "OutlineColor") == 0) push_color3(L, copy.outline_r, copy.outline_g, copy.outline_b);
    else if (strcmp(key, "PointA") == 0) {
        if (copy.type == DrawingObject::Type::Quad) push_vec2(L, copy.qa_x, copy.qa_y);
        else push_vec2(L, copy.pa_x, copy.pa_y);
    }
    else if (strcmp(key, "PointB") == 0) {
        if (copy.type == DrawingObject::Type::Quad) push_vec2(L, copy.qb_x, copy.qb_y);
        else push_vec2(L, copy.pb_x, copy.pb_y);
    }
    else if (strcmp(key, "PointC") == 0) {
        if (copy.type == DrawingObject::Type::Quad) push_vec2(L, copy.qc_x, copy.qc_y);
        else push_vec2(L, copy.pc_x, copy.pc_y);
    }
    else if (strcmp(key, "PointD") == 0)       push_vec2(L, copy.qd_x, copy.qd_y);
    else lua_pushnil(L);
    return 1;
}

int LuaEngine::lua_drawing_newindex(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    const char* key = luaL_checkstring(L, 2);
    auto& ov = Overlay::instance();

    // ---- Read all Lua values BEFORE taking the overlay lock ----

    if (strcmp(key, "Visible") == 0) {
        bool v = lua_toboolean(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.visible = v; });
    }
    else if (strcmp(key, "ZIndex") == 0) {
        int v = static_cast<int>(luaL_checkinteger(L, 3));
        ov.update_object(h->id, [v](DrawingObject& o){ o.z_index = v; });
    }
    else if (strcmp(key, "Transparency") == 0) {
        double v = luaL_checknumber(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.transparency = v; });
    }
    else if (strcmp(key, "Thickness") == 0) {
        double v = luaL_checknumber(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.thickness = v; });
    }
    else if (strcmp(key, "Filled") == 0) {
        bool v = lua_toboolean(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.filled = v; });
    }
    else if (strcmp(key, "Radius") == 0) {
        double v = luaL_checknumber(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.radius = v; });
    }
    else if (strcmp(key, "NumSides") == 0) {
        int v = static_cast<int>(luaL_checkinteger(L, 3));
        ov.update_object(h->id, [v](DrawingObject& o){ o.num_sides = v; });
    }
    else if (strcmp(key, "Center") == 0) {
        bool v = lua_toboolean(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.center = v; });
    }
    else if (strcmp(key, "Outline") == 0) {
        bool v = lua_toboolean(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.outline = v; });
    }
    else if (strcmp(key, "Text") == 0) {
        std::string v = luaL_checkstring(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.text = v; });
    }
    else if (strcmp(key, "Size") == 0) {
        if (lua_isnumber(L, 3)) {
            double v = lua_tonumber(L, 3);
            ov.update_object(h->id, [v](DrawingObject& o){ o.text_size = v; });
        } else {
            double x = 0, y = 0; read_vec2(L, 3, x, y);
            ov.update_object(h->id, [x,y](DrawingObject& o){ o.size_x = x; o.size_y = y; });
        }
    }
    else if (strcmp(key, "TextSize") == 0) {
        double v = luaL_checknumber(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.text_size = v; });
    }
    else if (strcmp(key, "Font") == 0) {
        int v = static_cast<int>(luaL_checkinteger(L, 3));
        ov.update_object(h->id, [v](DrawingObject& o){ o.font = v; });
    }
    else if (strcmp(key, "Rounding") == 0) {
        double v = luaL_checknumber(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.rounding = v; });
    }
    else if (strcmp(key, "Position") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){ o.pos_x = x; o.pos_y = y; });
    }
    else if (strcmp(key, "From") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){ o.from_x = x; o.from_y = y; });
    }
    else if (strcmp(key, "To") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){ o.to_x = x; o.to_y = y; });
    }
    else if (strcmp(key, "Color") == 0) {
        double r = 1, g = 1, b = 1; read_color(L, 3, r, g, b);
        ov.update_object(h->id, [r,g,b](DrawingObject& o){
            o.color_r = r; o.color_g = g; o.color_b = b; });
    }
    else if (strcmp(key, "OutlineColor") == 0) {
        double r = 0, g = 0, b = 0; read_color(L, 3, r, g, b);
        ov.update_object(h->id, [r,g,b](DrawingObject& o){
            o.outline_r = r; o.outline_g = g; o.outline_b = b; });
    }
    else if (strcmp(key, "PointA") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){
            if (o.type == DrawingObject::Type::Quad) { o.qa_x = x; o.qa_y = y; }
            else { o.pa_x = x; o.pa_y = y; }
        });
    }
    else if (strcmp(key, "PointB") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){
            if (o.type == DrawingObject::Type::Quad) { o.qb_x = x; o.qb_y = y; }
            else { o.pb_x = x; o.pb_y = y; }
        });
    }
    else if (strcmp(key, "PointC") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){
            if (o.type == DrawingObject::Type::Quad) { o.qc_x = x; o.qc_y = y; }
            else { o.pc_x = x; o.pc_y = y; }
        });
    }
    else if (strcmp(key, "PointD") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){ o.qd_x = x; o.qd_y = y; });
    }
    else if (strcmp(key, "SizeXY") == 0) {
        double x = 0, y = 0; read_vec2(L, 3, x, y);
        ov.update_object(h->id, [x,y](DrawingObject& o){ o.size_x = x; o.size_y = y; });
    }
    else if (strcmp(key, "ImageWidth") == 0) {
        double v = luaL_checknumber(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.image_w = v; });
    }
    else if (strcmp(key, "ImageHeight") == 0) {
        double v = luaL_checknumber(L, 3);
        ov.update_object(h->id, [v](DrawingObject& o){ o.image_h = v; });
    }
    else if (strcmp(key, "Data") == 0 || strcmp(key, "ImagePath") == 0) {
        std::string path = luaL_checkstring(L, 3);
        // Load image outside the overlay lock
        cairo_surface_t* surface = cairo_image_surface_create_from_png(path.c_str());
        if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(surface);
            surface = nullptr;
        }
        ov.update_object(h->id, [&path, surface](DrawingObject& o){
            if (o.image_surface) cairo_surface_destroy(o.image_surface);
            o.image_path = path;
            o.image_surface = surface;
        });
    }

    return 0;
}

int LuaEngine::lua_drawing_remove(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    if (h->id >= 0) {
        Overlay::instance().remove_object(h->id);
        h->id = -1;
    }
    return 0;
}

int LuaEngine::lua_drawing_gc(lua_State*) {
    // No-op: prevents deadlock if GC fires while overlay lock is held.
    // Users must call :Remove() explicitly.
    return 0;
}

int LuaEngine::lua_drawing_tostring(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    lua_pushfstring(L, "Drawing(%d)", h->id);
    return 1;
}

int LuaEngine::lua_drawing_clear(lua_State*) {
    Overlay::instance().clear_objects();
    return 0;
}

int LuaEngine::lua_drawing_is_rendered(lua_State* L) {
    lua_pushboolean(L, Overlay::instance().is_visible());
    return 1;
}

int LuaEngine::lua_drawing_get_screen_size(lua_State* L) {
    auto& ov = Overlay::instance();
    lua_newtable(L);
    lua_pushinteger(L, ov.screen_width());  lua_rawseti(L, -2, 1);
    lua_pushinteger(L, ov.screen_height()); lua_rawseti(L, -2, 2);
    return 1;
}

// ===========================================================================
//  Task library
// ===========================================================================

int LuaEngine::lua_task_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) return luaL_error(L, "engine not available");

    lua_State* co = lua_newthread(L);
    lua_pushvalue(L, 1);
    lua_xmove(L, co, 1);
    int nargs = lua_gettop(L) - 2;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 2);
        lua_xmove(L, co, 1);
    }
    int status = lua_resume(co, nargs);
    if (status != 0 && status != LUA_YIELD) {
        const char* err = lua_tostring(co, -1);
        if (eng->error_cb_)
            eng->error_cb_({err ? err : "task.spawn error", -1, "task.spawn"});
    }
    return 1;
}

int LuaEngine::lua_task_delay(lua_State* L) {
    double seconds = luaL_checknumber(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) return luaL_error(L, "engine not available");

    ScheduledTask task;
    task.type = ScheduledTask::Type::Delay;
    task.delay_seconds = seconds;
    task.resume_at = std::chrono::steady_clock::now() +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(seconds));
    lua_pushvalue(L, 2);
    task.func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    int nargs = lua_gettop(L) - 2;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 3);
        task.arg_refs.push_back(luaL_ref(L, LUA_REGISTRYINDEX));
    }
    int id = eng->schedule_task(std::move(task));
    lua_pushinteger(L, id);
    return 1;
}

int LuaEngine::lua_task_defer(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) return luaL_error(L, "engine not available");

    ScheduledTask task;
    task.type = ScheduledTask::Type::Defer;
    task.resume_at = std::chrono::steady_clock::now();
    lua_pushvalue(L, 1);
    task.func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    int nargs = lua_gettop(L) - 1;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 2);
        task.arg_refs.push_back(luaL_ref(L, LUA_REGISTRYINDEX));
    }
    int id = eng->schedule_task(std::move(task));
    lua_pushinteger(L, id);
    return 1;
}

int LuaEngine::lua_task_wait(lua_State* L) {
    double s = luaL_optnumber(L, 1, 0.03);
    std::this_thread::sleep_for(
        std::chrono::milliseconds(static_cast<int>(s * 1000)));
    lua_pushnumber(L, s);
    return 1;
}

int LuaEngine::lua_task_cancel(lua_State* L) {
    int id = static_cast<int>(luaL_checkinteger(L, 1));
    auto* eng = get_engine(L);
    if (eng) eng->cancel_task(id);
    return 0;
}

int LuaEngine::lua_task_desynchronize(lua_State*) { return 0; }
int LuaEngine::lua_task_synchronize(lua_State*)   { return 0; }

// ===========================================================================
//  Signal library
// ===========================================================================

struct SignalUserdata { char name[128]; };

int LuaEngine::lua_signal_new(lua_State* L) {
    const char* name = luaL_optstring(L, 1, "");
    auto* eng = get_engine(L);
    if (!eng) return luaL_error(L, "engine not available");

    std::string sig_name = name;
    if (sig_name.empty())
        sig_name = "signal_" + std::to_string(reinterpret_cast<uintptr_t>(L))
                   + "_" + std::to_string(lua_gc(L, LUA_GCCOUNT, 0));
    eng->get_or_create_signal(sig_name);

    auto* ud = static_cast<SignalUserdata*>(lua_newuserdata(L, sizeof(SignalUserdata)));
    memset(ud->name, 0, sizeof(ud->name));
    strncpy(ud->name, sig_name.c_str(), sizeof(ud->name) - 1);
    luaL_getmetatable(L, "SignalObject");
    lua_setmetatable(L, -2);
    return 1;
}

int LuaEngine::lua_signal_connect(lua_State* L) {
    auto* ud = static_cast<SignalUserdata*>(luaL_checkudata(L, 1, "SignalObject"));
    luaL_checktype(L, 2, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) return luaL_error(L, "engine not available");
    Signal* sig = eng->get_signal(ud->name);
    if (!sig) return luaL_error(L, "Signal destroyed");

    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    Signal::Connection conn;
    conn.callback_ref = ref;
    conn.id = sig->next_id++;
    conn.connected = true;
    sig->connections.push_back(conn);

    struct ConnUD { char sig_name[128]; int conn_id; };
    auto* cud = static_cast<ConnUD*>(lua_newuserdata(L, sizeof(ConnUD)));
    memset(cud->sig_name, 0, sizeof(cud->sig_name));
    strncpy(cud->sig_name, ud->name, sizeof(cud->sig_name) - 1);
    cud->conn_id = conn.id;
    luaL_getmetatable(L, "SignalConnection");
    lua_setmetatable(L, -2);
    return 1;
}

int LuaEngine::lua_signal_fire(lua_State* L) {
    auto* ud = static_cast<SignalUserdata*>(luaL_checkudata(L, 1, "SignalObject"));
    int nargs = lua_gettop(L) - 1;
    auto* eng = get_engine(L);
    if (!eng) return 0;
    Signal* sig = eng->get_signal(ud->name);
    if (!sig) return 0;

    for (auto& conn : sig->connections) {
        if (!conn.connected || conn.callback_ref == LUA_NOREF) continue;
        lua_rawgeti(L, LUA_REGISTRYINDEX, conn.callback_ref);
        for (int i = 0; i < nargs; ++i) lua_pushvalue(L, i + 2);
        if (lua_pcall(L, nargs, 0, 0) != 0) {
            LOG_ERROR("[Signal:{}] {}", ud->name, lua_tostring(L, -1));
            lua_pop(L, 1);
        }
    }
    return 0;
}

int LuaEngine::lua_signal_wait(lua_State* L) { return lua_yield(L, 0); }

int LuaEngine::lua_signal_disconnect(lua_State* L) {
    struct ConnUD { char sig_name[128]; int conn_id; };
    auto* cud = static_cast<ConnUD*>(luaL_checkudata(L, 1, "SignalConnection"));
    auto* eng = get_engine(L);
    if (!eng) return 0;
    Signal* sig = eng->get_signal(cud->sig_name);
    if (!sig) return 0;
    for (auto& c : sig->connections) {
        if (c.id == cud->conn_id) {
            c.connected = false;
            if (c.callback_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, c.callback_ref);
                c.callback_ref = LUA_NOREF;
            }
            break;
        }
    }
    return 0;
}

int LuaEngine::lua_signal_destroy(lua_State* L) {
    auto* ud = static_cast<SignalUserdata*>(luaL_checkudata(L, 1, "SignalObject"));
    auto* eng = get_engine(L);
    if (!eng) return 0;
    Signal* sig = eng->get_signal(ud->name);
    if (sig) {
        for (auto& c : sig->connections)
            if (c.callback_ref != LUA_NOREF)
                luaL_unref(L, LUA_REGISTRYINDEX, c.callback_ref);
        eng->signals_.erase(ud->name);
    }
    return 0;
}

int LuaEngine::lua_signal_gc(lua_State*) { return 0; }

// ===========================================================================
//  Core Lua globals
// ===========================================================================

int LuaEngine::lua_print(lua_State* L) {
    int n = lua_gettop(L);
    std::string output;
    for (int i = 1; i <= n; i++) {
        if (i > 1) output += "\t";
        if (lua_isstring(L, i))       output += lua_tostring(L, i);
        else if (lua_isnil(L, i))     output += "nil";
        else if (lua_isboolean(L, i)) output += lua_toboolean(L, i) ? "true" : "false";
        else if (lua_isnumber(L, i))  output += std::to_string(lua_tonumber(L, i));
        else {
            char buf[64];
            snprintf(buf, sizeof(buf), "%s: %p", luaL_typename(L, i), lua_topointer(L, i));
            output += buf;
        }
    }
    auto* eng = get_engine(L);
    if (eng && eng->output_cb_) eng->output_cb_(output);
    LOG_INFO("[Lua] {}", output);
    return 0;
}

int LuaEngine::lua_warn_handler(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);
    auto* eng = get_engine(L);
    if (eng && eng->output_cb_) eng->output_cb_(std::string("[WARN] ") + msg);
    LOG_WARN("[Lua] {}", msg);
    return 0;
}

int LuaEngine::lua_pcall_handler(lua_State* L) {
    const char* msg = lua_tostring(L, -1);
    if (!msg) msg = "Unknown error";
    luaL_traceback(L, L, msg, 1);
    return 1;
}

// ===========================================================================
//  HTTP
// ===========================================================================

int LuaEngine::lua_http_get(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    auto resp = Http::instance().get(url);
    lua_newtable(L);
    lua_pushstring(L, resp.body.c_str());    lua_setfield(L, -2, "Body");
    lua_pushinteger(L, resp.status_code);    lua_setfield(L, -2, "StatusCode");
    lua_pushboolean(L, resp.success());      lua_setfield(L, -2, "Success");
    if (!resp.error.empty()) {
        lua_pushstring(L, resp.error.c_str()); lua_setfield(L, -2, "Error");
    }
    lua_newtable(L);
    for (const auto& [k, v] : resp.headers) {
        lua_pushstring(L, v.c_str()); lua_setfield(L, -2, k.c_str());
    }
    lua_setfield(L, -2, "Headers");
    return 1;
}

int LuaEngine::lua_http_post(lua_State* L) {
    const char* url  = luaL_checkstring(L, 1);
    const char* body = luaL_optstring(L, 2, "");
    std::map<std::string, std::string> headers;
    if (lua_istable(L, 3)) {
        lua_pushnil(L);
        while (lua_next(L, 3)) {
            if (lua_isstring(L, -2) && lua_isstring(L, -1))
                headers[lua_tostring(L, -2)] = lua_tostring(L, -1);
            lua_pop(L, 1);
        }
    }
    auto resp = Http::instance().post(url, body, headers);
    lua_newtable(L);
    lua_pushstring(L, resp.body.c_str()); lua_setfield(L, -2, "Body");
    lua_pushinteger(L, resp.status_code); lua_setfield(L, -2, "StatusCode");
    lua_pushboolean(L, resp.success());   lua_setfield(L, -2, "Success");
    return 1;
}

// ===========================================================================
//  wait / spawn
// ===========================================================================

int LuaEngine::lua_wait(lua_State* L) {
    double s = luaL_optnumber(L, 1, 0.03);
    std::this_thread::sleep_for(
        std::chrono::milliseconds(static_cast<int>(s * 1000)));
    lua_pushnumber(L, s);
    lua_pushnumber(L, s);
    return 2;
}

int LuaEngine::lua_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_State* co = lua_newthread(L);
    lua_pushvalue(L, 1);
    lua_xmove(L, co, 1);
    int nargs = lua_gettop(L) - 2;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 2);
        lua_xmove(L, co, 1);
    }
    int status = lua_resume(co, nargs);
    if (status != 0 && status != LUA_YIELD) {
        const char* err = lua_tostring(co, -1);
        auto* eng = get_engine(L);
        if (eng && eng->error_cb_)
            eng->error_cb_({err ? err : "spawn error", -1, "spawn"});
    }
    return 1;
}

// ===========================================================================
//  Filesystem (sandboxed to workspace/)
// ===========================================================================

int LuaEngine::lua_readfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base))
        return luaL_error(L, "Access denied: path traversal detected");
    std::ifstream f(full);
    if (!f.is_open()) return luaL_error(L, "Cannot open file: %s", path);
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    lua_pushstring(L, content.c_str());
    return 1;
}

int LuaEngine::lua_writefile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* content = luaL_checkstring(L, 2);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base))
        return luaL_error(L, "Access denied: path traversal detected");
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(full).parent_path(), ec);
    std::ofstream f(full);
    if (!f.is_open()) return luaL_error(L, "Cannot write file: %s", path);
    f << content;
    return 0;
}

int LuaEngine::lua_appendfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* content = luaL_checkstring(L, 2);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base))
        return luaL_error(L, "Access denied: path traversal detected");
    std::ofstream f(full, std::ios::app);
    if (!f.is_open()) return luaL_error(L, "Cannot append to file: %s", path);
    f << content;
    return 0;
}

int LuaEngine::lua_isfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base)) { lua_pushboolean(L, false); return 1; }
    lua_pushboolean(L, std::filesystem::exists(full));
    return 1;
}

int LuaEngine::lua_listfiles(lua_State* L) {
    const char* path = luaL_optstring(L, 1, "");
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    lua_newtable(L);
    if (!is_sandboxed(full, base)) return 1;
    int idx = 1;
    if (std::filesystem::exists(full) && std::filesystem::is_directory(full)) {
        try {
            for (const auto& e : std::filesystem::directory_iterator(full)) {
                lua_pushstring(L, e.path().filename().string().c_str());
                lua_rawseti(L, -2, idx++);
            }
        } catch (...) {}
    }
    return 1;
}

int LuaEngine::lua_delfolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base))
        return luaL_error(L, "Access denied: path traversal detected");
    std::error_code ec;
    std::filesystem::remove_all(full, ec);
    return 0;
}

int LuaEngine::lua_makefolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base))
        return luaL_error(L, "Access denied: path traversal detected");
    std::error_code ec;
    std::filesystem::create_directories(full, ec);
    return 0;
}

// ===========================================================================
//  Clipboard
// ===========================================================================

int LuaEngine::lua_getclipboard(lua_State* L) {
    std::array<char, 4096> buf;
    std::string result;
    FILE* pipe = popen("xclip -selection clipboard -o 2>/dev/null || "
                       "xsel --clipboard --output 2>/dev/null || "
                       "wl-paste 2>/dev/null", "r");
    if (pipe) {
        while (fgets(buf.data(), buf.size(), pipe)) result += buf.data();
        pclose(pipe);
    }
    lua_pushstring(L, result.c_str());
    return 1;
}

int LuaEngine::lua_setclipboard(lua_State* L) {
    size_t len = 0;
    const char* text = luaL_checklstring(L, 1, &len);
    FILE* pipe = popen("xclip -selection clipboard 2>/dev/null || "
                       "xsel --clipboard --input 2>/dev/null || "
                       "wl-copy 2>/dev/null", "w");
    if (pipe) { fwrite(text, 1, len, pipe); pclose(pipe); }
    return 0;
}

// ===========================================================================
//  Executor identity
// ===========================================================================

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
    if (f.is_open()) std::getline(f, hwid);
    else hwid = "linux-unknown";
    lua_pushstring(L, Crypto::sha256(hwid).c_str());
    return 1;
}

// ===========================================================================
//  Console
// ===========================================================================

int LuaEngine::lua_rconsole_print(lua_State* L) { return lua_print(L); }

int LuaEngine::lua_rconsole_clear(lua_State* L) {
    auto* eng = get_engine(L);
    if (eng && eng->output_cb_) eng->output_cb_("\x1B[CLEAR]");
    return 0;
}

// ===========================================================================
//  Crypto helpers
// ===========================================================================

int LuaEngine::lua_base64_encode(lua_State* L) {
    size_t len;
    const char* data = luaL_checklstring(L, 1, &len);
    std::vector<uint8_t> input(data, data + len);
    lua_pushstring(L, Crypto::base64_encode(input).c_str());
    return 1;
}

int LuaEngine::lua_base64_decode(lua_State* L) {
    const char* encoded = luaL_checkstring(L, 1);

    static const auto table = []() {
        std::array<unsigned char, 256> t{};
        t.fill(0);
        const char* chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (size_t i = 0; i < 64; ++i)
            t[static_cast<unsigned char>(chars[i])] = static_cast<unsigned char>(i);
        return t;
    }();

    std::string input(encoded), output;
    size_t i = 0;
    while (i < input.size()) {
        uint32_t n = 0; int pad = 0;
        for (int j = 0; j < 4 && i < input.size(); j++, i++) {
            if (input[i] == '=') { pad++; n <<= 6; }
            else { n = (n << 6) | table[static_cast<unsigned char>(input[i])]; }
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
    lua_pushstring(L, Crypto::sha256(input).c_str());
    return 1;
}

} // namespace oss
