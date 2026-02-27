#include "lua_engine.hpp"
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

static thread_local LuaEngine* current_engine = nullptr;

static LuaEngine* get_engine(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "__oss_engine");
    auto* eng = static_cast<LuaEngine*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return eng ? eng : current_engine;
}

LuaEngine::LuaEngine() = default;

LuaEngine::~LuaEngine() {
    shutdown_internal();
}

bool LuaEngine::init() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (L_) shutdown_internal();

    L_ = luaL_newstate();
    if (!L_) {
        LOG_ERROR("Failed to create Lua state");
        return false;
    }

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

    drawings_.clear();
    signals_.clear();

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
    return execute_internal(script, chunk_name);
}

bool LuaEngine::execute_internal(const std::string& script,
                                  const std::string& chunk_name) {
    if (!L_) {
        if (error_cb_)
            error_cb_({"Engine not initialized", -1, chunk_name});
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

        auto colon1 = err.find(':');
        if (colon1 != std::string::npos) {
            auto colon2 = err.find(':', colon1 + 1);
            if (colon2 != std::string::npos) {
                try {
                    error.line = std::stoi(
                        err.substr(colon1 + 1, colon2 - colon1 - 1));
                } catch (...) {}
            }
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
        if (error_cb_)
            error_cb_({"Cannot open file: " + path, -1, path});
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    return execute(content, "@" + path);
}

void LuaEngine::tick() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!L_ || !running_) return;
    current_engine = this;
    process_tasks();
    current_engine = nullptr;
}

void LuaEngine::process_tasks() {
    auto now = std::chrono::steady_clock::now();

    std::vector<ScheduledTask> ready;
    std::vector<ScheduledTask> remaining;

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

        if (now >= task.resume_at) {
            ready.push_back(std::move(task));
        } else {
            remaining.push_back(std::move(task));
        }
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
    for (auto& t : tasks_) {
        if (t.id == task_id) {
            t.cancelled = true;
            return;
        }
    }
}

size_t LuaEngine::pending_task_count() const {
    size_t count = 0;
    for (auto& t : tasks_)
        if (!t.cancelled) ++count;
    return count;
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

DrawingObject* LuaEngine::get_drawing(int id) {
    auto it = drawings_.find(id);
    if (it != drawings_.end()) return &it->second;
    return nullptr;
}

void LuaEngine::remove_drawing(int id) {
    drawings_.erase(id);
    if (draw_remove_cb_) draw_remove_cb_(id);
}

void LuaEngine::clear_drawings() {
    auto ids = std::vector<int>();
    for (auto& [id, _] : drawings_) ids.push_back(id);
    drawings_.clear();
    if (draw_remove_cb_)
        for (int id : ids) draw_remove_cb_(id);
}

int LuaEngine::fire_signal(const std::string& name, int nargs) {
    auto it = signals_.find(name);
    if (it == signals_.end()) return 0;

    int fired = 0;
    for (auto& conn : it->second.connections) {
        if (!conn.connected || conn.callback_ref == LUA_NOREF) continue;

        lua_rawgeti(L_, LUA_REGISTRYINDEX, conn.callback_ref);

        for (int i = 0; i < nargs; ++i)
            lua_pushvalue(L_, -(nargs + 1));

        if (lua_pcall(L_, nargs, 0, 0) != 0) {
            const char* err = lua_tostring(L_, -1);
            LOG_ERROR("[Signal:{}] {}", name, err ? err : "unknown");
            lua_pop(L_, 1);
        }
        ++fired;
    }

    if (nargs > 0) lua_pop(L_, nargs);
    return fired;
}

Signal* LuaEngine::get_signal(const std::string& name) {
    auto it = signals_.find(name);
    if (it != signals_.end()) return &it->second;
    return nullptr;
}

Signal& LuaEngine::get_or_create_signal(const std::string& name) {
    auto& sig = signals_[name];
    sig.name = name;
    return sig;
}

bool LuaEngine::is_sandboxed(const std::string& full_path,
                              const std::string& base_dir) {
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(full_path, ec);
    if (ec) return false;
    auto base_canonical = std::filesystem::weakly_canonical(base_dir, ec);
    if (ec) return false;

    std::string base_str = base_canonical.string();
    if (!base_str.empty() && base_str.back() != '/')
        base_str += '/';

    return canonical.string().find(base_str) == 0;
}

void LuaEngine::setup_environment() {
    lua_pushcfunction(L_, lua_print);
    lua_setglobal(L_, "print");

    lua_pushcfunction(L_, lua_warn_handler);
    lua_setglobal(L_, "warn");
}

void LuaEngine::register_task_lib() {
    static const luaL_Reg task_funcs[] = {
        {"spawn", lua_task_spawn},
        {"delay", lua_task_delay},
        {"defer", lua_task_defer},
        {"wait", lua_task_wait},
        {"cancel", lua_task_cancel},
        {"desynchronize", lua_task_desynchronize},
        {"synchronize", lua_task_synchronize},
        {nullptr, nullptr}
    };
    register_library("task", task_funcs);
}

void LuaEngine::register_drawing_lib() {
    luaL_newmetatable(L_, "DrawingObject");

    lua_pushcfunction(L_, lua_drawing_index);
    lua_setfield(L_, -2, "__index");

    lua_pushcfunction(L_, lua_drawing_newindex);
    lua_setfield(L_, -2, "__newindex");

    lua_pushcfunction(L_, lua_drawing_gc);
    lua_setfield(L_, -2, "__gc");

    lua_pop(L_, 1);

    static const luaL_Reg drawing_funcs[] = {
        {"new", lua_drawing_new},
        {"clear", lua_drawing_clear},
        {nullptr, nullptr}
    };
    register_library("Drawing", drawing_funcs);
}

void LuaEngine::register_signal_lib() {
    luaL_newmetatable(L_, "SignalObject");

    lua_pushstring(L_, "__index");
    lua_newtable(L_);

    lua_pushcfunction(L_, lua_signal_connect);
    lua_setfield(L_, -2, "Connect");

    lua_pushcfunction(L_, lua_signal_fire);
    lua_setfield(L_, -2, "Fire");

    lua_pushcfunction(L_, lua_signal_wait);
    lua_setfield(L_, -2, "Wait");

    lua_pushcfunction(L_, lua_signal_destroy);
    lua_setfield(L_, -2, "Destroy");

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
    register_function("readfile", lua_readfile);
    register_function("writefile", lua_writefile);
    register_function("appendfile", lua_appendfile);
    register_function("isfile", lua_isfile);
    register_function("listfiles", lua_listfiles);
    register_function("delfolder", lua_delfolder);
    register_function("makefolder", lua_makefolder);

    static const luaL_Reg http_lib[] = {
        {"get", lua_http_get},
        {"post", lua_http_post},
        {nullptr, nullptr}
    };
    register_library("http", http_lib);

    lua_getglobal(L_, "http");
    lua_getfield(L_, -1, "get");
    lua_setglobal(L_, "http_get");
    lua_pop(L_, 1);

    register_function("wait", lua_wait);
    register_function("spawn", lua_spawn);
    register_function("getclipboard", lua_getclipboard);
    register_function("setclipboard", lua_setclipboard);
    register_function("identifyexecutor", lua_identifyexecutor);
    register_function("getexecutorname", lua_getexecutorname);
    register_function("gethwid", lua_get_hwid);

    static const luaL_Reg console_lib[] = {
        {"print", lua_rconsole_print},
        {"clear", lua_rconsole_clear},
        {nullptr, nullptr}
    };
    register_library("rconsole", console_lib);

    static const luaL_Reg crypt_lib[] = {
        {"base64encode", lua_base64_encode},
        {"base64decode", lua_base64_decode},
        {"sha256", lua_sha256},
        {nullptr, nullptr}
    };
    register_library("crypt", crypt_lib);

    set_global_string("_EXECUTOR", "OSS Executor");
    set_global_string("_EXECUTOR_VERSION", "2.0.0");
    set_global_number("_EXECUTOR_LEVEL", 8);
    set_global_bool("_OSS", true);

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
            time = os.time,
            clock = os.clock,
            date = os.date,
            difftime = os.difftime
        }
        os = safe_os
        loadfile = nil
        dofile = nil
    )", "=sandbox");
}

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
    double seconds = luaL_optnumber(L, 1, 0.03);
    auto ms = std::chrono::milliseconds(static_cast<int>(seconds * 1000));
    std::this_thread::sleep_for(ms);
    lua_pushnumber(L, seconds);
    return 1;
}

int LuaEngine::lua_task_cancel(lua_State* L) {
    int task_id = static_cast<int>(luaL_checkinteger(L, 1));
    auto* eng = get_engine(L);
    if (eng) eng->cancel_task(task_id);
    return 0;
}

int LuaEngine::lua_task_desynchronize(lua_State*) { return 0; }
int LuaEngine::lua_task_synchronize(lua_State*) { return 0; }

int LuaEngine::lua_drawing_new(lua_State* L) {
    const char* type_str = luaL_checkstring(L, 1);

    auto* eng = get_engine(L);
    if (!eng) return luaL_error(L, "engine not available");

    DrawingObject obj;
    obj.id = eng->next_drawing_id_++;

    std::string type_name(type_str);
    if (type_name == "Line") obj.type = DrawingObject::Type::Line;
    else if (type_name == "Circle") obj.type = DrawingObject::Type::Circle;
    else if (type_name == "Square" || type_name == "Rectangle")
        obj.type = DrawingObject::Type::Square;
    else if (type_name == "Triangle") obj.type = DrawingObject::Type::Triangle;
    else if (type_name == "Text") obj.type = DrawingObject::Type::Text;
    else if (type_name == "Quad") obj.type = DrawingObject::Type::Quad;
    else if (type_name == "Image") obj.type = DrawingObject::Type::Image;
    else return luaL_error(L, "Unknown drawing type: %s", type_str);

    eng->drawings_[obj.id] = obj;

    int* ud = static_cast<int*>(lua_newuserdata(L, sizeof(int)));
    *ud = obj.id;
    luaL_getmetatable(L, "DrawingObject");
    lua_setmetatable(L, -2);

    return 1;
}

int LuaEngine::lua_drawing_index(lua_State* L) {
    int* ud = static_cast<int*>(luaL_checkudata(L, 1, "DrawingObject"));
    const char* key = luaL_checkstring(L, 2);

    auto* eng = get_engine(L);
    if (!eng) return 0;

    DrawingObject* obj = eng->get_drawing(*ud);
    if (!obj) return luaL_error(L, "Drawing object has been removed");

    std::string k(key);

    if (k == "Remove" || k == "Destroy") {
        lua_pushcfunction(L, lua_drawing_remove);
        return 1;
    }

    if (k == "Visible") { lua_pushboolean(L, obj->visible); return 1; }
    if (k == "Color") {
        lua_newtable(L);
        lua_pushnumber(L, obj->color_r);
        lua_setfield(L, -2, "R");
        lua_pushnumber(L, obj->color_g);
        lua_setfield(L, -2, "G");
        lua_pushnumber(L, obj->color_b);
        lua_setfield(L, -2, "B");
        return 1;
    }
    if (k == "Thickness") { lua_pushnumber(L, obj->thickness); return 1; }
    if (k == "Transparency") { lua_pushnumber(L, obj->transparency); return 1; }
    if (k == "Filled") { lua_pushboolean(L, obj->filled); return 1; }
    if (k == "Text") { lua_pushstring(L, obj->text.c_str()); return 1; }
    if (k == "Size") { lua_pushnumber(L, obj->text_size); return 1; }
    if (k == "Font") { lua_pushinteger(L, obj->font); return 1; }
    if (k == "ZIndex") { lua_pushinteger(L, obj->z_index); return 1; }
    if (k == "Radius") { lua_pushnumber(L, obj->radius); return 1; }
    if (k == "NumSides") { lua_pushinteger(L, obj->num_sides); return 1; }
    if (k == "Center") { lua_pushboolean(L, obj->center); return 1; }
    if (k == "Outline") { lua_pushboolean(L, obj->outline); return 1; }

    auto push_vec2 = [L](float x, float y) {
        lua_newtable(L);
        lua_pushnumber(L, x);
        lua_setfield(L, -2, "X");
        lua_pushnumber(L, y);
        lua_setfield(L, -2, "Y");
    };

    if (k == "From") { push_vec2(obj->from_x, obj->from_y); return 1; }
    if (k == "To") { push_vec2(obj->to_x, obj->to_y); return 1; }
    if (k == "Position") { push_vec2(obj->pos_x, obj->pos_y); return 1; }
    if (k == "PointA") { push_vec2(obj->pa_x, obj->pa_y); return 1; }
    if (k == "PointB") { push_vec2(obj->pb_x, obj->pb_y); return 1; }
    if (k == "PointC") { push_vec2(obj->pc_x, obj->pc_y); return 1; }
    if (k == "PointD") { push_vec2(obj->pd_x, obj->pd_y); return 1; }

    lua_pushnil(L);
    return 1;
}

int LuaEngine::lua_drawing_newindex(lua_State* L) {
    int* ud = static_cast<int*>(luaL_checkudata(L, 1, "DrawingObject"));
    const char* key = luaL_checkstring(L, 2);

    auto* eng = get_engine(L);
    if (!eng) return 0;

    DrawingObject* obj = eng->get_drawing(*ud);
    if (!obj) return luaL_error(L, "Drawing object has been removed");

    std::string k(key);

    auto read_vec2 = [L](int idx, float& x, float& y) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "X");
            if (lua_isnumber(L, -1)) x = static_cast<float>(lua_tonumber(L, -1));
            lua_pop(L, 1);
            lua_getfield(L, idx, "Y");
            if (lua_isnumber(L, -1)) y = static_cast<float>(lua_tonumber(L, -1));
            lua_pop(L, 1);
        }
    };

    if (k == "Visible") obj->visible = lua_toboolean(L, 3);
    else if (k == "Color") {
        if (lua_istable(L, 3)) {
            lua_getfield(L, 3, "R");
            obj->color_r = static_cast<float>(lua_tonumber(L, -1));
            lua_pop(L, 1);
            lua_getfield(L, 3, "G");
            obj->color_g = static_cast<float>(lua_tonumber(L, -1));
            lua_pop(L, 1);
            lua_getfield(L, 3, "B");
            obj->color_b = static_cast<float>(lua_tonumber(L, -1));
            lua_pop(L, 1);
        }
    }
    else if (k == "Thickness") obj->thickness = static_cast<float>(luaL_checknumber(L, 3));
    else if (k == "Transparency") obj->transparency = static_cast<float>(luaL_checknumber(L, 3));
    else if (k == "Filled") obj->filled = lua_toboolean(L, 3);
    else if (k == "Text") obj->text = luaL_checkstring(L, 3);
    else if (k == "Size") obj->text_size = static_cast<float>(luaL_checknumber(L, 3));
    else if (k == "Font") obj->font = static_cast<int>(luaL_checkinteger(L, 3));
    else if (k == "ZIndex") obj->z_index = static_cast<int>(luaL_checkinteger(L, 3));
    else if (k == "Radius") obj->radius = static_cast<float>(luaL_checknumber(L, 3));
    else if (k == "NumSides") obj->num_sides = static_cast<int>(luaL_checkinteger(L, 3));
    else if (k == "Center") obj->center = lua_toboolean(L, 3);
    else if (k == "Outline") obj->outline = lua_toboolean(L, 3);
    else if (k == "From") read_vec2(3, obj->from_x, obj->from_y);
    else if (k == "To") read_vec2(3, obj->to_x, obj->to_y);
    else if (k == "Position") read_vec2(3, obj->pos_x, obj->pos_y);
    else if (k == "PointA") read_vec2(3, obj->pa_x, obj->pa_y);
    else if (k == "PointB") read_vec2(3, obj->pb_x, obj->pb_y);
    else if (k == "PointC") read_vec2(3, obj->pc_x, obj->pc_y);
    else if (k == "PointD") read_vec2(3, obj->pd_x, obj->pd_y);

    if (eng->draw_cb_) eng->draw_cb_(*obj);

    return 0;
}

int LuaEngine::lua_drawing_remove(lua_State* L) {
    int* ud = static_cast<int*>(luaL_checkudata(L, 1, "DrawingObject"));
    auto* eng = get_engine(L);
    if (eng) eng->remove_drawing(*ud);
    return 0;
}

int LuaEngine::lua_drawing_gc(lua_State* L) {
    return 0;
}

int LuaEngine::lua_drawing_clear(lua_State* L) {
    auto* eng = get_engine(L);
    if (eng) eng->clear_drawings();
    return 0;
}

struct SignalUserdata {
    char name[128];
};

int LuaEngine::lua_signal_new(lua_State* L) {
    const char* name = luaL_optstring(L, 1, "");

    auto* eng = get_engine(L);
    if (!eng) return luaL_error(L, "engine not available");

    std::string sig_name = name;
    if (sig_name.empty())
        sig_name = "signal_" + std::to_string(reinterpret_cast<uintptr_t>(L)) +
                   "_" + std::to_string(lua_gc(L, LUA_GCCOUNT, 0));

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

    struct ConnUserdata { char sig_name[128]; int conn_id; };
    auto* cud = static_cast<ConnUserdata*>(lua_newuserdata(L, sizeof(ConnUserdata)));
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
        for (int i = 0; i < nargs; ++i)
            lua_pushvalue(L, i + 2);

        if (lua_pcall(L, nargs, 0, 0) != 0) {
            LOG_ERROR("[Signal:{}] {}", ud->name, lua_tostring(L, -1));
            lua_pop(L, 1);
        }
    }

    return 0;
}

int LuaEngine::lua_signal_wait(lua_State* L) {
    return lua_yield(L, 0);
}

int LuaEngine::lua_signal_disconnect(lua_State* L) {
    struct ConnUserdata { char sig_name[128]; int conn_id; };
    auto* cud = static_cast<ConnUserdata*>(luaL_checkudata(L, 1, "SignalConnection"));

    auto* eng = get_engine(L);
    if (!eng) return 0;

    Signal* sig = eng->get_signal(cud->sig_name);
    if (!sig) return 0;

    for (auto& conn : sig->connections) {
        if (conn.id == cud->conn_id) {
            conn.connected = false;
            if (conn.callback_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, conn.callback_ref);
                conn.callback_ref = LUA_NOREF;
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
        for (auto& conn : sig->connections) {
            if (conn.callback_ref != LUA_NOREF)
                luaL_unref(L, LUA_REGISTRYINDEX, conn.callback_ref);
        }
        eng->signals_.erase(ud->name);
    }

    return 0;
}

int LuaEngine::lua_signal_gc(lua_State*) { return 0; }

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

    auto* eng = get_engine(L);
    if (eng && eng->output_cb_)
        eng->output_cb_(output);

    LOG_INFO("[Lua] {}", output);
    return 0;
}

int LuaEngine::lua_warn_handler(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);
    auto* eng = get_engine(L);
    if (eng && eng->output_cb_)
        eng->output_cb_(std::string("[WARN] ") + msg);
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
            if (lua_isstring(L, -2) && lua_isstring(L, -1))
                headers[lua_tostring(L, -2)] = lua_tostring(L, -1);
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
    lua_pushnumber(L, seconds);
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

int LuaEngine::lua_readfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;

    if (!is_sandboxed(full_path, base))
        return luaL_error(L, "Access denied: path traversal detected");

    std::ifstream file(full_path);
    if (!file.is_open())
        return luaL_error(L, "Cannot open file: %s", path);

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

    if (!is_sandboxed(full_path, base))
        return luaL_error(L, "Access denied: path traversal detected");

    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(full_path).parent_path(), ec);

    std::ofstream file(full_path);
    if (!file.is_open())
        return luaL_error(L, "Cannot write file: %s", path);

    file << content;
    return 0;
}

int LuaEngine::lua_appendfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* content = luaL_checkstring(L, 2);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;

    if (!is_sandboxed(full_path, base))
        return luaL_error(L, "Access denied: path traversal detected");

    std::ofstream file(full_path, std::ios::app);
    if (!file.is_open())
        return luaL_error(L, "Cannot append to file: %s", path);

    file << content;
    return 0;
}

int LuaEngine::lua_isfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;

    if (!is_sandboxed(full_path, base)) {
        lua_pushboolean(L, false);
        return 1;
    }

    lua_pushboolean(L, std::filesystem::exists(full_path));
    return 1;
}

int LuaEngine::lua_listfiles(lua_State* L) {
    const char* path = luaL_optstring(L, 1, "");
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;

    if (!is_sandboxed(full_path, base)) {
        lua_newtable(L);
        return 1;
    }

    lua_newtable(L);
    int index = 1;

    if (std::filesystem::exists(full_path) &&
        std::filesystem::is_directory(full_path)) {
        try {
            for (const auto& entry :
                 std::filesystem::directory_iterator(full_path)) {
                lua_pushstring(L, entry.path().filename().string().c_str());
                lua_rawseti(L, -2, index++);
            }
        } catch (const std::filesystem::filesystem_error&) {}
    }

    return 1;
}

int LuaEngine::lua_delfolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;

    if (!is_sandboxed(full_path, base))
        return luaL_error(L, "Access denied: path traversal detected");

    std::error_code ec;
    std::filesystem::remove_all(full_path, ec);
    return 0;
}

int LuaEngine::lua_makefolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full_path = base + path;

    if (!is_sandboxed(full_path, base))
        return luaL_error(L, "Access denied: path traversal detected");

    std::error_code ec;
    std::filesystem::create_directories(full_path, ec);
    return 0;
}

int LuaEngine::lua_getclipboard(lua_State* L) {
    std::array<char, 4096> buffer;
    std::string result;

    FILE* pipe = popen("xclip -selection clipboard -o 2>/dev/null || "
                       "xsel --clipboard --output 2>/dev/null || "
                       "wl-paste 2>/dev/null", "r");
    if (pipe) {
        while (fgets(buffer.data(), buffer.size(), pipe))
            result += buffer.data();
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
    if (pipe) {
        fwrite(text, 1, len, pipe);
        pclose(pipe);
    }

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
    if (f.is_open())
        std::getline(f, hwid);
    else
        hwid = "linux-unknown";

    lua_pushstring(L, Crypto::sha256(hwid).c_str());
    return 1;
}

int LuaEngine::lua_rconsole_print(lua_State* L) {
    return lua_print(L);
}

int LuaEngine::lua_rconsole_clear(lua_State* L) {
    auto* eng = get_engine(L);
    if (eng && eng->output_cb_)
        eng->output_cb_("\x1B[CLEAR]");
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

    static const auto table = []() {
        std::array<unsigned char, 256> t{};
        t.fill(0);
        const char* chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        for (size_t i = 0; i < 64; ++i)
            t[static_cast<unsigned char>(chars[i])] =
                static_cast<unsigned char>(i);
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
    std::string hash = Crypto::sha256(input);
    lua_pushstring(L, hash.c_str());
    return 1;
}

} // namespace oss
