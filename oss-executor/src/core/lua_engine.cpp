#include "lua_engine.hpp"
#include "ui/overlay.hpp"
#include "utils/http.hpp"
#include "utils/crypto.hpp"
#include "utils/config.hpp"
#include "api/environment.hpp"
#include "../utils/logger.hpp"

#include "lua.h"
#include "lualib.h"
#include "luacode.h"
#include "Luau/Compiler.h"

#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <array>
#include <algorithm>
#include <cstdlib>

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

struct DrawingHandle {
    int  id;
    bool removed;
};

static DrawingObject::Type parse_drawing_type(const char* s) {
    if (!s) return DrawingObject::Type::Line;
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

static bool read_vec2(lua_State* L, int idx, double& x, double& y) {
    if (!lua_istable(L, idx)) return false;
    int abs_idx = (idx > 0) ? idx : lua_gettop(L) + idx + 1;

    lua_getfield(L, abs_idx, "X");
    if (lua_isnumber(L, -1)) {
        x = lua_tonumber(L, -1); lua_pop(L, 1);
        lua_getfield(L, abs_idx, "Y");
        if (lua_isnumber(L, -1)) y = lua_tonumber(L, -1);
        lua_pop(L, 1);
        return true;
    }
    lua_pop(L, 1);

    lua_rawgeti(L, abs_idx, 1);
    if (lua_isnumber(L, -1)) x = lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_rawgeti(L, abs_idx, 2);
    if (lua_isnumber(L, -1)) y = lua_tonumber(L, -1);
    lua_pop(L, 1);
    return true;
}

static bool read_color(lua_State* L, int idx, double& r, double& g, double& b) {
    if (!lua_istable(L, idx)) return false;
    int abs_idx = (idx > 0) ? idx : lua_gettop(L) + idx + 1;

    lua_getfield(L, abs_idx, "R");
    if (lua_isnumber(L, -1)) {
        r = lua_tonumber(L, -1); lua_pop(L, 1);
        lua_getfield(L, abs_idx, "G");
        if (lua_isnumber(L, -1)) g = lua_tonumber(L, -1);
        lua_pop(L, 1);
        lua_getfield(L, abs_idx, "B");
        if (lua_isnumber(L, -1)) b = lua_tonumber(L, -1);
        lua_pop(L, 1);
        return true;
    }
    lua_pop(L, 1);

    lua_rawgeti(L, abs_idx, 1);
    if (lua_isnumber(L, -1)) r = lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_rawgeti(L, abs_idx, 2);
    if (lua_isnumber(L, -1)) g = lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_rawgeti(L, abs_idx, 3);
    if (lua_isnumber(L, -1)) b = lua_tonumber(L, -1);
    lua_pop(L, 1);
    return true;
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
// DrawingHandle validation helper
// ---------------------------------------------------------------------------

static DrawingHandle* check_drawing_handle(lua_State* L, int idx) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, idx, DRAWING_OBJ_MT));
    if (h->removed) {
        luaL_error(L, "Drawing object has been removed");
        return nullptr;
    }
    return h;
}

// ---------------------------------------------------------------------------
// Signal helper structs
// ---------------------------------------------------------------------------

struct SignalUserdata {
    char name[128];
    bool destroyed;
};

static SignalUserdata* check_signal_ud(lua_State* L, int idx) {
    auto* ud = static_cast<SignalUserdata*>(luaL_checkudata(L, idx, "SignalObject"));
    if (ud->destroyed)
        luaL_error(L, "Signal has been destroyed");
    return ud;
}

struct ConnUD {
    char sig_name[128];
    int  conn_id;
    bool disconnected;
};

// ---------------------------------------------------------------------------
// loadstring implementation (Luau does not provide one natively)
// ---------------------------------------------------------------------------

static int lua_loadstring_impl(lua_State* L) {
    size_t len;
    const char* source = luaL_checklstring(L, 1, &len);
    const char* chunkname = luaL_optstring(L, 2, "=loadstring");

    Luau::CompileOptions options{};
    options.optimizationLevel = 1;
    options.debugLevel        = 1;
    options.coverageLevel     = 0;

    std::string bytecode = Luau::compile(source, options);

    if (bytecode.empty() || bytecode[0] == 0) {
        lua_pushnil(L);
        if (bytecode.size() > 1)
            lua_pushstring(L, bytecode.c_str() + 1);
        else
            lua_pushstring(L, "compilation failed");
        return 2;
    }

    int status = luau_load(L, chunkname, bytecode.data(), bytecode.size(), 0);

    if (status != 0) {
        // luau_load pushed an error string
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }

    return 1; // compiled function on top of stack
}

// ===========================================================================
// Singleton
// ===========================================================================
LuaEngine& LuaEngine::instance() {
    static LuaEngine inst;
    return inst;
}

// ===========================================================================
// Luau custom allocator with memory cap
// ===========================================================================

void* LuaEngine::lua_alloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    auto* engine = static_cast<LuaEngine*>(ud);

    if (nsize == 0) {
        if (engine->total_allocated_ >= osize)
            engine->total_allocated_ -= osize;
        else
            engine->total_allocated_ = 0;
        free(ptr);
        return nullptr;
    }

    // Safe memory-limit check with underflow protection
    size_t projected = engine->total_allocated_;
    if (projected >= osize)
        projected = projected - osize + nsize;
    else
        projected = nsize;

    if (projected > MAX_MEMORY) {
        LOG_ERROR("LuaEngine: Memory limit exceeded ({} MB)",
                  MAX_MEMORY / (1024 * 1024));
        return nullptr;
    }

    void* result = realloc(ptr, nsize);
    if (result)
        engine->total_allocated_ = projected;
    return result;
}

// ===========================================================================
// Luau interrupt callback (instruction quota hook)
// ===========================================================================

void LuaEngine::lua_interrupt(lua_State* L, int gc) {
    if (gc >= 0) return;           // lua_getfield is unsafe during GC
    auto* eng = get_engine(L);
    if (eng && !eng->is_running())
        luaL_error(L, "Script execution cancelled");
}

// ===========================================================================
// Lifecycle
// ===========================================================================

LuaEngine::LuaEngine() = default;

LuaEngine::~LuaEngine() { shutdown_internal(); }

bool LuaEngine::init() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (L_) shutdown_internal();

    LOG_INFO("LuaEngine: Initializing embedded Luau VM");

       // Reset tracking BEFORE creating VM so allocator starts at zero
    next_task_id_    = 1;
    tasks_.clear();
    signals_.clear();
    {
        std::lock_guard<std::mutex> dlock(drawing_mutex_);
        drawing_objects_.clear();
    }
    next_drawing_id_ = 1;
    next_signal_id_  = 1;
    total_allocated_ = 0;

    LOG_DEBUG("LuaEngine: Creating Luau state...");
    L_ = lua_newstate(lua_alloc, this);
    if (!L_) {
        last_error_ = "Failed to create Lua state";
        LOG_ERROR("LuaEngine: {}", last_error_);
        return false;
    }

    LOG_DEBUG("LuaEngine: Opening standard libraries...");
    luaL_openlibs(L_);

    LOG_DEBUG("LuaEngine: Setting up callbacks and registry...");
    // Install interrupt for cancellation support
    lua_callbacks(L_)->interrupt = lua_interrupt;

    // Store engine pointer in registry for retrieval from C functions
    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, "__oss_engine");

    LOG_DEBUG("LuaEngine: Setting up environment...");
    setup_environment();
    LOG_DEBUG("LuaEngine: Registering custom libraries...");
    register_custom_libs();
    LOG_DEBUG("LuaEngine: Registering task library...");
    register_task_lib();
    LOG_DEBUG("LuaEngine: Registering drawing library...");
    register_drawing_lib();
    LOG_DEBUG("LuaEngine: Registering signal library...");
    register_signal_lib();
    LOG_DEBUG("LuaEngine: Setting up environment API...");
    Environment::instance().setup(L_);
    LOG_DEBUG("LuaEngine: Applying sandbox...");
    sandbox();

    ready_.store(true, std::memory_order_release);
    running_ = true;
    LOG_INFO("LuaEngine: VM initialized successfully");
    return true;
}

void LuaEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    shutdown_internal();
}

void LuaEngine::shutdown_internal() {
    ready_.store(false, std::memory_order_release);
    running_ = false;

    // Clean up tasks — release all Lua refs before closing state
    for (auto& task : tasks_) {
        if (L_) {
            if (task.thread_ref != LUA_NOREF)
                lua_unref(L_, task.thread_ref);
            if (task.func_ref != LUA_NOREF)
                lua_unref(L_, task.func_ref);
            for (int r : task.arg_refs)
                if (r != LUA_NOREF) lua_unref(L_, r);
        }
    }
    tasks_.clear();

    // Clean up signals
    if (L_) {
        for (auto& [name, sig] : signals_) {
            for (auto& conn : sig.connections) {
                if (conn.callback_ref != LUA_NOREF) {
                    lua_unref(L_, conn.callback_ref);
                    conn.callback_ref = LUA_NOREF;
                }
            }
        }
    }
    signals_.clear();

        // Clean up drawing objects
    {
        std::lock_guard<std::mutex> dlock(drawing_mutex_);
        for (auto& [id, obj] : drawing_objects_) {
            if (obj.image_surface) {
                cairo_surface_destroy(obj.image_surface);
                obj.image_surface = nullptr;
            }
        }
        drawing_objects_.clear();
    }
    try {
        Overlay::instance().clear_objects();
    } catch (...) {}

    // Drain script queue
    {
        std::lock_guard<std::mutex> ql(queue_mutex_);
        while (!script_queue_.empty()) script_queue_.pop();
    }

    if (L_) { lua_close(L_); L_ = nullptr; }

    LOG_INFO("LuaEngine: Shutdown complete");
}

void LuaEngine::reset() { shutdown(); init(); }

// ===========================================================================
// Luau bytecode compiler
// ===========================================================================

std::string LuaEngine::compile(const std::string& source) {
    Luau::CompileOptions options{};
    options.optimizationLevel = 1;
    options.debugLevel        = 1;
    options.coverageLevel     = 0;

    std::string bytecode = Luau::compile(std::string(source, len), options);

    if (bytecode.empty()) {
        last_error_ = "Compilation produced empty bytecode";
        return "";
    }

    // Luau convention: bytecode[0] == 0 means compile error, message follows
    if (bytecode[0] == 0) {
        last_error_ = "Compile error: " + bytecode.substr(1);
        LOG_ERROR("LuaEngine: {}", last_error_);
        return "";
    }

    return bytecode;
}

// ===========================================================================
// Execution
// ===========================================================================

bool LuaEngine::execute(const std::string& source,
                         const std::string& chunk_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return execute_internal(source, chunk_name);
}

bool LuaEngine::execute_internal(const std::string& source,
                                  const std::string& chunk_name) {
    if (!L_) {
        last_error_ = "VM not initialized";
        if (error_cb_) error_cb_({last_error_, -1, chunk_name});
        if (exec_cb_)  exec_cb_(false, last_error_);
        return false;
    }

    running_.store(true, std::memory_order_release);
    current_engine = this;

    // Compile source to Luau bytecode
    std::string bytecode = compile(source);
    if (bytecode.empty()) {
        if (error_cb_) error_cb_({last_error_, -1, chunk_name});
        if (exec_cb_)  exec_cb_(false, last_error_);
        current_engine = nullptr;
        return false;
    }

    bool result = execute_bytecode_internal(bytecode, chunk_name);
    current_engine = nullptr;
    return result;
}

bool LuaEngine::execute_bytecode(const std::string& bytecode,
                                  const std::string& chunk_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return execute_bytecode_internal(bytecode, chunk_name);
}

bool LuaEngine::execute_bytecode_internal(const std::string& bytecode,
                                           const std::string& chunk_name) {
    if (!L_) {
        last_error_ = "VM not initialized";
        if (exec_cb_) exec_cb_(false, last_error_);
        return false;
    }

    LOG_DEBUG("LuaEngine: Executing '{}' ({} bytes bytecode)",
              chunk_name, bytecode.size());

    lua_State* thread = lua_newthread(L_);
    luaL_sandboxthread(thread);

    int load_result = luau_load(thread, chunk_name.c_str(),
                                 bytecode.data(), bytecode.size(), 0);

    if (load_result != 0) {
        last_error_ = lua_tostring(thread, -1);
        LOG_ERROR("LuaEngine: Load error: {}", last_error_);
        lua_pop(L_, 1); // pop thread
        if (error_cb_) error_cb_({last_error_, -1, chunk_name});
        if (exec_cb_)  exec_cb_(false, last_error_);
        return false;
    }

    auto start_time = std::chrono::steady_clock::now();

    int exec_result = lua_resume(thread, nullptr, 0);

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    double ms = std::chrono::duration<double, std::milli>(elapsed).count();

    if (exec_result == 0) {
        LOG_INFO("LuaEngine: '{}' completed in {:.1f}ms", chunk_name, ms);
        lua_pop(L_, 1); // pop thread
        if (exec_cb_) exec_cb_(true, "");
        return true;
    } else if (exec_result == LUA_YIELD) {
        LOG_DEBUG("LuaEngine: '{}' yielded after {:.1f}ms", chunk_name, ms);

        // If the coroutine yielded a wait duration, schedule it
        if (lua_gettop(thread) > 0 && lua_isnumber(thread, -1)) {
            double wait_seconds = lua_tonumber(thread, -1);
            lua_pop(thread, 1);

                       // Reference the thread so it stays alive
            lua_pushthread(thread);
            lua_xmove(thread, L_, 1);
            int thread_ref = lua_ref(L_, -1);

            // Pop ref'd copy and original lua_newthread value from main stack
            lua_pop(L_, 2);

            ScheduledTask task;
            task.type = ScheduledTask::Type::Delay;
            task.delay_seconds = wait_seconds;
            task.resume_at = std::chrono::steady_clock::now() +
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(wait_seconds));
            task.thread_ref = thread_ref;
            task.func_ref   = LUA_NOREF;
            schedule_task(std::move(task));
        } else {
                       // Keep thread alive for next-tick resume
            lua_pushthread(thread);
            lua_xmove(thread, L_, 1);
            int thread_ref = lua_ref(L_, -1);

            // Pop ref'd copy and original lua_newthread value from main stack
            lua_pop(L_, 2);

            ScheduledTask task;
            task.type = ScheduledTask::Type::Defer;
            task.resume_at = std::chrono::steady_clock::now();
            task.thread_ref = thread_ref;
            task.func_ref   = LUA_NOREF;
            schedule_task(std::move(task));
        }

        if (exec_cb_) exec_cb_(true, "");
        return true;
    } else {
        const char* err = lua_tostring(thread, -1);
        last_error_ = err ? err : "Unknown runtime error";
        LOG_ERROR("LuaEngine: Runtime error in '{}': {}", chunk_name, last_error_);
        lua_pop(L_, 1); // pop thread
        if (error_cb_) error_cb_({last_error_, -1, chunk_name});
        if (exec_cb_)  exec_cb_(false, last_error_);
        return false;
    }
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

// ===========================================================================
// Script queue
// ===========================================================================

void LuaEngine::queue_script(const std::string& source,
                              const std::string& name) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    script_queue_.push({source, name.empty() ? "=queued_script" : name});
}

void LuaEngine::process_queue() {
    std::queue<QueuedScript> to_run;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        std::swap(to_run, script_queue_);
    }

    while (!to_run.empty()) {
        auto& script = to_run.front();
        execute(script.source, script.name);
        to_run.pop();
    }
}

// ===========================================================================
// Tick / task scheduler — coroutine-based
// ===========================================================================

void LuaEngine::tick() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!L_ || !running_) return;
    current_engine = this;
    process_tasks();
    current_engine = nullptr;
}

void LuaEngine::process_tasks() {
    auto now = std::chrono::steady_clock::now();

    // Remove cancelled tasks
    auto cancelled_end = std::stable_partition(
        tasks_.begin(), tasks_.end(),
        [](const ScheduledTask& t) { return !t.cancelled; });

    for (auto it = cancelled_end; it != tasks_.end(); ++it)
        release_task_refs(*it);
    tasks_.erase(cancelled_end, tasks_.end());

    // Partition ready vs remaining
    std::vector<ScheduledTask> ready;
    std::vector<ScheduledTask> remaining;
    remaining.reserve(tasks_.size());

    for (auto& task : tasks_) {
        if (now >= task.resume_at)
            ready.push_back(std::move(task));
        else
            remaining.push_back(std::move(task));
    }
    tasks_ = std::move(remaining);

    for (auto& task : ready)
        execute_task(task, now);
}

void LuaEngine::release_task_refs(ScheduledTask& task) {
    if (!L_) return;
    if (task.thread_ref != LUA_NOREF) {
        lua_unref(L_, task.thread_ref);
        task.thread_ref = LUA_NOREF;
    }
    if (task.func_ref != LUA_NOREF) {
        lua_unref(L_, task.func_ref);
        task.func_ref = LUA_NOREF;
    }
    for (int& r : task.arg_refs) {
        if (r != LUA_NOREF) {
            lua_unref(L_, r);
            r = LUA_NOREF;
        }
    }
    task.arg_refs.clear();
}

void LuaEngine::execute_task(ScheduledTask& task,
                              std::chrono::steady_clock::time_point now) {
    if (!L_) return;

    lua_State* co = nullptr;
    [[maybe_unused]] bool new_thread = false;

    // Resume existing coroutine or create new one from func_ref
    if (task.thread_ref != LUA_NOREF) {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, task.thread_ref);
        if (lua_isthread(L_, -1))
            co = lua_tothread(L_, -1);
        lua_pop(L_, 1);
    }

    if (!co && task.func_ref != LUA_NOREF) {
        co = lua_newthread(L_);
        luaL_sandboxthread(co);
        int thread_ref = lua_ref(L_, -1);
        lua_pop(L_, 1);

        if (task.thread_ref != LUA_NOREF)
            lua_unref(L_, task.thread_ref);
        task.thread_ref = thread_ref;

        // Push the function onto the coroutine
        lua_rawgeti(L_, LUA_REGISTRYINDEX, task.func_ref);
        lua_xmove(L_, co, 1);
        new_thread = true;
    }

    if (!co) {
        release_task_refs(task);
        return;
    }

    // Don't resume dead coroutines
    int co_status = lua_status(co);
    if (co_status != 0 && co_status != LUA_YIELD) {
        release_task_refs(task);
        return;
    }

    // Transfer argument refs to coroutine stack
    int nargs = 0;
    for (int& ref : task.arg_refs) {
        if (ref != LUA_NOREF) {
            lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
            lua_xmove(L_, co, 1);
            lua_unref(L_, ref);
            ref = LUA_NOREF;
            ++nargs;
        }
    }
    task.arg_refs.clear();

    // For delay tasks, push elapsed time
    if (task.type == ScheduledTask::Type::Delay) {
        auto scheduled_at = task.resume_at -
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                std::chrono::duration<double>(task.delay_seconds));
        double elapsed = std::chrono::duration<double>(now - scheduled_at).count();
        lua_pushnumber(co, elapsed);
        ++nargs;
    }

    int status = lua_resume(co, nullptr, nargs);

    if (status == LUA_YIELD) {
        if (lua_gettop(co) > 0 && lua_isnumber(co, -1)) {
            double wait_seconds = lua_tonumber(co, -1);
            lua_pop(co, 1);

            ScheduledTask new_task;
            new_task.id            = next_task_id_++;
            new_task.type          = ScheduledTask::Type::Delay;
            new_task.delay_seconds = wait_seconds;
            new_task.resume_at     = now +
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(wait_seconds));
            new_task.thread_ref = task.thread_ref;
            task.thread_ref     = LUA_NOREF;
            new_task.func_ref   = LUA_NOREF;
            tasks_.push_back(std::move(new_task));
        } else {
            ScheduledTask new_task;
            new_task.id         = next_task_id_++;
            new_task.type       = ScheduledTask::Type::Defer;
            new_task.resume_at  = now;
            new_task.thread_ref = task.thread_ref;
            task.thread_ref     = LUA_NOREF;
            new_task.func_ref   = LUA_NOREF;
            tasks_.push_back(std::move(new_task));
        }
    } else if (status != 0) {
        const char* err = lua_tostring(co, -1);
        if (error_cb_)
            error_cb_({err ? err : "task error", -1, "task"});
        LOG_ERROR("[Task] {}", err ? err : "unknown error");
    }
    // status == 0: coroutine finished normally

    release_task_refs(task);
}

int LuaEngine::schedule_task(ScheduledTask task) {
    task.id = next_task_id_++;
    int id  = task.id;
    tasks_.push_back(std::move(task));
    return id;
}

void LuaEngine::cancel_task(int task_id) {
    for (auto& t : tasks_)
        if (t.id == task_id) { t.cancelled = true; return; }
}

size_t LuaEngine::pending_task_count() const {
    size_t c = 0;
    for (const auto& t : tasks_)
        if (!t.cancelled) ++c;
    return c;
}

// ===========================================================================
// Drawing object store — local registry with sync to Overlay
// ===========================================================================

int LuaEngine::create_drawing_object(DrawingObject::Type type) {
    std::lock_guard<std::mutex> dlock(drawing_mutex_);
    int id = next_drawing_id_++;
    DrawingObject obj;
    obj.type = type;
    obj.id   = id;
    drawing_objects_[id] = obj;
    Overlay::instance().create_object_with_id(id, type);
    return id;
}

bool LuaEngine::get_drawing_object(int id, DrawingObject& out) {
    std::lock_guard<std::mutex> dlock(drawing_mutex_);
    auto it = drawing_objects_.find(id);
    if (it == drawing_objects_.end()) return false;
    out = it->second;
    return true;
}

bool LuaEngine::update_drawing_object(int id,
                                       const std::function<void(DrawingObject&)>& fn) {
    std::lock_guard<std::mutex> dlock(drawing_mutex_);
    auto it = drawing_objects_.find(id);
    if (it == drawing_objects_.end()) return false;
    fn(it->second);
    DrawingObject copy = it->second;
    Overlay::instance().update_object(id,
        [&copy](DrawingObject& o) { o = copy; });
    return true;
}

bool LuaEngine::remove_drawing_object(int id) {
    std::lock_guard<std::mutex> dlock(drawing_mutex_);
    auto it = drawing_objects_.find(id);
    if (it == drawing_objects_.end()) return false;
    if (it->second.image_surface) {
        cairo_surface_destroy(it->second.image_surface);
        it->second.image_surface = nullptr;
    }
    drawing_objects_.erase(it);
    Overlay::instance().remove_object(id);
    return true;
}

void LuaEngine::clear_all_drawing_objects() {
    std::lock_guard<std::mutex> dlock(drawing_mutex_);
    for (auto& [id, obj] : drawing_objects_) {
        if (obj.image_surface) {
            cairo_surface_destroy(obj.image_surface);
            obj.image_surface = nullptr;
        }
    }
    drawing_objects_.clear();
    Overlay::instance().clear_objects();
}

// ===========================================================================
// Global registration helpers
// ===========================================================================

void LuaEngine::register_function(const std::string& name,
                                   lua_CFunction func) {
    if (!L_) return;
    lua_pushcfunction(L_, func, name.c_str());
    lua_setglobal(L_, name.c_str());
}

void LuaEngine::register_library(const std::string& name,
                                  const luaL_Reg* funcs) {
    if (!L_) return;
    lua_newtable(L_);
    for (const luaL_Reg* f = funcs; f->name; ++f) {
        lua_pushcfunction(L_, f->func, f->name);
        lua_setfield(L_, -2, f->name);
    }
    lua_setglobal(L_, name.c_str());
}

void LuaEngine::set_global_string(const std::string& n,
                                   const std::string& v) {
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
        std::string v = lua_tostring(L_, -1);
        lua_pop(L_, 1);
        return v;
    }
    lua_pop(L_, 1);
    return std::nullopt;
}

// ===========================================================================
// Signals — fire with argument duplication
// ===========================================================================

int LuaEngine::fire_signal(const std::string& name, int nargs) {
    if (!L_) return 0;
    auto it = signals_.find(name);
    if (it == signals_.end()) {
        if (nargs > 0) lua_pop(L_, nargs);
        return 0;
    }

    int fired = 0;
    auto connections = it->second.connections;

    for (auto& conn : connections) {
        if (!conn.connected || conn.callback_ref == LUA_NOREF) continue;

        lua_rawgeti(L_, LUA_REGISTRYINDEX, conn.callback_ref);
        for (int i = 0; i < nargs; ++i)
            lua_pushvalue(L_, -(nargs + 1));

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
    auto& s = signals_[n];
    s.name  = n;
    return s;
}

// ===========================================================================
// Sandbox helpers
// ===========================================================================

bool LuaEngine::is_sandboxed(const std::string& full_path,
                              const std::string& base_dir) {
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(full_path, ec);
    if (ec) return false;
    auto base_canonical = std::filesystem::weakly_canonical(base_dir, ec);
    if (ec) return false;
    std::string cs = canonical.string();
    std::string bs = base_canonical.string();
    if (!bs.empty() && bs.back() != '/') bs += '/';
    return cs.find(bs) == 0 || cs == base_canonical.string();
}

// ===========================================================================
// Environment / library setup
// ===========================================================================

void LuaEngine::setup_environment() {
    register_function("print", lua_print);
    register_function("warn",  lua_warn_handler);
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

    lua_pushcfunction(L_, lua_drawing_index, "__index");
    lua_setfield(L_, -2, "__index");

    lua_pushcfunction(L_, lua_drawing_newindex, "__newindex");
    lua_setfield(L_, -2, "__newindex");

    lua_pushcfunction(L_, lua_drawing_gc, "__gc");
    lua_setfield(L_, -2, "__gc");

    lua_pushcfunction(L_, lua_drawing_tostring, "__tostring");
    lua_setfield(L_, -2, "__tostring");

    lua_pop(L_, 1);

    // Drawing library table
    lua_newtable(L_);

    lua_pushcfunction(L_, lua_drawing_new, "Drawing.new");
    lua_setfield(L_, -2, "new");

    lua_pushcfunction(L_, lua_drawing_clear, "Drawing.clear");
    lua_setfield(L_, -2, "clear");

    lua_pushcfunction(L_, lua_drawing_is_rendered, "Drawing.isRendered");
    lua_setfield(L_, -2, "isRendered");

    lua_pushcfunction(L_, lua_drawing_get_screen_size, "Drawing.getScreenSize");
    lua_setfield(L_, -2, "getScreenSize");

    lua_setglobal(L_, "Drawing");
}

void LuaEngine::register_signal_lib() {
    luaL_newmetatable(L_, "SignalObject");
    lua_pushstring(L_, "__index");
    lua_newtable(L_);
    lua_pushcfunction(L_, lua_signal_connect, "Signal.Connect");
    lua_setfield(L_, -2, "Connect");
    lua_pushcfunction(L_, lua_signal_fire, "Signal.Fire");
    lua_setfield(L_, -2, "Fire");
    lua_pushcfunction(L_, lua_signal_wait, "Signal.Wait");
    lua_setfield(L_, -2, "Wait");
    lua_pushcfunction(L_, lua_signal_destroy, "Signal.Destroy");
    lua_setfield(L_, -2, "Destroy");
    lua_settable(L_, -3);
    lua_pushcfunction(L_, lua_signal_gc, "Signal.__gc");
    lua_setfield(L_, -2, "__gc");
    lua_pop(L_, 1);

    luaL_newmetatable(L_, "SignalConnection");
    lua_pushstring(L_, "__index");
    lua_newtable(L_);
    lua_pushcfunction(L_, lua_signal_disconnect, "Connection.Disconnect");
    lua_setfield(L_, -2, "Disconnect");
    lua_settable(L_, -3);
    lua_pop(L_, 1);

    register_function("Signal", lua_signal_new);
}

void LuaEngine::register_custom_libs() {
    register_function("readfile",   lua_readfile);
    register_function("writefile",  lua_writefile);
    register_function("appendfile", lua_appendfile);
    register_function("isfile",     lua_isfile);
    register_function("listfiles",  lua_listfiles);
    register_function("delfolder",  lua_delfolder);
    register_function("makefolder", lua_makefolder);

    static const luaL_Reg http_lib[] = {
        {"get",  lua_http_get},
        {"post", lua_http_post},
        {nullptr, nullptr}
    };
    register_library("http", http_lib);

    // Alias http.get as global http_get
    lua_getglobal(L_, "http");
    lua_getfield(L_, -1, "get");
    lua_setglobal(L_, "http_get");
    lua_pop(L_, 1);

    register_function("wait",             lua_wait);
    register_function("spawn",            lua_spawn);
    register_function("getclipboard",     lua_getclipboard);
    register_function("setclipboard",     lua_setclipboard);
    register_function("identifyexecutor", lua_identifyexecutor);
    register_function("getexecutorname",  lua_getexecutorname);
    register_function("gethwid",          lua_get_hwid);
    register_function("loadstring",       lua_loadstring_impl);

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
    set_global_bool  ("_OSS",              true);

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
        game = game or {
            HttpGet = function(_, url)
                local ok, res = pcall(function() return http.get(url) end)
                if ok and res then return res.Body or "" end
                return ""
            end
        }
    )", "=env_setup");
}

void LuaEngine::sandbox() {
    // Manual sandboxing — restrict dangerous functions without freezing tables.
    // luaL_sandbox() is intentionally NOT called because it makes every
    // global table readonly, which prevents community scripts (ESP, aimbot,
    // etc.) from working.  Without luaL_sandbox(), luaL_sandboxthread() on
    // new threads is a harmless no-op, so all threads share L_'s writable
    // globals directly — exactly what executor scripts expect.
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
//  Drawing API
// ===========================================================================

int LuaEngine::lua_drawing_new(lua_State* L) {
    const char* ts = luaL_checkstring(L, 1);
    auto type = parse_drawing_type(ts);

    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    int id = eng->create_drawing_object(type);

    auto* h = static_cast<DrawingHandle*>(lua_newuserdata(L, sizeof(DrawingHandle)));
    h->id      = id;
    h->removed = false;
    luaL_getmetatable(L, DRAWING_OBJ_MT);
    lua_setmetatable(L, -2);
    return 1;
}

int LuaEngine::lua_drawing_index(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    const char* key = luaL_checkstring(L, 2);

    if (strcmp(key, "Remove") == 0 || strcmp(key, "Destroy") == 0) {
        lua_pushcfunction(L, lua_drawing_remove, "Drawing:Remove");
        return 1;
    }

    if (h->removed) { lua_pushnil(L); return 1; }

    auto* eng = get_engine(L);
    if (!eng) { lua_pushnil(L); return 1; }

    DrawingObject copy;
    if (!eng->get_drawing_object(h->id, copy)) { lua_pushnil(L); return 1; }

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
    auto* h = check_drawing_handle(L, 1);
    if (!h) return 0;

    const char* key = luaL_checkstring(L, 2);
    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    if (strcmp(key, "Visible") == 0) {
        bool v = lua_toboolean(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.visible = v; });
    }
    else if (strcmp(key, "ZIndex") == 0) {
        int v = static_cast<int>(luaL_checkinteger(L, 3));
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.z_index = v; });
    }
    else if (strcmp(key, "Transparency") == 0) {
        double v = std::clamp(luaL_checknumber(L, 3), 0.0, 1.0);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.transparency = v; });
    }
    else if (strcmp(key, "Thickness") == 0) {
        double v = std::max(0.0, luaL_checknumber(L, 3));
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.thickness = v; });
    }
    else if (strcmp(key, "Filled") == 0) {
        bool v = lua_toboolean(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.filled = v; });
    }
    else if (strcmp(key, "Radius") == 0) {
        double v = std::max(0.0, luaL_checknumber(L, 3));
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.radius = v; });
    }
    else if (strcmp(key, "NumSides") == 0) {
        int v = std::max(3, static_cast<int>(luaL_checkinteger(L, 3)));
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.num_sides = v; });
    }
    else if (strcmp(key, "Center") == 0) {
        bool v = lua_toboolean(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.center = v; });
    }
    else if (strcmp(key, "Outline") == 0) {
        bool v = lua_toboolean(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.outline = v; });
    }
    else if (strcmp(key, "Text") == 0) {
        std::string v = luaL_checkstring(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.text = v; });
    }
    else if (strcmp(key, "Size") == 0) {
        if (lua_isnumber(L, 3)) {
            double v = lua_tonumber(L, 3);
            eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.text_size = v; });
        } else {
            double x = 0, y = 0;
            read_vec2(L, 3, x, y);
            eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
                o.size_x = x; o.size_y = y;
            });
        }
    }
    else if (strcmp(key, "TextSize") == 0) {
        double v = luaL_checknumber(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.text_size = v; });
    }
    else if (strcmp(key, "Font") == 0) {
        int v = static_cast<int>(luaL_checkinteger(L, 3));
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.font = v; });
    }
    else if (strcmp(key, "Rounding") == 0) {
        double v = std::max(0.0, luaL_checknumber(L, 3));
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.rounding = v; });
    }
    else if (strcmp(key, "Position") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            o.pos_x = x; o.pos_y = y;
        });
    }
    else if (strcmp(key, "From") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            o.from_x = x; o.from_y = y;
        });
    }
    else if (strcmp(key, "To") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            o.to_x = x; o.to_y = y;
        });
    }
    else if (strcmp(key, "Color") == 0) {
        double r = 1, g = 1, b = 1;
        read_color(L, 3, r, g, b);
        eng->update_drawing_object(h->id, [r, g, b](DrawingObject& o){
            o.color_r = r; o.color_g = g; o.color_b = b;
        });
    }
    else if (strcmp(key, "OutlineColor") == 0) {
        double r = 0, g = 0, b = 0;
        read_color(L, 3, r, g, b);
        eng->update_drawing_object(h->id, [r, g, b](DrawingObject& o){
            o.outline_r = r; o.outline_g = g; o.outline_b = b;
        });
    }
    else if (strcmp(key, "PointA") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            if (o.type == DrawingObject::Type::Quad) { o.qa_x = x; o.qa_y = y; }
            else { o.pa_x = x; o.pa_y = y; }
        });
    }
    else if (strcmp(key, "PointB") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            if (o.type == DrawingObject::Type::Quad) { o.qb_x = x; o.qb_y = y; }
            else { o.pb_x = x; o.pb_y = y; }
        });
    }
    else if (strcmp(key, "PointC") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            if (o.type == DrawingObject::Type::Quad) { o.qc_x = x; o.qc_y = y; }
            else { o.pc_x = x; o.pc_y = y; }
        });
    }
    else if (strcmp(key, "PointD") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            o.qd_x = x; o.qd_y = y;
        });
    }
    else if (strcmp(key, "SizeXY") == 0) {
        double x = 0, y = 0;
        read_vec2(L, 3, x, y);
        eng->update_drawing_object(h->id, [x, y](DrawingObject& o){
            o.size_x = x; o.size_y = y;
        });
    }
    else if (strcmp(key, "ImageWidth") == 0) {
        double v = luaL_checknumber(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.image_w = v; });
    }
    else if (strcmp(key, "ImageHeight") == 0) {
        double v = luaL_checknumber(L, 3);
        eng->update_drawing_object(h->id, [v](DrawingObject& o){ o.image_h = v; });
    }
    else if (strcmp(key, "Data") == 0 || strcmp(key, "ImagePath") == 0) {
        std::string path = luaL_checkstring(L, 3);
        cairo_surface_t* surface = cairo_image_surface_create_from_png(path.c_str());
        if (surface && cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(surface);
            surface = nullptr;
        }
        eng->update_drawing_object(h->id, [&path, surface](DrawingObject& o){
            if (o.image_surface) cairo_surface_destroy(o.image_surface);
            o.image_path    = path;
            o.image_surface = surface;
        });
    }

    return 0;
}

int LuaEngine::lua_drawing_remove(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    if (!h->removed && h->id >= 0) {
        auto* eng = get_engine(L);
        if (eng) eng->remove_drawing_object(h->id);
        h->removed = true;
        h->id      = -1;
    }
    return 0;
}

int LuaEngine::lua_drawing_gc(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    if (!h->removed && h->id >= 0) {
        auto* eng = get_engine(L);
        if (eng) eng->remove_drawing_object(h->id);
        h->removed = true;
        h->id      = -1;
    }
    return 0;
}

int LuaEngine::lua_drawing_tostring(lua_State* L) {
    auto* h = static_cast<DrawingHandle*>(luaL_checkudata(L, 1, DRAWING_OBJ_MT));
    if (h->removed)
        lua_pushstring(L, "Drawing(removed)");
    else
        lua_pushfstring(L, "Drawing(%d)", h->id);
    return 1;
}

int LuaEngine::lua_drawing_clear(lua_State* L) {
    auto* eng = get_engine(L);
    if (eng) eng->clear_all_drawing_objects();
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
//  Task library — coroutine-based scheduler (Luau)
// ===========================================================================

int LuaEngine::lua_task_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    lua_State* co = lua_newthread(eng->L_);
    luaL_sandboxthread(co);
    int thread_ref = lua_ref(eng->L_, -1);
    lua_pop(eng->L_, 1);

    // Push function and args onto coroutine
    lua_pushvalue(L, 1);
    lua_xmove(L, co, 1);
    int nargs = lua_gettop(L) - 1;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 2);
        lua_xmove(L, co, 1);
    }

    int status = lua_resume(co, nullptr, nargs);

    if (status == LUA_YIELD) {
        if (lua_gettop(co) > 0 && lua_isnumber(co, -1)) {
            double wait_seconds = lua_tonumber(co, -1);
            lua_pop(co, 1);
            ScheduledTask task;
            task.type          = ScheduledTask::Type::Delay;
            task.delay_seconds = wait_seconds;
            task.resume_at     = std::chrono::steady_clock::now() +
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(wait_seconds));
            task.thread_ref = thread_ref;
            task.func_ref   = LUA_NOREF;
            eng->schedule_task(std::move(task));
        } else {
            ScheduledTask task;
            task.type       = ScheduledTask::Type::Defer;
            task.resume_at  = std::chrono::steady_clock::now();
            task.thread_ref = thread_ref;
            task.func_ref   = LUA_NOREF;
            eng->schedule_task(std::move(task));
        }
    } else if (status != 0) {
        const char* err = lua_tostring(co, -1);
        if (eng->error_cb_)
            eng->error_cb_({err ? err : "task.spawn error", -1, "task.spawn"});
        LOG_ERROR("[task.spawn] {}", err ? err : "unknown error");
    }

    // Push thread for return BEFORE releasing the reference
    lua_rawgeti(L, LUA_REGISTRYINDEX, thread_ref);
    if (!lua_isthread(L, -1)) {
        lua_pop(L, 1);
        lua_pushnil(L);
    }

    // Release ref if coroutine completed or errored (yielded refs are owned by tasks)
    if (status != LUA_YIELD) {
        lua_unref(eng->L_, thread_ref);
    }
    return 1;
}

int LuaEngine::lua_task_delay(lua_State* L) {
    double seconds = luaL_checknumber(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    if (seconds < 0) seconds = 0;

    ScheduledTask task;
    task.type          = ScheduledTask::Type::Delay;
    task.delay_seconds = seconds;
    task.resume_at     = std::chrono::steady_clock::now() +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(seconds));

    lua_pushvalue(L, 2);
    task.func_ref = lua_ref(L, -1);
    lua_pop(L, 1);

    int nargs = lua_gettop(L) - 2;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 3);
        int aref = lua_ref(L, -1);
        lua_pop(L, 1);
        task.arg_refs.push_back(aref);
    }

    int id = eng->schedule_task(std::move(task));
    lua_pushinteger(L, id);
    return 1;
}

int LuaEngine::lua_task_defer(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    ScheduledTask task;
    task.type      = ScheduledTask::Type::Defer;
    task.resume_at = std::chrono::steady_clock::now();

    lua_pushvalue(L, 1);
    task.func_ref = lua_ref(L, -1);
    lua_pop(L, 1);

    int nargs = lua_gettop(L) - 1;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 2);
        int aref = lua_ref(L, -1);
        lua_pop(L, 1);
        task.arg_refs.push_back(aref);
    }

    int id = eng->schedule_task(std::move(task));
    lua_pushinteger(L, id);
    return 1;
}

int LuaEngine::lua_task_wait(lua_State* L) {
    double s = luaL_optnumber(L, 1, 0.03);
    if (s < 0) s = 0;

    // Check if we're on the main thread
    if (lua_pushthread(L)) {
        // Main thread — can't yield, fallback to sleep
        lua_pop(L, 1);
        std::this_thread::sleep_for(
            std::chrono::milliseconds(static_cast<int>(s * 1000)));
        lua_pushnumber(L, s);
        return 1;
    }
    lua_pop(L, 1);

    // Coroutine — yield with wait duration
    lua_pushnumber(L, s);
    return lua_yield(L, 1);
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

int LuaEngine::lua_signal_new(lua_State* L) {
    const char* name = luaL_optstring(L, 1, "");
    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    std::string sig_name = name;
    if (sig_name.empty())
        sig_name = "signal_" + std::to_string(eng->next_signal_id_++);
    eng->get_or_create_signal(sig_name);

    auto* ud = static_cast<SignalUserdata*>(
        lua_newuserdata(L, sizeof(SignalUserdata)));
    memset(ud->name, 0, sizeof(ud->name));
    strncpy(ud->name, sig_name.c_str(), sizeof(ud->name) - 1);
    ud->destroyed = false;
    luaL_getmetatable(L, "SignalObject");
    lua_setmetatable(L, -2);
    return 1;
}

int LuaEngine::lua_signal_connect(lua_State* L) {
    auto* ud = check_signal_ud(L, 1);
    if (!ud) return 0;
    luaL_checktype(L, 2, LUA_TFUNCTION);

    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    Signal* sig = eng->get_signal(ud->name);
    if (!sig) { luaL_error(L, "Signal '%s' not found", ud->name); return 0; }

    lua_pushvalue(L, 2);
    int ref = lua_ref(L, -1);
    lua_pop(L, 1);

    Signal::Connection conn;
    conn.callback_ref = ref;
    conn.id           = sig->next_id++;
    conn.connected    = true;
    sig->connections.push_back(conn);

    auto* cud = static_cast<ConnUD*>(lua_newuserdata(L, sizeof(ConnUD)));
    memset(cud->sig_name, 0, sizeof(cud->sig_name));
    snprintf(cud->sig_name, sizeof(cud->sig_name), "%s", ud->name);
    cud->conn_id      = conn.id;
    cud->disconnected  = false;
    luaL_getmetatable(L, "SignalConnection");
    lua_setmetatable(L, -2);
    return 1;
}

int LuaEngine::lua_signal_fire(lua_State* L) {
    auto* ud = check_signal_ud(L, 1);
    if (!ud) return 0;

    int nargs = lua_gettop(L) - 1;
    auto* eng = get_engine(L);
    if (!eng) return 0;

    Signal* sig = eng->get_signal(ud->name);
    if (!sig) return 0;

    auto connections_copy = sig->connections;

    for (auto& conn : connections_copy) {
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
    auto* cud = static_cast<ConnUD*>(luaL_checkudata(L, 1, "SignalConnection"));
    if (cud->disconnected) return 0;

    auto* eng = get_engine(L);
    if (!eng) return 0;

    Signal* sig = eng->get_signal(cud->sig_name);
    if (!sig) return 0;

    for (auto it = sig->connections.begin(); it != sig->connections.end(); ++it) {
        if (it->id == cud->conn_id) {
            it->connected = false;
            if (it->callback_ref != LUA_NOREF) {
                lua_unref(L, it->callback_ref);
                it->callback_ref = LUA_NOREF;
            }
            sig->connections.erase(it);
            break;
        }
    }
    cud->disconnected = true;
    return 0;
}

int LuaEngine::lua_signal_destroy(lua_State* L) {
    auto* ud = static_cast<SignalUserdata*>(luaL_checkudata(L, 1, "SignalObject"));
    if (ud->destroyed) return 0;

    auto* eng = get_engine(L);
    if (!eng) return 0;

    Signal* sig = eng->get_signal(ud->name);
    if (sig) {
        for (auto& c : sig->connections) {
            if (c.callback_ref != LUA_NOREF) {
                lua_unref(L, c.callback_ref);
                c.callback_ref = LUA_NOREF;
            }
        }
        eng->signals_.erase(ud->name);
    }
    ud->destroyed = true;
    return 0;
}

int LuaEngine::lua_signal_gc(lua_State* L) {
    auto* ud = static_cast<SignalUserdata*>(luaL_checkudata(L, 1, "SignalObject"));
    if (!ud->destroyed) {
        auto* eng = get_engine(L);
        if (eng) {
            Signal* sig = eng->get_signal(ud->name);
            if (sig) {
                for (auto& c : sig->connections) {
                    if (c.callback_ref != LUA_NOREF) {
                        lua_unref(L, c.callback_ref);
                        c.callback_ref = LUA_NOREF;
                    }
                }
                eng->signals_.erase(ud->name);
            }
            ud->destroyed = true;
        }
    }
    return 0;
}

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
            snprintf(buf, sizeof(buf), "%s: %p",
                     luaL_typename(L, i), lua_topointer(L, i));
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

    if (msg) {
        const char* phantom = strstr(msg, "Phantom exec");
        if (phantom) {
            LOG_DEBUG("[Lua] (mock mode) {}", msg);
            return 0;
        }
    }

    auto* eng = get_engine(L);
    if (eng && eng->output_cb_) eng->output_cb_(std::string("[WARN] ") + msg);
    LOG_WARN("[Lua] {}", msg);
    return 0;
}

int LuaEngine::lua_pcall_handler(lua_State* L) {
    const char* msg = lua_tostring(L, -1);
    if (!msg) msg = "Unknown error";
    lua_pushstring(L, msg);
    return 1;
}

// ===========================================================================
//  HTTP
// ===========================================================================

int LuaEngine::lua_http_get(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    auto resp = Http::instance().get(url);
    lua_newtable(L);
    lua_pushstring(L, resp.body.c_str());
    lua_setfield(L, -2, "Body");
    lua_pushinteger(L, static_cast<int>(resp.status_code));
    lua_setfield(L, -2, "StatusCode");
    lua_pushboolean(L, resp.success());
    lua_setfield(L, -2, "Success");
    if (!resp.error.empty()) {
        lua_pushstring(L, resp.error.c_str());
        lua_setfield(L, -2, "Error");
    }
    lua_newtable(L);
    for (const auto& [k, v] : resp.headers) {
        lua_pushstring(L, v.c_str());
        lua_setfield(L, -2, k.c_str());
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
    lua_pushstring(L, resp.body.c_str());
    lua_setfield(L, -2, "Body");
    lua_pushinteger(L, static_cast<int>(resp.status_code));
    lua_setfield(L, -2, "StatusCode");
    lua_pushboolean(L, resp.success());
    lua_setfield(L, -2, "Success");
    if (!resp.error.empty()) {
        lua_pushstring(L, resp.error.c_str());
        lua_setfield(L, -2, "Error");
    }
    return 1;
}

// ===========================================================================
//  wait / spawn (global versions)
// ===========================================================================

int LuaEngine::lua_wait(lua_State* L) {
    double s = luaL_optnumber(L, 1, 0.03);
    if (s < 0) s = 0;

    if (lua_pushthread(L)) {
        lua_pop(L, 1);
        std::this_thread::sleep_for(
            std::chrono::milliseconds(static_cast<int>(s * 1000)));
        lua_pushnumber(L, s);
        lua_pushnumber(L, s);
        return 2;
    }
    lua_pop(L, 1);

    lua_pushnumber(L, s);
    return lua_yield(L, 1);
}

int LuaEngine::lua_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    auto* eng = get_engine(L);
    if (!eng) { luaL_error(L, "engine not available"); return 0; }

    lua_State* co = lua_newthread(eng->L_);
    luaL_sandboxthread(co);
    int thread_ref = lua_ref(eng->L_, -1);
    lua_pop(eng->L_, 1);

    lua_pushvalue(L, 1);
    lua_xmove(L, co, 1);
    int nargs = lua_gettop(L) - 1;
    for (int i = 0; i < nargs; ++i) {
        lua_pushvalue(L, i + 2);
        lua_xmove(L, co, 1);
    }

    int status = lua_resume(co, nullptr, nargs);

    if (status == LUA_YIELD) {
        if (lua_gettop(co) > 0 && lua_isnumber(co, -1)) {
            double wait_seconds = lua_tonumber(co, -1);
            lua_pop(co, 1);
            ScheduledTask task;
            task.type          = ScheduledTask::Type::Delay;
            task.delay_seconds = wait_seconds;
            task.resume_at     = std::chrono::steady_clock::now() +
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(wait_seconds));
            task.thread_ref = thread_ref;
            task.func_ref   = LUA_NOREF;
            eng->schedule_task(std::move(task));
        } else {
            ScheduledTask task;
            task.type       = ScheduledTask::Type::Defer;
            task.resume_at  = std::chrono::steady_clock::now();
            task.thread_ref = thread_ref;
            task.func_ref   = LUA_NOREF;
            eng->schedule_task(std::move(task));
        }
    } else if (status != 0) {
        const char* err = lua_tostring(co, -1);
        if (eng->error_cb_)
            eng->error_cb_({err ? err : "spawn error", -1, "spawn"});
        LOG_ERROR("[spawn] {}", err ? err : "unknown error");
    }

    // Push thread for return BEFORE releasing the reference
    lua_rawgeti(L, LUA_REGISTRYINDEX, thread_ref);
    if (!lua_isthread(L, -1)) {
        lua_pop(L, 1);
        lua_pushnil(L);
    }

    // Release ref if coroutine completed or errored (yielded refs are owned by tasks)
    if (status != LUA_YIELD) {
        lua_unref(eng->L_, thread_ref);
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
    if (!is_sandboxed(full, base)) {
        luaL_error(L, "Access denied: path traversal detected");
        return 0;
    }
    std::ifstream f(full);
    if (!f.is_open()) {
        luaL_error(L, "Cannot open file: %s", path);
        return 0;
    }
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    lua_pushlstring(L, content.c_str(), content.size());
    return 1;
}

int LuaEngine::lua_writefile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    size_t content_len;
    const char* content = luaL_checklstring(L, 2, &content_len);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base)) {
        luaL_error(L, "Access denied: path traversal detected");
        return 0;
    }
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(full).parent_path(), ec);
    std::ofstream f(full, std::ios::binary);
    if (!f.is_open()) {
        luaL_error(L, "Cannot write file: %s", path);
        return 0;
    }
    f.write(content, static_cast<std::streamsize>(content_len));
    return 0;
}

int LuaEngine::lua_appendfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    size_t content_len;
    const char* content = luaL_checklstring(L, 2, &content_len);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base)) {
        luaL_error(L, "Access denied: path traversal detected");
        return 0;
    }
    std::ofstream f(full, std::ios::app | std::ios::binary);
    if (!f.is_open()) {
        luaL_error(L, "Cannot append to file: %s", path);
        return 0;
    }
    f.write(content, static_cast<std::streamsize>(content_len));
    return 0;
}

int LuaEngine::lua_isfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base)) { lua_pushboolean(L, false); return 1; }
    std::error_code ec;
    lua_pushboolean(L, std::filesystem::exists(full, ec) &&
                       std::filesystem::is_regular_file(full, ec));
    return 1;
}

int LuaEngine::lua_listfiles(lua_State* L) {
    const char* path = luaL_optstring(L, 1, "");
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    lua_newtable(L);
    if (!is_sandboxed(full, base)) return 1;
    int idx = 1;
    std::error_code ec;
    if (std::filesystem::exists(full, ec) &&
        std::filesystem::is_directory(full, ec)) {
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
    if (!is_sandboxed(full, base)) {
        luaL_error(L, "Access denied: path traversal detected");
        return 0;
    }
    std::error_code ec;
    std::filesystem::remove_all(full, ec);
    return 0;
}

int LuaEngine::lua_makefolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::string base = Config::instance().home_dir() + "/workspace/";
    std::string full = base + path;
    if (!is_sandboxed(full, base)) {
        luaL_error(L, "Access denied: path traversal detected");
        return 0;
    }
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
        while (fgets(buf.data(), static_cast<int>(buf.size()), pipe))
            result += buf.data();
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
    size_t encoded_len;
    const char* encoded = luaL_checklstring(L, 1, &encoded_len);

    static const auto table = []() {
        std::array<unsigned char, 256> t{};
        t.fill(0xFF);
        const char* chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (size_t i = 0; i < 64; ++i)
            t[static_cast<unsigned char>(chars[i])] =
                static_cast<unsigned char>(i);
        t[static_cast<unsigned char>('=')] = 0;
        return t;
    }();

    std::string output;
    output.reserve(encoded_len * 3 / 4);

    size_t i = 0;
    while (i < encoded_len) {
        while (i < encoded_len &&
               (encoded[i] == '\n' || encoded[i] == '\r' ||
                encoded[i] == ' '  || encoded[i] == '\t'))
            ++i;
        if (i >= encoded_len) break;

        uint32_t n = 0;
        int pad = 0;
        int chars_read = 0;

        for (int j = 0; j < 4 && i < encoded_len; ++j) {
            unsigned char c = static_cast<unsigned char>(encoded[i]);
            if (c == '=') {
                ++pad;
                n <<= 6;
            } else if (table[c] != 0xFF) {
                n = (n << 6) | table[c];
            } else {
                --j;
                ++i;
                continue;
            }
            ++i;
            ++chars_read;
        }

        if (chars_read < 2) break;

        output += static_cast<char>((n >> 16) & 0xFF);
        if (pad < 2) output += static_cast<char>((n >> 8) & 0xFF);
        if (pad < 1) output += static_cast<char>(n & 0xFF);
    }

    lua_pushlstring(L, output.c_str(), output.size());
    return 1;
}

int LuaEngine::lua_sha256(lua_State* L) {
    size_t len;
    const char* input = luaL_checklstring(L, 1, &len);
    lua_pushstring(L, Crypto::sha256(std::string(input, len)).c_str());
    return 1;
}

} // namespace oss





