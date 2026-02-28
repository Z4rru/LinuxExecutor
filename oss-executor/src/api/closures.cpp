#include "closures.hpp"
#include "../ui/overlay.hpp"
#include "../utils/logger.hpp"
#include "../utils/http.hpp"
#include "../core/lua_engine.hpp"
#include "Luau/Compiler.h"
#include <spdlog/spdlog.h>
#include <ctime>
#include <cmath>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstring>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <deque>

namespace oss {

const char* Closures::EXECUTOR_MARKER = "__oss_executor_closure";
const char* Closures::HOOK_TABLE_KEY  = "__oss_hook_table";

struct InstanceData {
    int id = 0;
    int overlay_id = 0;
    std::string class_name;
    std::string name;
    int parent_id = 0;
};

static std::mutex g_inst_mtx;
static std::unordered_map<int, InstanceData> g_inst_reg;
static std::unordered_map<int, std::vector<int>> g_inst_children;
static int g_next_id = 1;
static const std::string WS_DIR = "workspace";
static std::atomic<bool> g_cancel{false};

struct Deferred {
    lua_State* thr;
    int nargs;
    double at;
};

static std::mutex g_def_mtx;
static std::deque<Deferred> g_deferred;
static auto g_epoch = std::chrono::steady_clock::now();

static double mono() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now() - g_epoch).count();
}

void Closures::cancel_execution()   { g_cancel.store(true); }
void Closures::reset_cancellation() { g_cancel.store(false); }

static void chk(lua_State* L) {
    if (g_cancel.load()) luaL_error(L, "Execution cancelled");
}

void Closures::pump_deferred() {
    double now = mono();
    std::vector<Deferred> ready;
    {
        std::lock_guard<std::mutex> lk(g_def_mtx);
        auto it = g_deferred.begin();
        while (it != g_deferred.end()) {
            if (it->at <= now) { ready.push_back(*it); it = g_deferred.erase(it); }
            else ++it;
        }
    }
    for (auto& d : ready) {
        int st = lua_resume(d.thr, nullptr, d.nargs);
        if (st == LUA_YIELD) {
            double w = 0.03;
            if (lua_isnumber(d.thr, -1)) { w = lua_tonumber(d.thr, -1); lua_pop(d.thr, 1); }
            std::lock_guard<std::mutex> lk(g_def_mtx);
            g_deferred.push_back({d.thr, 0, mono() + w});
        } else if (st != 0) {
            const char* e = lua_tostring(d.thr, -1);
            spdlog::error("[task] {}", e ? e : "unknown");
        }
    }
}

static void inst_register(int id, int ov, const std::string& cn,
                           const std::string& nm, int pid = 0) {
    std::lock_guard<std::mutex> lk(g_inst_mtx);
    g_inst_reg[id] = {id, ov, cn, nm, pid};
    if (pid > 0) g_inst_children[pid].push_back(id);
}

static void inst_unregister(int id) {
    std::lock_guard<std::mutex> lk(g_inst_mtx);
    auto it = g_inst_reg.find(id);
    if (it == g_inst_reg.end()) return;
    int pid = it->second.parent_id;
    if (pid > 0) {
        auto& ch = g_inst_children[pid];
        ch.erase(std::remove(ch.begin(), ch.end(), id), ch.end());
    }
    auto cit = g_inst_children.find(id);
    if (cit != g_inst_children.end()) {
        for (int c : cit->second) {
            auto ci = g_inst_reg.find(c);
            if (ci != g_inst_reg.end()) ci->second.parent_id = 0;
        }
        g_inst_children.erase(cit);
    }
    g_inst_reg.erase(it);
}

static void inst_set_parent(int id, int npid) {
    std::lock_guard<std::mutex> lk(g_inst_mtx);
    auto it = g_inst_reg.find(id);
    if (it == g_inst_reg.end()) return;
    int old = it->second.parent_id;
    if (old > 0) {
        auto& ch = g_inst_children[old];
        ch.erase(std::remove(ch.begin(), ch.end(), id), ch.end());
    }
    it->second.parent_id = npid;
    if (npid > 0) g_inst_children[npid].push_back(id);
}

static void inst_set_name(int id, const std::string& nm) {
    std::lock_guard<std::mutex> lk(g_inst_mtx);
    auto it = g_inst_reg.find(id);
    if (it != g_inst_reg.end()) it->second.name = nm;
}

static int inst_find_child(int pid, const std::string& name) {
    std::lock_guard<std::mutex> lk(g_inst_mtx);
    auto cit = g_inst_children.find(pid);
    if (cit == g_inst_children.end()) return 0;
    for (int c : cit->second) {
        auto ci = g_inst_reg.find(c);
        if (ci != g_inst_reg.end() && ci->second.name == name) return c;
    }
    return 0;
}

static std::vector<int> inst_get_children(int pid) {
    std::lock_guard<std::mutex> lk(g_inst_mtx);
    auto cit = g_inst_children.find(pid);
    if (cit == g_inst_children.end()) return {};
    return cit->second;
}

static InstanceData inst_get_data(int id) {
    std::lock_guard<std::mutex> lk(g_inst_mtx);
    auto it = g_inst_reg.find(id);
    if (it != g_inst_reg.end()) return it->second;
    return {};
}

static std::string get_ws(const std::string& fn = "") {
    std::filesystem::create_directories(WS_DIR);
    if (fn.empty()) return WS_DIR;
    return WS_DIR + "/" + fn;
}

static void push_color3(lua_State* L, double r, double g, double b) {
    lua_newtable(L);
    lua_pushnumber(L, r); lua_setfield(L, -2, "R");
    lua_pushnumber(L, g); lua_setfield(L, -2, "G");
    lua_pushnumber(L, b); lua_setfield(L, -2, "B");
    lua_pushstring(L, "Color3"); lua_setfield(L, -2, "__type");
}

static void push_udim2(lua_State* L, double xs, double xo, double ys, double yo) {
    lua_newtable(L);
    lua_newtable(L);
    lua_pushnumber(L, xs); lua_setfield(L, -2, "Scale");
    lua_pushnumber(L, xo); lua_setfield(L, -2, "Offset");
    lua_setfield(L, -2, "X");
    lua_newtable(L);
    lua_pushnumber(L, ys); lua_setfield(L, -2, "Scale");
    lua_pushnumber(L, yo); lua_setfield(L, -2, "Offset");
    lua_setfield(L, -2, "Y");
    lua_pushstring(L, "UDim2"); lua_setfield(L, -2, "__type");
    lua_pushnumber(L, xs); lua_setfield(L, -2, "_xs");
    lua_pushnumber(L, xo); lua_setfield(L, -2, "_xo");
    lua_pushnumber(L, ys); lua_setfield(L, -2, "_ys");
    lua_pushnumber(L, yo); lua_setfield(L, -2, "_yo");
}

static void push_vector2(lua_State* L, double x, double y) {
    lua_newtable(L);
    lua_pushnumber(L, x); lua_setfield(L, -2, "X");
    lua_pushnumber(L, y); lua_setfield(L, -2, "Y");
    lua_pushnumber(L, std::sqrt(x * x + y * y)); lua_setfield(L, -2, "Magnitude");
    lua_pushstring(L, "Vector2"); lua_setfield(L, -2, "__type");
}

static void read_udim2(lua_State* L, int idx, float& xs, float& xo, float& ys, float& yo) {
    xs = xo = ys = yo = 0;
    if (!lua_istable(L, idx)) return;
    lua_getfield(L, idx, "_xs"); if (lua_isnumber(L, -1)) xs = (float)lua_tonumber(L, -1); lua_pop(L, 1);
    lua_getfield(L, idx, "_xo"); if (lua_isnumber(L, -1)) xo = (float)lua_tonumber(L, -1); lua_pop(L, 1);
    lua_getfield(L, idx, "_ys"); if (lua_isnumber(L, -1)) ys = (float)lua_tonumber(L, -1); lua_pop(L, 1);
    lua_getfield(L, idx, "_yo"); if (lua_isnumber(L, -1)) yo = (float)lua_tonumber(L, -1); lua_pop(L, 1);
}

static void read_color3(lua_State* L, int idx, float& r, float& g, float& b) {
    r = g = b = 0;
    if (!lua_istable(L, idx)) return;
    lua_getfield(L, idx, "R"); if (lua_isnumber(L, -1)) r = (float)lua_tonumber(L, -1); lua_pop(L, 1);
    lua_getfield(L, idx, "G"); if (lua_isnumber(L, -1)) g = (float)lua_tonumber(L, -1); lua_pop(L, 1);
    lua_getfield(L, idx, "B"); if (lua_isnumber(L, -1)) b = (float)lua_tonumber(L, -1); lua_pop(L, 1);
}

static void push_instance(lua_State* L, int instance_id, const std::string& class_name) {
    lua_newtable(L);
    lua_pushinteger(L, instance_id);       lua_setfield(L, -2, "__id");
    lua_pushstring(L, class_name.c_str()); lua_setfield(L, -2, "ClassName");
    lua_pushstring(L, class_name.c_str()); lua_setfield(L, -2, "Name");
    lua_pushcfunction(L, Closures::l_instance_destroy,       "Destroy");        lua_setfield(L, -2, "Destroy");
    lua_pushcfunction(L, Closures::l_instance_getchildren,   "GetChildren");    lua_setfield(L, -2, "GetChildren");
    lua_pushcfunction(L, Closures::l_instance_findfirstchild,"FindFirstChild"); lua_setfield(L, -2, "FindFirstChild");
    lua_pushcfunction(L, Closures::l_instance_waitforchild,  "WaitForChild");   lua_setfield(L, -2, "WaitForChild");
    lua_pushcfunction(L, Closures::l_instance_isA,           "IsA");            lua_setfield(L, -2, "IsA");
    lua_pushcfunction(L, Closures::l_instance_clone,         "Clone");          lua_setfield(L, -2, "Clone");
    lua_newtable(L);
    lua_pushcfunction(L, Closures::l_instance_index,   "__index");    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, Closures::l_instance_newindex, "__newindex"); lua_setfield(L, -2, "__newindex");
    lua_pushstring(L, class_name.c_str()); lua_setfield(L, -2, "__type");
    lua_setmetatable(L, -2);
}

static bool compile_and_load(lua_State* L, const char* src, const char* chunkname) {
    Luau::CompileOptions opts;
    opts.optimizationLevel = 1;
    std::string bc = Luau::compile(src, opts);
    if (!bc.empty() && bc[0] == 0) return false;
    return luau_load(L, chunkname, bc.data(), bc.size(), 0) == 0;
}

void Closures::ensure_hook_table(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    }
    lua_pop(L, 1);
}

int Closures::get_hook_table(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    }
    return 1;
}

void Closures::register_all(lua_State* L) {
    ensure_hook_table(L);
    lua_pushboolean(L, 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "__oss_is_executor");

    lua_pushcfunction(L, wrap_closure,        "wrapclosure");       lua_setglobal(L, "wrapclosure");
    lua_pushcfunction(L, getscriptclosure,    "getscriptclosure");  lua_setglobal(L, "getscriptclosure");
    lua_pushcfunction(L, compare_closures,    "compareinstances");  lua_setglobal(L, "compareinstances");
    lua_pushcfunction(L, clone_function,      "clonefunction");     lua_setglobal(L, "clonefunction");
    lua_pushcfunction(L, get_calling_script,  "getcallingscript");  lua_setglobal(L, "getcallingscript");
    lua_pushcfunction(L, l_newcclosure,       "newcclosure");       lua_setglobal(L, "newcclosure");
    lua_pushcfunction(L, l_hookfunction,      "hookfunction");      lua_setglobal(L, "hookfunction");
    lua_pushcfunction(L, l_hookfunction,      "replaceclosure");    lua_setglobal(L, "replaceclosure");
    lua_pushcfunction(L, l_hookmetamethod,    "hookmetamethod");    lua_setglobal(L, "hookmetamethod");
    lua_pushcfunction(L, iscclosure,          "iscclosure");        lua_setglobal(L, "iscclosure");
    lua_pushcfunction(L, islclosure,          "islclosure");        lua_setglobal(L, "islclosure");
    lua_pushcfunction(L, l_isexecutorclosure, "isexecutorclosure"); lua_setglobal(L, "isexecutorclosure");
    lua_pushcfunction(L, l_isexecutorclosure, "checkclosure");      lua_setglobal(L, "checkclosure");
    lua_pushcfunction(L, l_isexecutorclosure, "isourclosure");      lua_setglobal(L, "isourclosure");
    lua_pushcfunction(L, l_checkcaller,       "checkcaller");       lua_setglobal(L, "checkcaller");
    lua_pushcfunction(L, l_getinfo,           "getinfo");           lua_setglobal(L, "getinfo");
    lua_pushcfunction(L, l_loadstring,        "loadstring");        lua_setglobal(L, "loadstring");
    lua_pushcfunction(L, newlclosure,         "newlclosure");       lua_setglobal(L, "newlclosure");
}

int Closures::l_print(lua_State* L) {
    int n = lua_gettop(L);
    std::string out;
    for (int i = 1; i <= n; i++) {
        size_t len;
        const char* s = luaL_tolstring(L, i, &len);
        if (i > 1) out += "\t";
        if (s) out += std::string(s, len);
        lua_pop(L, 1);
    }
    spdlog::info("[Script] {}", out);
    return 0;
}

int Closures::l_warn(lua_State* L) {
    int n = lua_gettop(L);
    std::string out;
    for (int i = 1; i <= n; i++) {
        size_t len;
        const char* s = luaL_tolstring(L, i, &len);
        if (i > 1) out += "\t";
        if (s) out += std::string(s, len);
        lua_pop(L, 1);
    }
    spdlog::warn("[Script] {}", out);
    return 0;
}

int Closures::l_wait(lua_State* L) {
    double seconds = luaL_optnumber(L, 1, 0.03);
    if (seconds < 0) seconds = 0;
    if (seconds > 10) seconds = 10;
    auto start = std::chrono::steady_clock::now();
    double elapsed = 0;
    while (elapsed < seconds) {
        chk(L);
        pump_deferred();
        double chunk = std::min(seconds - elapsed, 0.016);
        std::this_thread::sleep_for(std::chrono::duration<double>(chunk));
        elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count();
    }
    lua_pushnumber(L, elapsed);
    lua_pushnumber(L, elapsed);
    return 2;
}

int Closures::l_delay(lua_State* L) {
    double seconds = luaL_checknumber(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (seconds < 0) seconds = 0;
    if (seconds > 30) seconds = 30;

    lua_State* thr = lua_newthread(L);
    luaL_sandboxthread(thr);
    lua_pushvalue(L, 2);
    lua_xmove(L, thr, 1);

    {
        std::lock_guard<std::mutex> lk(g_def_mtx);
        g_deferred.push_back({thr, 0, mono() + seconds});
    }
    return 0;
}

int Closures::l_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int top = lua_gettop(L);
    int nargs = top - 1;

    lua_State* thr = lua_newthread(L);
    luaL_sandboxthread(thr);

    lua_pushvalue(L, 1);
    for (int i = 2; i <= top; i++)
        lua_pushvalue(L, i);
    lua_xmove(L, thr, 1 + nargs);

    int status = lua_resume(thr, nullptr, nargs);
    if (status != 0 && status != LUA_YIELD) {
        const char* err = lua_tostring(thr, -1);
        spdlog::error("[spawn] {}", err ? err : "unknown");
    } else if (status == LUA_YIELD) {
        double w = 0.03;
        if (lua_isnumber(thr, -1)) { w = lua_tonumber(thr, -1); lua_pop(thr, 1); }
        std::lock_guard<std::mutex> lk(g_def_mtx);
        g_deferred.push_back({thr, 0, mono() + w});
    }
    return 0;
}

int Closures::l_loadstring(lua_State* L) {
    size_t len;
    const char* source = luaL_checklstring(L, 1, &len);
    const char* chunkname = luaL_optstring(L, 2, "=loadstring");

    Luau::CompileOptions opts;
    opts.optimizationLevel = 1;
    opts.debugLevel = 1;
    std::string bytecode = Luau::compile(std::string(source, len), opts);

    if (!bytecode.empty() && bytecode[0] == 0) {
        lua_pushnil(L);
        lua_pushstring(L, bytecode.c_str() + 1);
        return 2;
    }

    if (luau_load(L, chunkname, bytecode.data(), bytecode.size(), 0) != 0) {
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }

    get_hook_table(L);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    return 1;
}

int Closures::l_typeof(lua_State* L) {
    if (lua_istable(L, 1)) {
        lua_getfield(L, 1, "__type");
        if (lua_isstring(L, -1)) return 1;
        lua_pop(L, 1);
    }
    lua_pushstring(L, luaL_typename(L, 1));
    return 1;
}

int Closures::l_tick(lua_State* L) {
    lua_pushnumber(L, std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    return 1;
}

int Closures::l_instance_new(lua_State* L) {
    const char* cn = luaL_checkstring(L, 1);
    auto& overlay = Overlay::instance();
    int ov_id = overlay.create_gui_element(cn, cn);
    int inst_id = g_next_id++;
    int parent_inst = 0;

    if (lua_gettop(L) >= 2 && lua_istable(L, 2)) {
        lua_getfield(L, 2, "__id");
        if (lua_isnumber(L, -1)) {
            parent_inst = (int)lua_tointeger(L, -1);
            auto pd = inst_get_data(parent_inst);
            if (pd.id > 0)
                overlay.set_gui_parent(ov_id, pd.overlay_id);
        }
        lua_pop(L, 1);
    }

    inst_register(inst_id, ov_id, cn, cn, parent_inst);
    push_instance(L, inst_id, cn);
    spdlog::debug("Instance.new('{}') id={} ov={}", cn, inst_id, ov_id);
    return 1;
}

int Closures::l_instance_index(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);

    lua_pushvalue(L, 2);
    lua_rawget(L, 1);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 1);

    lua_getfield(L, 1, "__id");
    if (!lua_isnumber(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; }
    int inst_id = (int)lua_tointeger(L, -1);
    lua_pop(L, 1);

    std::string k(key);
    if (k == "Parent") {
        auto data = inst_get_data(inst_id);
        if (data.parent_id > 0) {
            auto pdata = inst_get_data(data.parent_id);
            if (pdata.id > 0) { push_instance(L, pdata.id, pdata.class_name); return 1; }
        }
        lua_pushnil(L);
        return 1;
    }

    int child = inst_find_child(inst_id, k);
    if (child > 0) {
        auto cd = inst_get_data(child);
        push_instance(L, cd.id, cd.class_name);
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

int Closures::l_instance_newindex(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);

    lua_getfield(L, 1, "__id");
    if (!lua_isnumber(L, -1)) { lua_pop(L, 1); lua_rawset(L, 1); return 0; }
    int inst_id = (int)lua_tointeger(L, -1);
    lua_pop(L, 1);

    auto data = inst_get_data(inst_id);
    if (data.id == 0) { lua_rawset(L, 1); return 0; }

    int overlay_id = data.overlay_id;
    auto& overlay = Overlay::instance();
    std::string prop(key);

    if (prop == "Parent") {
        if (lua_isnil(L, 3)) {
            inst_set_parent(inst_id, 0);
            overlay.set_gui_parent(overlay_id, 0);
        } else if (lua_istable(L, 3)) {
            lua_getfield(L, 3, "__id");
            if (lua_isnumber(L, -1)) {
                int pi = (int)lua_tointeger(L, -1);
                inst_set_parent(inst_id, pi);
                auto pd = inst_get_data(pi);
                if (pd.id > 0)
                    overlay.set_gui_parent(overlay_id, pd.overlay_id);
            }
            lua_pop(L, 1);
            lua_getfield(L, 3, "ClassName");
            if (lua_isstring(L, -1)) {
                std::string cn = lua_tostring(L, -1);
                if (cn == "CoreGui" || cn == "PlayerGui") {
                    overlay.update_gui_element(overlay_id, [](GuiElement& e) {
                        e.enabled = true; e.visible = true;
                    });
                    if (!overlay.is_visible()) overlay.show();
                }
            }
            lua_pop(L, 1);
        }
        return 0;
    }

    if (prop == "Name") {
        if (lua_isstring(L, 3)) {
            std::string nm = lua_tostring(L, 3);
            inst_set_name(inst_id, nm);
            lua_pushvalue(L, 3);
            lua_setfield(L, 1, "Name");
        }
        return 0;
    }

    overlay.update_gui_element(overlay_id, [&](GuiElement& e) {
        if      (prop == "Visible")    { e.visible = lua_toboolean(L, 3); }
        else if (prop == "Text")       { if (lua_isstring(L, 3)) e.text = lua_tostring(L, 3); }
        else if (prop == "TextColor3") { read_color3(L, 3, e.text_r, e.text_g, e.text_b); }
        else if (prop == "TextSize")   { if (lua_isnumber(L, 3)) e.text_size = (float)lua_tonumber(L, 3); }
        else if (prop == "TextTransparency")       { if (lua_isnumber(L, 3)) e.text_transparency = (float)lua_tonumber(L, 3); }
        else if (prop == "TextStrokeTransparency")  { if (lua_isnumber(L, 3)) e.text_stroke_transparency = (float)lua_tonumber(L, 3); }
        else if (prop == "TextStrokeColor3")        { read_color3(L, 3, e.text_stroke_r, e.text_stroke_g, e.text_stroke_b); }
        else if (prop == "TextXAlignment")  { if (lua_isnumber(L, 3)) e.text_x_alignment = (int)lua_tointeger(L, 3); }
        else if (prop == "TextYAlignment")  { if (lua_isnumber(L, 3)) e.text_y_alignment = (int)lua_tointeger(L, 3); }
        else if (prop == "TextWrapped")     { e.text_wrapped = lua_toboolean(L, 3); }
        else if (prop == "TextScaled")      { e.text_scaled = lua_toboolean(L, 3); }
        else if (prop == "RichText")        { e.rich_text = lua_toboolean(L, 3); }
        else if (prop == "BackgroundColor3")       { read_color3(L, 3, e.bg_r, e.bg_g, e.bg_b); }
        else if (prop == "BackgroundTransparency") { if (lua_isnumber(L, 3)) e.bg_transparency = (float)lua_tonumber(L, 3); }
        else if (prop == "BorderColor3")    { read_color3(L, 3, e.border_r, e.border_g, e.border_b); }
        else if (prop == "BorderSizePixel") { if (lua_isnumber(L, 3)) e.border_size = (int)lua_tointeger(L, 3); }
        else if (prop == "Size") {
            read_udim2(L, 3, e.size_x_scale, e.size_x_offset, e.size_y_scale, e.size_y_offset);
        }
        else if (prop == "Position") {
            read_udim2(L, 3, e.pos_x_scale, e.pos_x_offset, e.pos_y_scale, e.pos_y_offset);
        }
        else if (prop == "AnchorPoint") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "X"); if (lua_isnumber(L, -1)) e.anchor_x = (float)lua_tonumber(L, -1); lua_pop(L, 1);
                lua_getfield(L, 3, "Y"); if (lua_isnumber(L, -1)) e.anchor_y = (float)lua_tonumber(L, -1); lua_pop(L, 1);
            }
        }
        else if (prop == "Rotation")         { if (lua_isnumber(L, 3)) e.rotation = (float)lua_tonumber(L, 3); }
        else if (prop == "ClipsDescendants") { e.clips_descendants = lua_toboolean(L, 3); }
        else if (prop == "ZIndex")           { if (lua_isnumber(L, 3)) e.z_index = (int)lua_tointeger(L, 3); }
        else if (prop == "LayoutOrder")      { if (lua_isnumber(L, 3)) e.layout_order = (int)lua_tointeger(L, 3); }
        else if (prop == "Enabled")          { e.enabled = lua_toboolean(L, 3); }
        else if (prop == "DisplayOrder")     { if (lua_isnumber(L, 3)) e.display_order = (int)lua_tointeger(L, 3); }
        else if (prop == "IgnoreGuiInset")   { e.ignore_gui_inset = lua_toboolean(L, 3); }
        else if (prop == "ResetOnSpawn")     { }
        else if (prop == "CornerRadius") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Offset"); if (lua_isnumber(L, -1)) e.corner_radius = (float)lua_tonumber(L, -1); lua_pop(L, 1);
            } else if (lua_isnumber(L, 3)) e.corner_radius = (float)lua_tonumber(L, 3);
        }
        else if (prop == "Thickness")   { if (lua_isnumber(L, 3)) e.stroke_thickness = (float)lua_tonumber(L, 3); }
        else if (prop == "Color")       { read_color3(L, 3, e.stroke_r, e.stroke_g, e.stroke_b); }
        else if (prop == "Transparency"){ if (lua_isnumber(L, 3)) e.stroke_transparency = (float)lua_tonumber(L, 3); }
        else if (prop == "PaddingTop") {
            if (lua_istable(L, 3)) { lua_getfield(L, 3, "Offset"); if (lua_isnumber(L, -1)) e.pad_top = (float)lua_tonumber(L, -1); lua_pop(L, 1); }
        }
        else if (prop == "PaddingBottom") {
            if (lua_istable(L, 3)) { lua_getfield(L, 3, "Offset"); if (lua_isnumber(L, -1)) e.pad_bottom = (float)lua_tonumber(L, -1); lua_pop(L, 1); }
        }
        else if (prop == "PaddingLeft") {
            if (lua_istable(L, 3)) { lua_getfield(L, 3, "Offset"); if (lua_isnumber(L, -1)) e.pad_left = (float)lua_tonumber(L, -1); lua_pop(L, 1); }
        }
        else if (prop == "PaddingRight") {
            if (lua_istable(L, 3)) { lua_getfield(L, 3, "Offset"); if (lua_isnumber(L, -1)) e.pad_right = (float)lua_tonumber(L, -1); lua_pop(L, 1); }
        }
        else if (prop == "Image")             { if (lua_isstring(L, 3)) e.image = lua_tostring(L, 3); }
        else if (prop == "ImageColor3")       { read_color3(L, 3, e.image_r, e.image_g, e.image_b); }
        else if (prop == "ImageTransparency") { if (lua_isnumber(L, 3)) e.image_transparency = (float)lua_tonumber(L, 3); }
        else if (prop == "ScrollingEnabled")  { e.scrolling_enabled = lua_toboolean(L, 3); }
        else if (prop == "CanvasSize") {
            if (lua_istable(L, 3)) {
                float xs2, xo2, ys2, yo2;
                read_udim2(L, 3, xs2, xo2, ys2, yo2);
                e.canvas_size_y = ys2 * 1000 + yo2;
            }
        }
        else if (prop == "Padding") {
            if (lua_istable(L, 3)) { lua_getfield(L, 3, "Offset"); if (lua_isnumber(L, -1)) e.pad_top = (float)lua_tonumber(L, -1); lua_pop(L, 1); }
        }
    });

    lua_rawset(L, 1);
    return 0;
}

int Closures::l_instance_destroy(lua_State* L) {
    lua_getfield(L, 1, "__id");
    if (lua_isnumber(L, -1)) {
        int inst_id = (int)lua_tointeger(L, -1);
        auto data = inst_get_data(inst_id);
        if (data.id > 0) {
            Overlay::instance().remove_gui_element(data.overlay_id);
            auto children = inst_get_children(inst_id);
            for (int cid : children) {
                auto cd = inst_get_data(cid);
                if (cd.id > 0) Overlay::instance().remove_gui_element(cd.overlay_id);
                inst_unregister(cid);
            }
            inst_unregister(inst_id);
        }
    }
    lua_pop(L, 1);
    return 0;
}

int Closures::l_instance_clone(lua_State* L) {
    lua_getfield(L, 1, "__id");
    int src_id = lua_isnumber(L, -1) ? (int)lua_tointeger(L, -1) : 0;
    lua_pop(L, 1);

    auto src = inst_get_data(src_id);
    std::string cn = src.id > 0 ? src.class_name : "Frame";
    std::string nm = src.id > 0 ? src.name : cn;

    auto& overlay = Overlay::instance();
    int new_ov = overlay.create_gui_element(cn.c_str(), nm.c_str());
    int new_id = g_next_id++;
    inst_register(new_id, new_ov, cn, nm, 0);

    if (src.id > 0) {
        overlay.update_gui_element(new_ov, [&](GuiElement& dst) {
            overlay.read_gui_element(src.overlay_id, [&](const GuiElement& s) {
                dst = s;
            });
        });
    }

    push_instance(L, new_id, cn);
    return 1;
}

int Closures::l_instance_getchildren(lua_State* L) {
    lua_getfield(L, 1, "__id");
    int inst_id = lua_isnumber(L, -1) ? (int)lua_tointeger(L, -1) : 0;
    lua_pop(L, 1);

    auto children = inst_get_children(inst_id);
    lua_createtable(L, (int)children.size(), 0);
    int idx = 1;
    for (int cid : children) {
        auto cd = inst_get_data(cid);
        if (cd.id > 0) {
            push_instance(L, cd.id, cd.class_name);
            lua_rawseti(L, -2, idx++);
        }
    }
    return 1;
}

int Closures::l_instance_findfirstchild(lua_State* L) {
    const char* name = luaL_checkstring(L, 2);
    lua_getfield(L, 1, "__id");
    int inst_id = lua_isnumber(L, -1) ? (int)lua_tointeger(L, -1) : 0;
    lua_pop(L, 1);

    int child = inst_find_child(inst_id, name);
    if (child > 0) {
        auto cd = inst_get_data(child);
        push_instance(L, cd.id, cd.class_name);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int Closures::l_instance_waitforchild(lua_State* L) {
    const char* name = luaL_checkstring(L, 2);
    double timeout = luaL_optnumber(L, 3, 5.0);
    if (timeout < 0) timeout = 0;
    if (timeout > 30) timeout = 30;

    lua_getfield(L, 1, "__id");
    int inst_id = lua_isnumber(L, -1) ? (int)lua_tointeger(L, -1) : 0;
    lua_pop(L, 1);

    auto start = std::chrono::steady_clock::now();
    while (true) {
        chk(L);
        int child = inst_find_child(inst_id, name);
        if (child > 0) {
            auto cd = inst_get_data(child);
            push_instance(L, cd.id, cd.class_name);
            return 1;
        }
        double elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeout) break;
        pump_deferred();
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    spdlog::warn("[Script] WaitForChild('{}') timed out after {:.1f}s", name, timeout);
    lua_pushnil(L);
    return 1;
}

int Closures::l_instance_isA(lua_State* L) {
    const char* check = luaL_checkstring(L, 2);
    lua_getfield(L, 1, "ClassName");
    const char* cn = lua_tostring(L, -1);
    lua_pop(L, 1);
    bool match = false;
    if (cn && check) {
        match = (strcmp(cn, check) == 0);
        if (!match) {
            std::string c(check);
            if (c == "GuiObject" || c == "GuiBase2d") {
                std::string cls(cn);
                match = (cls == "Frame" || cls == "TextLabel" || cls == "TextButton" ||
                         cls == "TextBox" || cls == "ImageLabel" || cls == "ImageButton" ||
                         cls == "ScrollingFrame" || cls == "ViewportFrame" ||
                         cls == "CanvasGroup" || cls == "SurfaceGui" ||
                         cls == "BillboardGui" || cls == "ScreenGui");
            }
            if (!match && c == "GuiBase") {
                std::string cls(cn);
                match = (cls == "ScreenGui" || cls == "SurfaceGui" || cls == "BillboardGui");
            }
            if (!match && c == "Instance") match = true;
        }
    }
    lua_pushboolean(L, match);
    return 1;
}

int Closures::l_color3_new(lua_State* L) {
    push_color3(L, luaL_optnumber(L,1,0), luaL_optnumber(L,2,0), luaL_optnumber(L,3,0));
    return 1;
}

int Closures::l_color3_fromRGB(lua_State* L) {
    push_color3(L, luaL_optnumber(L,1,0)/255.0, luaL_optnumber(L,2,0)/255.0, luaL_optnumber(L,3,0)/255.0);
    return 1;
}

int Closures::l_color3_fromHSV(lua_State* L) {
    double h = luaL_optnumber(L,1,0), s = luaL_optnumber(L,2,0), v = luaL_optnumber(L,3,0);
    double r, g, b;
    int i = (int)(h * 6.0);
    double f = h * 6.0 - i, p = v*(1-s), q = v*(1-f*s), t = v*(1-(1-f)*s);
    switch (i % 6) {
        case 0: r=v; g=t; b=p; break;
        case 1: r=q; g=v; b=p; break;
        case 2: r=p; g=v; b=t; break;
        case 3: r=p; g=q; b=v; break;
        case 4: r=t; g=p; b=v; break;
        case 5: r=v; g=p; b=q; break;
        default: r=g=b=0; break;
    }
    push_color3(L, r, g, b);
    return 1;
}

int Closures::l_udim2_new(lua_State* L) {
    push_udim2(L, luaL_optnumber(L,1,0), luaL_optnumber(L,2,0), luaL_optnumber(L,3,0), luaL_optnumber(L,4,0));
    return 1;
}

int Closures::l_udim2_fromScale(lua_State* L) {
    push_udim2(L, luaL_optnumber(L,1,0), 0, luaL_optnumber(L,2,0), 0);
    return 1;
}

int Closures::l_udim2_fromOffset(lua_State* L) {
    push_udim2(L, 0, luaL_optnumber(L,1,0), 0, luaL_optnumber(L,2,0));
    return 1;
}

int Closures::l_udim_new(lua_State* L) {
    lua_newtable(L);
    lua_pushnumber(L, luaL_optnumber(L,1,0)); lua_setfield(L,-2,"Scale");
    lua_pushnumber(L, luaL_optnumber(L,2,0)); lua_setfield(L,-2,"Offset");
    lua_pushstring(L, "UDim"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_vector2_new(lua_State* L) {
    push_vector2(L, luaL_optnumber(L,1,0), luaL_optnumber(L,2,0));
    return 1;
}

int Closures::l_vector3_new(lua_State* L) {
    double x = luaL_optnumber(L,1,0), y = luaL_optnumber(L,2,0), z = luaL_optnumber(L,3,0);
    lua_newtable(L);
    lua_pushnumber(L,x); lua_setfield(L,-2,"X");
    lua_pushnumber(L,y); lua_setfield(L,-2,"Y");
    lua_pushnumber(L,z); lua_setfield(L,-2,"Z");
    lua_pushnumber(L, std::sqrt(x*x+y*y+z*z)); lua_setfield(L,-2,"Magnitude");
    lua_pushstring(L,"Vector3"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_cframe_new(lua_State* L) {
    lua_newtable(L);
    lua_pushnumber(L, luaL_optnumber(L,1,0)); lua_setfield(L,-2,"X");
    lua_pushnumber(L, luaL_optnumber(L,2,0)); lua_setfield(L,-2,"Y");
    lua_pushnumber(L, luaL_optnumber(L,3,0)); lua_setfield(L,-2,"Z");
    lua_pushstring(L,"CFrame"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_tweeninfo_new(lua_State* L) {
    lua_newtable(L);
    lua_pushnumber(L, luaL_optnumber(L,1,1));       lua_setfield(L,-2,"Time");
    lua_pushinteger(L,(int)luaL_optinteger(L,2,0));  lua_setfield(L,-2,"EasingStyle");
    lua_pushinteger(L,(int)luaL_optinteger(L,3,0));  lua_setfield(L,-2,"EasingDirection");
    lua_pushinteger(L,(int)luaL_optinteger(L,4,0));  lua_setfield(L,-2,"RepeatCount");
    lua_pushboolean(L, lua_toboolean(L,5));           lua_setfield(L,-2,"Reverses");
    lua_pushnumber(L, luaL_optnumber(L,6,0));         lua_setfield(L,-2,"DelayTime");
    lua_pushstring(L,"TweenInfo"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_numberrange_new(lua_State* L) {
    double mn = luaL_optnumber(L,1,0);
    lua_newtable(L);
    lua_pushnumber(L, mn);                     lua_setfield(L,-2,"Min");
    lua_pushnumber(L, luaL_optnumber(L,2,mn)); lua_setfield(L,-2,"Max");
    lua_pushstring(L,"NumberRange"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_colorsequence_new(lua_State* L) {
    lua_newtable(L);
    lua_pushstring(L,"ColorSequence"); lua_setfield(L,-2,"__type");
    if (lua_istable(L, 1)) {
        lua_pushvalue(L, 1);
        lua_setfield(L, -2, "Keypoints");
    }
    return 1;
}

int Closures::l_numbersequence_new(lua_State* L) {
    lua_newtable(L);
    lua_pushstring(L,"NumberSequence"); lua_setfield(L,-2,"__type");
    if (lua_istable(L, 1)) {
        lua_pushvalue(L, 1);
        lua_setfield(L, -2, "Keypoints");
    }
    return 1;
}

int Closures::l_drawing_new(lua_State* L) {
    const char* ts = luaL_checkstring(L, 1);
    DrawingObject::Type type;

    if      (strcmp(ts,"Line")==0)     type = DrawingObject::Type::Line;
    else if (strcmp(ts,"Text")==0)     type = DrawingObject::Type::Text;
    else if (strcmp(ts,"Circle")==0)   type = DrawingObject::Type::Circle;
    else if (strcmp(ts,"Square")==0)   type = DrawingObject::Type::Square;
    else if (strcmp(ts,"Triangle")==0) type = DrawingObject::Type::Triangle;
    else if (strcmp(ts,"Quad")==0)     type = DrawingObject::Type::Quad;
    else if (strcmp(ts,"Image")==0)    type = DrawingObject::Type::Image;
    else { luaL_error(L,"Invalid Drawing type: %s",ts); return 0; }

    auto& overlay = Overlay::instance();
    int id = overlay.create_object(type);
    if (!overlay.is_visible()) overlay.show();

    lua_newtable(L);
    lua_pushinteger(L, id);
    lua_setfield(L, -2, "__drawing_id");
    lua_pushcfunction(L, l_drawing_remove, "Remove");
    lua_setfield(L, -2, "Remove");

    lua_newtable(L);
    lua_pushcfunction(L, l_drawing_index,   "__index");    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_drawing_newindex, "__newindex"); lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);
    return 1;
}

int Closures::l_drawing_index(lua_State* L) {
    lua_pushvalue(L, 2);
    lua_rawget(L, 1);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 1);
    lua_pushnil(L);
    return 1;
}

int Closures::l_drawing_newindex(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);
    lua_getfield(L, 1, "__drawing_id");
    if (!lua_isnumber(L, -1)) { lua_pop(L, 1); return 0; }
    int id = (int)lua_tointeger(L, -1);
    lua_pop(L, 1);

    auto& overlay = Overlay::instance();
    std::string prop(key);

    overlay.update_object(id, [&](DrawingObject& obj) {
        if      (prop == "Visible")      { obj.visible = lua_toboolean(L,3); }
        else if (prop == "Color") {
            float r, g, b; read_color3(L, 3, r, g, b);
            obj.color_r = r; obj.color_g = g; obj.color_b = b;
        }
        else if (prop == "Transparency") { if (lua_isnumber(L,3)) obj.transparency=(float)lua_tonumber(L,3); }
        else if (prop == "Thickness")    { if (lua_isnumber(L,3)) obj.thickness=(float)lua_tonumber(L,3); }
        else if (prop == "From") {
            if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); if (lua_isnumber(L,-1)) obj.from_x=(float)lua_tonumber(L,-1); lua_pop(L,1);
                lua_getfield(L,3,"Y"); if (lua_isnumber(L,-1)) obj.from_y=(float)lua_tonumber(L,-1); lua_pop(L,1);
            }
        }
        else if (prop == "To") {
            if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); if (lua_isnumber(L,-1)) obj.to_x=(float)lua_tonumber(L,-1); lua_pop(L,1);
                lua_getfield(L,3,"Y"); if (lua_isnumber(L,-1)) obj.to_y=(float)lua_tonumber(L,-1); lua_pop(L,1);
            }
        }
        else if (prop == "Position") {
            if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); if (lua_isnumber(L,-1)) obj.pos_x=(float)lua_tonumber(L,-1); lua_pop(L,1);
                lua_getfield(L,3,"Y"); if (lua_isnumber(L,-1)) obj.pos_y=(float)lua_tonumber(L,-1); lua_pop(L,1);
            }
        }
        else if (prop == "Size") {
            if (lua_isnumber(L,3)) {
                obj.size_x = obj.size_y = (float)lua_tonumber(L,3);
            } else if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); if (lua_isnumber(L,-1)) obj.size_x=(float)lua_tonumber(L,-1); lua_pop(L,1);
                lua_getfield(L,3,"Y"); if (lua_isnumber(L,-1)) obj.size_y=(float)lua_tonumber(L,-1); lua_pop(L,1);
            }
        }
        else if (prop == "Text")     { if (lua_isstring(L,3)) obj.text = lua_tostring(L,3); }
        else if (prop == "TextSize" || prop == "FontSize") {
            if (lua_isnumber(L,3)) obj.text_size=(float)lua_tonumber(L,3);
        }
        else if (prop == "Center")       { obj.center = lua_toboolean(L,3); }
        else if (prop == "Outline")      { obj.outline = lua_toboolean(L,3); }
        else if (prop == "OutlineColor") {
            float r, g, b; read_color3(L, 3, r, g, b);
            obj.outline_r = r; obj.outline_g = g; obj.outline_b = b;
        }
        else if (prop == "Font")     { if (lua_isnumber(L,3)) obj.font=(int)lua_tointeger(L,3); }
        else if (prop == "Radius")   { if (lua_isnumber(L,3)) obj.radius=(float)lua_tonumber(L,3); }
        else if (prop == "Filled")   { obj.filled = lua_toboolean(L,3); }
        else if (prop == "NumSides") { if (lua_isnumber(L,3)) obj.num_sides=(int)lua_tointeger(L,3); }
        else if (prop == "Rounding") { if (lua_isnumber(L,3)) obj.rounding=(float)lua_tonumber(L,3); }
        else if (prop == "ZIndex")   { if (lua_isnumber(L,3)) obj.z_index=(int)lua_tointeger(L,3); }
        else if (prop == "PointA") {
            if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); obj.pa_x=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
                lua_getfield(L,3,"Y"); obj.pa_y=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
            }
        }
        else if (prop == "PointB") {
            if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); obj.pb_x=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
                lua_getfield(L,3,"Y"); obj.pb_y=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
            }
        }
        else if (prop == "PointC") {
            if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); obj.pc_x=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
                lua_getfield(L,3,"Y"); obj.pc_y=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
            }
        }
        else if (prop == "PointD") {
            if (lua_istable(L,3)) {
                lua_getfield(L,3,"X"); obj.qd_x=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
                lua_getfield(L,3,"Y"); obj.qd_y=(float)luaL_optnumber(L,-1,0); lua_pop(L,1);
            }
        }
    });

    lua_rawset(L, 1);
    return 0;
}

int Closures::l_drawing_remove(lua_State* L) {
    lua_getfield(L, 1, "__drawing_id");
    if (lua_isnumber(L, -1))
        Overlay::instance().remove_object((int)lua_tointeger(L, -1));
    lua_pop(L, 1);
    return 0;
}

int Closures::l_cleardrawcache(lua_State* L) {
    Overlay::instance().clear_objects();
    return 0;
}

int Closures::l_game_getservice(lua_State* L) {
    const char* sn_str = luaL_checkstring(L, 2);
    std::string sn(sn_str);

    lua_newtable(L);
    lua_pushstring(L, sn_str); lua_setfield(L, -2, "ClassName");
    lua_pushstring(L, sn_str); lua_setfield(L, -2, "Name");

    if (sn == "Players") {
        lua_newtable(L);
        lua_pushstring(L, "Player");      lua_setfield(L, -2, "ClassName");
        lua_pushstring(L, "LocalPlayer"); lua_setfield(L, -2, "Name");
        lua_pushinteger(L, 1);            lua_setfield(L, -2, "UserId");
        lua_pushstring(L, "Player1");     lua_setfield(L, -2, "DisplayName");

        int pg_inst = g_next_id++;
        auto& ov = Overlay::instance();
        int pg_ov = ov.create_gui_element("PlayerGui", "PlayerGui");
        inst_register(pg_inst, pg_ov, "PlayerGui", "PlayerGui");
        push_instance(L, pg_inst, "PlayerGui");
        lua_setfield(L, -2, "PlayerGui");

        lua_newtable(L);
        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_getfield(Ls, 1, "ClassName");
            const char* cn = lua_tostring(Ls, -1);
            lua_pop(Ls, 1);
            const char* check = luaL_checkstring(Ls, 2);
            lua_pushboolean(Ls, cn && check && strcmp(cn, check) == 0);
            return 1;
        }, "IsA");
        lua_setfield(L, -2, "IsA");
        lua_setmetatable(L, -2);

        lua_setfield(L, -2, "LocalPlayer");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_newtable(Ls);
            return 1;
        }, "GetPlayers");
        lua_setfield(L, -2, "GetPlayers");
    }
    else if (sn == "CoreGui") {
        int cg_inst = g_next_id++;
        auto& ov = Overlay::instance();
        int cg_ov = ov.create_gui_element("CoreGui", "CoreGui");
        inst_register(cg_inst, cg_ov, "CoreGui", "CoreGui");
        lua_pushinteger(L, cg_inst); lua_setfield(L, -2, "__id");
    }
    else if (sn == "UserInputService") {
        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushboolean(Ls, false); return 1;
        }, "IsKeyDown");
        lua_setfield(L, -2, "IsKeyDown");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushboolean(Ls, false); return 1;
        }, "IsMouseButtonPressed");
        lua_setfield(L, -2, "IsMouseButtonPressed");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            push_vector2(Ls, 0, 0); return 1;
        }, "GetMouseLocation");
        lua_setfield(L, -2, "GetMouseLocation");

        lua_newtable(L);
        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_newtable(Ls);
            lua_pushcfunction(Ls, [](lua_State*) -> int { return 0; }, "Disconnect");
            lua_setfield(Ls, -2, "Disconnect");
            return 1;
        }, "Connect");
        lua_setfield(L, -2, "Connect");
        lua_setfield(L, -2, "InputBegan");

        lua_newtable(L);
        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_newtable(Ls);
            lua_pushcfunction(Ls, [](lua_State*) -> int { return 0; }, "Disconnect");
            lua_setfield(Ls, -2, "Disconnect");
            return 1;
        }, "Connect");
        lua_setfield(L, -2, "Connect");
        lua_setfield(L, -2, "InputEnded");
    }
    else if (sn == "TweenService") {
        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_newtable(Ls);
            lua_pushcfunction(Ls, [](lua_State*) -> int { return 0; }, "Play");
            lua_setfield(Ls, -2, "Play");
            lua_pushcfunction(Ls, [](lua_State*) -> int { return 0; }, "Cancel");
            lua_setfield(Ls, -2, "Cancel");
            lua_pushcfunction(Ls, [](lua_State*) -> int { return 0; }, "Pause");
            lua_setfield(Ls, -2, "Pause");

            lua_newtable(Ls);
            lua_pushcfunction(Ls, [](lua_State* Ls2) -> int {
                lua_newtable(Ls2);
                lua_pushcfunction(Ls2, [](lua_State*) -> int { return 0; }, "Disconnect");
                lua_setfield(Ls2, -2, "Disconnect");
                return 1;
            }, "Connect");
            lua_setfield(Ls, -2, "Connect");
            lua_setfield(Ls, -2, "Completed");

            return 1;
        }, "Create");
        lua_setfield(L, -2, "Create");
    }
    else if (sn == "RunService") {
        auto make_signal = [](lua_State* Ls, const char* name) {
            lua_newtable(Ls);
            lua_pushcfunction(Ls, [](lua_State* Ls2) -> int {
                lua_newtable(Ls2);
                lua_pushcfunction(Ls2, [](lua_State*) -> int { return 0; }, "Disconnect");
                lua_setfield(Ls2, -2, "Disconnect");
                return 1;
            }, "Connect");
            lua_setfield(Ls, -2, "Connect");
            lua_pushcfunction(Ls, [](lua_State* Ls2) -> int {
                Closures::l_wait(Ls2);
                return 0;
            }, "Wait");
            lua_setfield(Ls, -2, "Wait");
            lua_setfield(Ls, -2, name);
        };
        make_signal(L, "RenderStepped");
        make_signal(L, "Heartbeat");
        make_signal(L, "Stepped");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushboolean(Ls, false); return 1;
        }, "IsClient");
        lua_setfield(L, -2, "IsClient");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushboolean(Ls, false); return 1;
        }, "IsServer");
        lua_setfield(L, -2, "IsServer");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushboolean(Ls, true); return 1;
        }, "IsStudio");
        lua_setfield(L, -2, "IsStudio");
    }
    else if (sn == "HttpService") {
        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            size_t len;
            const char* js = luaL_checklstring(Ls, 2, &len);
            lua_pushlstring(Ls, js, len);
            return 1;
        }, "JSONDecode");
        lua_setfield(L, -2, "JSONDecode");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushstring(Ls, "{}");
            return 1;
        }, "JSONEncode");
        lua_setfield(L, -2, "JSONEncode");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            std::string uuid;
            uuid.resize(36);
            static const char hex[] = "0123456789abcdef";
            for (int i = 0; i < 36; i++) {
                if (i == 8 || i == 13 || i == 18 || i == 23) uuid[i] = '-';
                else uuid[i] = hex[rand() % 16];
            }
            lua_pushstring(Ls, uuid.c_str());
            return 1;
        }, "GenerateGUID");
        lua_setfield(L, -2, "GenerateGUID");
    }
    else if (sn == "StarterGui") {
        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            return 0;
        }, "SetCoreGuiEnabled");
        lua_setfield(L, -2, "SetCoreGuiEnabled");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushboolean(Ls, true);
            return 1;
        }, "GetCoreGuiEnabled");
        lua_setfield(L, -2, "GetCoreGuiEnabled");
    }
    else if (sn == "Workspace") {
        lua_newtable(L);
        lua_pushstring(L, "Camera"); lua_setfield(L, -2, "ClassName");
        lua_pushstring(L, "Camera"); lua_setfield(L, -2, "Name");

        lua_newtable(L);
        lua_pushnumber(L, 0); lua_setfield(L, -2, "X");
        lua_pushnumber(L, 0); lua_setfield(L, -2, "Y");
        lua_pushnumber(L, 0); lua_setfield(L, -2, "Z");
        lua_pushstring(L, "CFrame"); lua_setfield(L, -2, "__type");
        lua_setfield(L, -2, "CFrame");

        lua_pushnumber(L, 70);
        lua_setfield(L, -2, "FieldOfView");

        push_vector2(L, 1920, 1080);
        lua_setfield(L, -2, "ViewportSize");

        lua_setfield(L, -2, "CurrentCamera");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_newtable(Ls);
            return 1;
        }, "GetChildren");
        lua_setfield(L, -2, "GetChildren");

        lua_pushcfunction(L, [](lua_State* Ls) -> int {
            lua_pushnil(Ls);
            return 1;
        }, "FindFirstChild");
        lua_setfield(L, -2, "FindFirstChild");
    }

    lua_newtable(L);
    lua_pushcfunction(L, [](lua_State* Ls) -> int {
        const char* k = luaL_checkstring(Ls, 2);
        lua_pushvalue(Ls, 2);
        lua_rawget(Ls, 1);
        if (!lua_isnil(Ls, -1)) return 1;
        lua_pop(Ls, 1);
        lua_pushnil(Ls);
        return 1;
    }, "__index");
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);
    return 1;
}

int Closures::l_game_httpget(lua_State* L) {
    const char* url = luaL_checkstring(L, 2);
    auto& http = Http::instance();
    auto resp = http.get(url);
    lua_pushlstring(L, resp.body.data(), resp.body.size());
    return 1;
}

int Closures::l_game_index(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);

    lua_pushvalue(L, 2);
    lua_rawget(L, 1);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 1);

    std::string k(key);
    if (k == "Players" || k == "Workspace" || k == "Lighting" ||
        k == "ReplicatedStorage" || k == "StarterGui" || k == "CoreGui" ||
        k == "ReplicatedFirst" || k == "ServerStorage" || k == "ServerScriptService" ||
        k == "StarterPack" || k == "StarterPlayer" || k == "SoundService" ||
        k == "Chat" || k == "LocalizationService" || k == "TestService") {
        lua_getfield(L, 1, "GetService");
        lua_pushvalue(L, 1);
        lua_pushstring(L, key);
        lua_call(L, 2, 1);
        return 1;
    }

    if (k == "PlaceId") { lua_pushinteger(L, 0); return 1; }
    if (k == "GameId")  { lua_pushinteger(L, 0); return 1; }
    if (k == "JobId")   { lua_pushstring(L, ""); return 1; }

    lua_pushnil(L);
    return 1;
}

int Closures::l_getgenv(lua_State* L) {
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

int Closures::l_getrenv(lua_State* L) {
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

int Closures::l_getrawmetatable(lua_State* L) {
    if (!lua_getmetatable(L, 1)) lua_pushnil(L);
    return 1;
}

int Closures::l_setrawmetatable(lua_State* L) {
    lua_setmetatable(L, 1);
    lua_pushvalue(L, 1);
    return 1;
}

int Closures::l_identifyexecutor(lua_State* L) {
    lua_pushstring(L, "OSS");
    lua_pushstring(L, "2.0.0");
    return 2;
}

int Closures::l_setclipboard(lua_State* L) {
    const char* text = luaL_checkstring(L, 1);
    std::string escaped;
    for (size_t i = 0; text[i]; i++) {
        if (text[i] == '\'') escaped += "'\\''";
        else escaped += text[i];
    }
    std::string cmd = "echo -n '" + escaped + "' | ";
    if (std::system("which wl-copy > /dev/null 2>&1") == 0)
        cmd += "wl-copy";
    else
        cmd += "xclip -selection clipboard";
    std::system(cmd.c_str());
    return 0;
}

int Closures::l_getnamecallmethod(lua_State* L) {
    const char* name = lua_namecallatom(L, nullptr);
    if (name) lua_pushstring(L, name);
    else      lua_pushnil(L);
    return 1;
}

int Closures::l_fireclickdetector(lua_State* L) {
    spdlog::warn("[Script] fireclickdetector: requires injection into target process");
    return 0;
}

int Closures::l_firetouchinterest(lua_State* L) {
    spdlog::warn("[Script] firetouchinterest: requires injection into target process");
    return 0;
}

int Closures::l_fireproximityprompt(lua_State* L) {
    spdlog::warn("[Script] fireproximityprompt: requires injection into target process");
    return 0;
}

int Closures::l_gethui(lua_State* L) {
    static int hui_inst = 0;
    static int hui_ov   = 0;
    if (hui_inst == 0) {
        auto& overlay = Overlay::instance();
        hui_ov   = overlay.create_gui_element("Folder", "HiddenUI");
        hui_inst = g_next_id++;
        inst_register(hui_inst, hui_ov, "Folder", "HiddenUI");
    }
    push_instance(L, hui_inst, "Folder");
    lua_pushstring(L, "CoreGui"); lua_setfield(L, -2, "ClassName");
    return 1;
}

int Closures::l_http_request(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    chk(L);

    lua_getfield(L, 1, "Url");
    if (lua_isnil(L, -1)) { lua_pop(L,1); lua_getfield(L,1,"url"); }
    const char* url = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, 1, "Method");
    if (lua_isnil(L, -1)) { lua_pop(L,1); lua_getfield(L,1,"method"); }
    const char* method = luaL_optstring(L, -1, "GET");
    lua_pop(L, 1);

    lua_getfield(L, 1, "Body");
    if (lua_isnil(L, -1)) { lua_pop(L,1); lua_getfield(L,1,"body"); }
    const char* body = lua_isstring(L, -1) ? lua_tostring(L, -1) : nullptr;
    lua_pop(L, 1);

    std::map<std::string,std::string> headers;
    lua_getfield(L, 1, "Headers");
    if (lua_isnil(L, -1)) { lua_pop(L,1); lua_getfield(L,1,"headers"); }
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            if (lua_isstring(L,-2) && lua_isstring(L,-1))
                headers[lua_tostring(L,-2)] = lua_tostring(L,-1);
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    auto& http = Http::instance();
    std::string response_body;
    int status_code = 0;
    bool success = false;
    std::string ms(method);

    if (ms == "GET") {
        auto resp = http.get(url, headers);
        response_body = resp.body;
        status_code = resp.status_code > 0 ? resp.status_code : (response_body.empty() ? 0 : 200);
        success = status_code >= 200 && status_code < 300;
    } else if (ms == "POST") {
        std::string bs = body ? body : "";
        std::string ct = "application/json";
        auto it = headers.find("Content-Type");
        if (it != headers.end()) ct = it->second;
        std::map<std::string,std::string> req_headers = headers;
        req_headers["Content-Type"] = ct;
        auto resp = http.post(url, bs, req_headers);
        response_body = resp.body;
        status_code = resp.status_code > 0 ? resp.status_code : (response_body.empty() ? 0 : 200);
        success = status_code >= 200 && status_code < 300;
    } else {
        auto resp = http.get(url, headers);
        response_body = resp.body;
        status_code = resp.status_code > 0 ? resp.status_code : 200;
        success = true;
    }

    lua_newtable(L);
    lua_pushinteger(L, status_code);                            lua_setfield(L,-2,"StatusCode");
    lua_pushstring(L, success ? "OK" : "Error");                lua_setfield(L,-2,"StatusMessage");
    lua_pushboolean(L, success);                                lua_setfield(L,-2,"Success");
    lua_pushlstring(L, response_body.data(), response_body.size()); lua_setfield(L,-2,"Body");
    lua_newtable(L); lua_setfield(L,-2,"Headers");
    return 1;
}

int Closures::wrap_closure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);
    lua_pushcclosure(L, closure_handler, "wrapclosure_proxy", 1);
    return 1;
}

int Closures::closure_handler(lua_State* L) {
    int nargs = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    for (int i = 1; i <= nargs; i++) lua_pushvalue(L, i);
    lua_call(L, nargs, LUA_MULTRET);
    return lua_gettop(L) - nargs;
}

int Closures::newcclosure_handler(lua_State* L) {
    int nargs = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    if (lua_isnil(L, -1)) { lua_pop(L, 1); return 0; }
    for (int i = 1; i <= nargs; i++) lua_pushvalue(L, i);
    int status = lua_pcall(L, nargs, LUA_MULTRET, 0);
    if (status != 0) { lua_error(L); return 0; }
    return lua_gettop(L) - nargs;
}

int Closures::newlclosure_handler(lua_State* L) {
    int nargs = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    for (int i = 1; i <= nargs; i++) lua_pushvalue(L, i);
    lua_call(L, nargs, LUA_MULTRET);
    return lua_gettop(L) - nargs;
}

int Closures::loadstring_enhanced(lua_State* L) {
    return l_loadstring(L);
}

int Closures::l_newcclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);
    lua_pushcclosure(L, newcclosure_handler, "newcclosure_proxy", 1);

    get_hook_table(L);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    return 1;
}

int Closures::l_hookfunction(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    lua_pushvalue(L, 1);
    int orig_ref = lua_ref(L, -1);
    lua_pop(L, 1);

    get_hook_table(L);
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 2);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    lua_getref(L, orig_ref);
    lua_unref(L, orig_ref);
    return 1;
}

int Closures::l_hookmetamethod(lua_State* L) {
    luaL_checkany(L, 1);
    const char* method = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    if (!lua_getmetatable(L, 1)) {
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setmetatable(L, 1);
    }

    lua_getfield(L, -1, method);
    int old_ref = LUA_NOREF;
    if (!lua_isnil(L, -1)) old_ref = lua_ref(L, -1);
    lua_pop(L, 1);

    lua_pushvalue(L, 3);
    lua_setfield(L, -2, method);
    lua_pop(L, 1);

    if (old_ref != LUA_NOREF) {
        lua_getref(L, old_ref);
        lua_unref(L, old_ref);
    } else {
        lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "hookmetamethod_old");
    }
    return 1;
}

int Closures::iscclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushboolean(L, lua_iscfunction(L, 1));
    return 1;
}

int Closures::islclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushboolean(L, !lua_iscfunction(L, 1));
    return 1;
}

int Closures::l_isexecutorclosure(lua_State* L) {
    if (!lua_isfunction(L, 1)) { lua_pushboolean(L, 0); return 1; }

    get_hook_table(L);
    lua_pushvalue(L, 1);
    lua_rawget(L, -2);
    if (!lua_isnil(L, -1)) { lua_pop(L, 2); lua_pushboolean(L, 1); return 1; }
    lua_pop(L, 2);

    if (lua_iscfunction(L, 1)) { lua_pushboolean(L, 1); return 1; }

    lua_Debug ar;
    memset(&ar, 0, sizeof(ar));
    lua_pushvalue(L, 1);
    if (lua_getinfo(L, 0, "s", &ar) && ar.source) {
        std::string src(ar.source);
        if (src.find("=env") != std::string::npos ||
            src.find("=sandbox") != std::string::npos ||
            src.find("=input") != std::string::npos ||
            src.find("=cloned") != std::string::npos ||
            src.find("=newlclosure") != std::string::npos ||
            src.find("=hooked") != std::string::npos ||
            src.find("=loadstring") != std::string::npos ||
            src.find("=user") != std::string::npos) {
            lua_pushboolean(L, 1); return 1;
        }
    }

    lua_pushboolean(L, 0);
    return 1;
}

int Closures::l_checkcaller(lua_State* L) {
    lua_Debug ar;
    int level = 2;
    while (lua_getinfo(L, level, "s", &ar)) {
        if (ar.source) {
            std::string src(ar.source);
            if (src == "=input" ||
                src.find("=env") != std::string::npos ||
                src.find("=sandbox") != std::string::npos ||
                src.find("=user") != std::string::npos ||
                src.find("=loadstring") != std::string::npos) {
                lua_pushboolean(L, 1); return 1;
            }
            if (src[0] == '@') { lua_pushboolean(L, 0); return 1; }
        }
        ++level;
    }
    lua_getfield(L, LUA_REGISTRYINDEX, "__oss_is_executor");
    bool is_exec = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_pushboolean(L, is_exec ? 1 : 0);
    return 1;
}

int Closures::l_getinfo(lua_State* L) {
    lua_Debug ar;
    memset(&ar, 0, sizeof(ar));

    if (lua_isnumber(L, 1)) {
        int level = (int)lua_tointeger(L, 1);
        if (!lua_getinfo(L, level, "slna", &ar)) { lua_pushnil(L); return 1; }
    } else if (lua_isfunction(L, 1)) {
        lua_pushvalue(L, 1);
        lua_getinfo(L, 0, "slna", &ar);
    } else {
        lua_pushnil(L); return 1;
    }

    lua_newtable(L);
    if (ar.source)   { lua_pushstring(L, ar.source); lua_setfield(L, -2, "source"); lua_pushstring(L, ar.source); lua_setfield(L, -2, "short_src"); }
    if (ar.name)     { lua_pushstring(L, ar.name);   lua_setfield(L, -2, "name"); }
    if (ar.what)     { lua_pushstring(L, ar.what);    lua_setfield(L, -2, "what"); lua_pushboolean(L, strcmp(ar.what, "C") == 0); lua_setfield(L, -2, "is_c"); }
    lua_pushinteger(L, ar.currentline); lua_setfield(L, -2, "currentline");
    lua_pushinteger(L, ar.linedefined); lua_setfield(L, -2, "linedefined");
    lua_pushinteger(L, ar.nupvals);     lua_setfield(L, -2, "nups");
    lua_pushinteger(L, ar.nparams);     lua_setfield(L, -2, "numparams");
    lua_pushboolean(L, ar.isvararg);    lua_setfield(L, -2, "is_vararg");
    return 1;
}

int Closures::checkclosure(lua_State* L) {
    return l_isexecutorclosure(L);
}

int Closures::get_script_closure(lua_State* L) {
    if (lua_isstring(L, 1)) {
        const char* name = lua_tostring(L, 1);
        lua_getglobal(L, name);
        if (lua_isfunction(L, -1)) return 1;
        lua_pop(L, 1);
    }
    lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "script_closure_fallback");
    return 1;
}

int Closures::getscriptclosure(lua_State* L) {
    return get_script_closure(L);
}

int Closures::compare_closures(lua_State* L) {
    lua_pushboolean(L, lua_rawequal(L, 1, 2));
    return 1;
}

int Closures::clone_function(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    if (lua_iscfunction(L, 1)) {
        lua_pushvalue(L, 1);
        lua_pushcclosure(L, [](lua_State* Ls) -> int {
            int n = lua_gettop(Ls);
            lua_pushvalue(Ls, lua_upvalueindex(1));
            for (int i = 1; i <= n; i++) lua_pushvalue(Ls, i);
            lua_call(Ls, n, LUA_MULTRET);
            return lua_gettop(Ls) - n;
        }, "cloned_c", 1);

        get_hook_table(L);
        lua_pushvalue(L, -2);
        lua_pushboolean(L, 1);
        lua_rawset(L, -3);
        lua_pop(L, 1);
        return 1;
    }

    static const char* src =
        "local f = ...\n"
        "return function(...)\n"
        "    return f(...)\n"
        "end\n";
    if (!compile_and_load(L, src, "=cloned")) {
        luaL_error(L, "clonefunction: compile failed");
        return 0;
    }
    lua_pushvalue(L, 1);
    lua_call(L, 1, 1);

    get_hook_table(L);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    return 1;
}

int Closures::get_calling_script(lua_State* L) {
    lua_Debug ar;
    int level = 1;
    while (lua_getinfo(L, level, "s", &ar)) {
        if (ar.source && ar.source[0] == '@') {
            lua_pushstring(L, ar.source + 1);
            return 1;
        }
        ++level;
    }
    lua_pushnil(L);
    return 1;
}

int Closures::newlclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    static const char* src =
        "local f = ...\n"
        "return function(...)\n"
        "    return f(...)\n"
        "end\n";
    if (!compile_and_load(L, src, "=newlclosure")) {
        luaL_error(L, "newlclosure: compile failed");
        return 0;
    }
    lua_pushvalue(L, 1);
    lua_call(L, 1, 1);

    get_hook_table(L);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    return 1;
}

static bool path_safe(const std::string& path) {
    try {
        auto resolved  = std::filesystem::weakly_canonical(path);
        auto workspace = std::filesystem::weakly_canonical(WS_DIR);
        return resolved.string().find(workspace.string()) == 0;
    } catch (...) { return false; }
}

int Closures::l_readfile(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    std::string path = get_ws(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal blocked"); return 0; }

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) { luaL_error(L, "Cannot read file: %s", fn); return 0; }

    std::ostringstream ss; ss << f.rdbuf();
    std::string content = ss.str();
    f.close();
    lua_pushlstring(L, content.data(), content.size());
    return 1;
}

int Closures::l_writefile(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    std::string path = get_ws(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal blocked"); return 0; }

    std::filesystem::path fp(path);
    if (fp.has_parent_path()) std::filesystem::create_directories(fp.parent_path());

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) { luaL_error(L, "Cannot write file: %s", fn); return 0; }
    f.write(data, (std::streamsize)len);
    f.close();
    spdlog::debug("[Script] writefile: {} ({} bytes)", fn, len);
    return 0;
}

int Closures::l_isfile(lua_State* L) {
    lua_pushboolean(L, std::filesystem::is_regular_file(get_ws(luaL_checkstring(L, 1))));
    return 1;
}

int Closures::l_isfolder(lua_State* L) {
    lua_pushboolean(L, std::filesystem::is_directory(get_ws(luaL_checkstring(L, 1))));
    return 1;
}

int Closures::l_makefolder(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    std::string path = get_ws(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal blocked"); return 0; }
    std::filesystem::create_directories(path);
    return 0;
}

int Closures::l_listfiles(lua_State* L) {
    const char* fn = luaL_optstring(L, 1, "");
    std::string path = get_ws(fn);
    lua_newtable(L);
    if (!std::filesystem::is_directory(path)) return 1;

    int idx = 1;
    try {
        for (auto& entry : std::filesystem::directory_iterator(path)) {
            std::string rel = entry.path().filename().string();
            if (fn[0] != '\0') rel = std::string(fn) + "/" + rel;
            lua_pushstring(L, rel.c_str());
            lua_rawseti(L, -2, idx++);
        }
    } catch (const std::exception& e) {
        spdlog::warn("[Script] listfiles: {}", e.what());
    }
    return 1;
}

int Closures::l_delfile(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    std::string path = get_ws(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal blocked"); return 0; }
    try { std::filesystem::remove_all(path); }
    catch (const std::exception& e) { luaL_error(L, "Cannot delete: %s", e.what()); }
    return 0;
}

int Closures::l_appendfile(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    std::string path = get_ws(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal blocked"); return 0; }

    std::ofstream f(path, std::ios::binary | std::ios::app);
    if (!f.is_open()) { luaL_error(L, "Cannot append file: %s", fn); return 0; }
    f.write(data, (std::streamsize)len);
    f.close();
    return 0;
}

int Closures::l_setfpscap(lua_State* L) {
    int fps = (int)luaL_optinteger(L, 1, 60);
    if (fps < 1) fps = 1;
    if (fps > 999) fps = 999;
    spdlog::info("[Script] setfpscap({})", fps);
    return 0;
}

int Closures::l_task_wait(lua_State* L) {
    double sec = luaL_optnumber(L, 1, 0.03);
    if (sec < 0) sec = 0;
    if (sec > 30) sec = 30;

    auto start = std::chrono::steady_clock::now();
    double elapsed = 0;
    while (elapsed < sec) {
        chk(L);
        pump_deferred();
        double chunk = std::min(sec - elapsed, 0.016);
        std::this_thread::sleep_for(std::chrono::duration<double>(chunk));
        elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count();
    }
    lua_pushnumber(L, elapsed);
    return 1;
}

int Closures::l_task_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int top = lua_gettop(L);
    int nargs = top - 1;

    lua_State* thr = lua_newthread(L);
    luaL_sandboxthread(thr);

    lua_pushvalue(L, 1);
    for (int i = 2; i <= top; i++)
        lua_pushvalue(L, i);
    lua_xmove(L, thr, 1 + nargs);

    int status = lua_resume(thr, nullptr, nargs);
    if (status == LUA_YIELD) {
        double w = 0.03;
        if (lua_isnumber(thr, -1)) { w = lua_tonumber(thr, -1); lua_pop(thr, 1); }
        std::lock_guard<std::mutex> lk(g_def_mtx);
        g_deferred.push_back({thr, 0, mono() + w});
    } else if (status != 0) {
        const char* err = lua_tostring(thr, -1);
        spdlog::error("[task.spawn] {}", err ? err : "unknown");
    }

    lua_pushvalue(L, -1);
    return 1;
}

int Closures::l_task_defer(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int top = lua_gettop(L);
    int nargs = top - 1;

    lua_State* thr = lua_newthread(L);
    luaL_sandboxthread(thr);

    lua_pushvalue(L, 1);
    for (int i = 2; i <= top; i++)
        lua_pushvalue(L, i);
    lua_xmove(L, thr, 1 + nargs);

    {
        std::lock_guard<std::mutex> lk(g_def_mtx);
        g_deferred.push_back({thr, nargs, mono()});
    }

    lua_pushvalue(L, -1);
    return 1;
}

int Closures::l_task_delay(lua_State* L) {
    double dt = luaL_checknumber(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (dt < 0) dt = 0;
    if (dt > 30) dt = 30;

    int top = lua_gettop(L);
    int nargs = top - 2;

    lua_State* thr = lua_newthread(L);
    luaL_sandboxthread(thr);

    lua_pushvalue(L, 2);
    for (int i = 3; i <= top; i++)
        lua_pushvalue(L, i);
    lua_xmove(L, thr, 1 + nargs);

    lua_pushnumber(thr, dt);

    {
        std::lock_guard<std::mutex> lk(g_def_mtx);
        g_deferred.push_back({thr, nargs + 1, mono() + dt});
    }

    lua_pushvalue(L, -1);
    return 1;
}

int Closures::l_task_cancel(lua_State* L) {
    if (!lua_isthread(L, 1)) { luaL_error(L, "Expected thread"); return 0; }
    lua_State* thr = lua_tothread(L, 1);

    {
        std::lock_guard<std::mutex> lk(g_def_mtx);
        g_deferred.erase(
            std::remove_if(g_deferred.begin(), g_deferred.end(),
                [thr](const Deferred& d) { return d.thr == thr; }),
            g_deferred.end());
    }

    if (thr) lua_resetthread(thr);
    return 0;
}

} // namespace oss
