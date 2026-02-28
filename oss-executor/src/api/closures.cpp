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

namespace oss {

// ═══════════════════════════════════════════════════════════════
//  Static Constants
// ═══════════════════════════════════════════════════════════════

const char* Closures::EXECUTOR_MARKER = "__oss_executor_closure";
const char* Closures::HOOK_TABLE_KEY  = "__oss_hook_table";

// ═══════════════════════════════════════════════════════════════
//  Internal State
// ═══════════════════════════════════════════════════════════════

static std::unordered_map<int, int> g_instance_to_overlay;
static int g_next_instance_id = 1;
static const std::string WORKSPACE_DIR = "workspace";

// ═══════════════════════════════════════════════════════════════
//  Free-standing Helpers
// ═══════════════════════════════════════════════════════════════

static std::string get_workspace_path(const std::string& filename = "") {
    std::filesystem::create_directories(WORKSPACE_DIR);
    if (filename.empty()) return WORKSPACE_DIR;
    return WORKSPACE_DIR + "/" + filename;
}

static void push_color3(lua_State* L, double r, double g, double b) {
    lua_newtable(L);
    lua_pushnumber(L, r); lua_setfield(L, -2, "R");
    lua_pushnumber(L, g); lua_setfield(L, -2, "G");
    lua_pushnumber(L, b); lua_setfield(L, -2, "B");
    lua_pushstring(L, "Color3");
    lua_setfield(L, -2, "__type");
}

static void push_udim2(lua_State* L, double xs, double xo,
                        double ys, double yo) {
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
    lua_pushnumber(L, std::sqrt(x*x + y*y));
    lua_setfield(L, -2, "Magnitude");
    lua_pushstring(L, "Vector2"); lua_setfield(L, -2, "__type");
}

static void read_udim2(lua_State* L, int idx,
                       float& xs, float& xo, float& ys, float& yo) {
    xs = xo = ys = yo = 0;
    if (!lua_istable(L, idx)) return;
    lua_getfield(L, idx, "_xs");
    if (lua_isnumber(L, -1)) xs = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, idx, "_xo");
    if (lua_isnumber(L, -1)) xo = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, idx, "_ys");
    if (lua_isnumber(L, -1)) ys = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, idx, "_yo");
    if (lua_isnumber(L, -1)) yo = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);
}

static void read_color3(lua_State* L, int idx,
                        float& r, float& g, float& b) {
    r = g = b = 0;
    if (!lua_istable(L, idx)) return;
    lua_getfield(L, idx, "R");
    if (lua_isnumber(L, -1)) r = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, idx, "G");
    if (lua_isnumber(L, -1)) g = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, idx, "B");
    if (lua_isnumber(L, -1)) b = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);
}

static void push_instance(lua_State* L, int instance_id,
                           const std::string& class_name) {
    lua_newtable(L);
    lua_pushinteger(L, instance_id);        lua_setfield(L, -2, "__id");
    lua_pushstring(L, class_name.c_str());  lua_setfield(L, -2, "ClassName");
    lua_pushstring(L, class_name.c_str());  lua_setfield(L, -2, "Name");

    lua_pushcfunction(L, Closures::l_instance_destroy,       "Destroy");
    lua_setfield(L, -2, "Destroy");
    lua_pushcfunction(L, Closures::l_instance_getchildren,   "GetChildren");
    lua_setfield(L, -2, "GetChildren");
    lua_pushcfunction(L, Closures::l_instance_findfirstchild,"FindFirstChild");
    lua_setfield(L, -2, "FindFirstChild");
    lua_pushcfunction(L, Closures::l_instance_waitforchild,  "WaitForChild");
    lua_setfield(L, -2, "WaitForChild");
    lua_pushcfunction(L, Closures::l_instance_isA,           "IsA");
    lua_setfield(L, -2, "IsA");

    lua_newtable(L);
    lua_pushcfunction(L, Closures::l_instance_index,    "__index");
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, Closures::l_instance_newindex,  "__newindex");
    lua_setfield(L, -2, "__newindex");
    lua_pushstring(L, class_name.c_str());
    lua_setfield(L, -2, "__type");
    lua_setmetatable(L, -2);
}

// helper: compile a small Luau snippet and load it
static bool compile_and_load(lua_State* L, const char* src,
                             const char* chunkname) {
    Luau::CompileOptions opts;
    opts.optimizationLevel = 1;
    std::string bc = Luau::compile(src, opts);
    if (!bc.empty() && bc[0] == 0) return false;
    return luau_load(L, chunkname, bc.data(), bc.size(), 0) == 0;
}

// ═══════════════════════════════════════════════════════════════
//  Hook-Table Infrastructure  (private)
// ═══════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════
//  Registration
// ═══════════════════════════════════════════════════════════════

void Closures::register_all(lua_State* L) {
    ensure_hook_table(L);

    lua_pushboolean(L, 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "__oss_is_executor");

    // ── closure manipulation globals ──
    lua_pushcfunction(L, wrap_closure,        "wrapclosure");
    lua_setglobal(L, "wrapclosure");

    lua_pushcfunction(L, getscriptclosure,    "getscriptclosure");
    lua_setglobal(L, "getscriptclosure");

    lua_pushcfunction(L, compare_closures,    "compareinstances");
    lua_setglobal(L, "compareinstances");

    lua_pushcfunction(L, clone_function,      "clonefunction");
    lua_setglobal(L, "clonefunction");

    lua_pushcfunction(L, get_calling_script,  "getcallingscript");
    lua_setglobal(L, "getcallingscript");

    lua_pushcfunction(L, l_newcclosure,       "newcclosure");
    lua_setglobal(L, "newcclosure");

    lua_pushcfunction(L, l_hookfunction,      "hookfunction");
    lua_setglobal(L, "hookfunction");
    lua_pushcfunction(L, l_hookfunction,      "replaceclosure");
    lua_setglobal(L, "replaceclosure");

    lua_pushcfunction(L, l_hookmetamethod,    "hookmetamethod");
    lua_setglobal(L, "hookmetamethod");

    lua_pushcfunction(L, iscclosure,          "iscclosure");
    lua_setglobal(L, "iscclosure");

    lua_pushcfunction(L, islclosure,          "islclosure");
    lua_setglobal(L, "islclosure");

    lua_pushcfunction(L, l_isexecutorclosure, "isexecutorclosure");
    lua_setglobal(L, "isexecutorclosure");
    lua_pushcfunction(L, l_isexecutorclosure, "checkclosure");
    lua_setglobal(L, "checkclosure");
    lua_pushcfunction(L, l_isexecutorclosure, "isourclosure");
    lua_setglobal(L, "isourclosure");

    lua_pushcfunction(L, l_checkcaller,       "checkcaller");
    lua_setglobal(L, "checkcaller");

    lua_pushcfunction(L, l_getinfo,           "getinfo");
    lua_setglobal(L, "getinfo");

    lua_pushcfunction(L, l_loadstring,        "loadstring");
    lua_setglobal(L, "loadstring");

    lua_pushcfunction(L, newlclosure,         "newlclosure");
    lua_setglobal(L, "newlclosure");
}

// ═══════════════════════════════════════════════════════════════
//  Global Closures
// ═══════════════════════════════════════════════════════════════

int Closures::l_print(lua_State* L) {
    int n = lua_gettop(L);
    std::string output;
    for (int i = 1; i <= n; i++) {
        size_t len;
        const char* s = luaL_tolstring(L, i, &len);
        if (i > 1) output += "\t";
        if (s) output += std::string(s, len);
        lua_pop(L, 1);
    }
    spdlog::info("[Script] {}", output);
    return 0;
}

int Closures::l_warn(lua_State* L) {
    int n = lua_gettop(L);
    std::string output;
    for (int i = 1; i <= n; i++) {
        size_t len;
        const char* s = luaL_tolstring(L, i, &len);
        if (i > 1) output += "\t";
        if (s) output += std::string(s, len);
        lua_pop(L, 1);
    }
    spdlog::warn("[Script] {}", output);
    return 0;
}

int Closures::l_wait(lua_State* L) {
    double seconds = luaL_optnumber(L, 1, 0.03);
    if (seconds < 0) seconds = 0;
    if (seconds > 10) seconds = 10;
    auto start = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    double actual = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();
    lua_pushnumber(L, actual);
    lua_pushnumber(L, actual);
    return 2;
}

int Closures::l_delay(lua_State* L) {
    double seconds = luaL_checknumber(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (seconds > 0)
        std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    lua_pushvalue(L, 2);
    lua_call(L, 0, 0);
    return 0;
}

int Closures::l_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);
    int nargs = lua_gettop(L) - 1;
    for (int i = 2; i <= lua_gettop(L); i++)
        lua_pushvalue(L, i);
    int status = lua_pcall(L, nargs - 1, 0, 0);
    if (status != 0) {
        const char* err = lua_tostring(L, -1);
        spdlog::error("[Script] spawn error: {}",
                      err ? err : "unknown");
        lua_pop(L, 1);
    }
    return 0;
}

int Closures::l_loadstring(lua_State* L) {
    size_t len;
    const char* source = luaL_checklstring(L, 1, &len);
    const char* chunkname = luaL_optstring(L, 2, "=loadstring");

    std::string src(source, len);
    Luau::CompileOptions opts;
    opts.optimizationLevel = 1;
    opts.debugLevel = 1;
    std::string bytecode = Luau::compile(src, opts);

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

    // mark in hook table so isexecutorclosure recognises it
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
    auto now = std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch());
    lua_pushnumber(L, now.count());
    return 1;
}

// ═══════════════════════════════════════════════════════════════
//  Instance Closures
// ═══════════════════════════════════════════════════════════════

int Closures::l_instance_new(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 1);
    auto& overlay = Overlay::instance();
    int overlay_id = overlay.create_gui_element(class_name, class_name);
    int inst_id = g_next_instance_id++;
    g_instance_to_overlay[inst_id] = overlay_id;

    if (lua_gettop(L) >= 2 && lua_istable(L, 2)) {
        lua_getfield(L, 2, "__id");
        if (lua_isnumber(L, -1)) {
            int parent_inst_id = (int)lua_tointeger(L, -1);
            auto pit = g_instance_to_overlay.find(parent_inst_id);
            if (pit != g_instance_to_overlay.end())
                overlay.set_gui_parent(overlay_id, pit->second);
        }
        lua_pop(L, 1);
    }

    push_instance(L, inst_id, class_name);
    spdlog::debug("Instance.new('{}') -> id={}, overlay_id={}",
                  class_name, inst_id, overlay_id);
    return 1;
}

int Closures::l_instance_index(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);
    lua_rawget(L, 1);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 1);

    lua_getfield(L, 1, "__id");
    if (!lua_isnumber(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; }
    int inst_id = (int)lua_tointeger(L, -1);
    lua_pop(L, 1);

    auto oit = g_instance_to_overlay.find(inst_id);
    if (oit == g_instance_to_overlay.end()) { lua_pushnil(L); return 1; }

    (void)key;
    lua_pushnil(L);
    return 1;
}

int Closures::l_instance_newindex(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);

    lua_getfield(L, 1, "__id");
    if (!lua_isnumber(L, -1)) { lua_pop(L, 1); lua_rawset(L, 1); return 0; }
    int inst_id = (int)lua_tointeger(L, -1);
    lua_pop(L, 1);

    auto oit = g_instance_to_overlay.find(inst_id);
    if (oit == g_instance_to_overlay.end()) { lua_rawset(L, 1); return 0; }

    int overlay_id = oit->second;
    auto& overlay = Overlay::instance();
    std::string prop(key);

    // ── Parent ──
    if (prop == "Parent") {
        if (lua_isnil(L, 3)) {
            overlay.set_gui_parent(overlay_id, 0);
        } else if (lua_istable(L, 3)) {
            lua_getfield(L, 3, "__id");
            if (lua_isnumber(L, -1)) {
                int pi = (int)lua_tointeger(L, -1);
                auto pit = g_instance_to_overlay.find(pi);
                if (pit != g_instance_to_overlay.end())
                    overlay.set_gui_parent(overlay_id, pit->second);
            }
            lua_pop(L, 1);
        }
        if (lua_istable(L, 3)) {
            lua_getfield(L, 3, "ClassName");
            if (lua_isstring(L, -1)) {
                std::string cn = lua_tostring(L, -1);
                if (cn == "CoreGui" || cn == "PlayerGui") {
                    overlay.update_gui_element(overlay_id, [](GuiElement& e) {
                        e.enabled = true;  e.visible = true;
                    });
                    if (!overlay.is_visible()) overlay.show();
                }
            }
            lua_pop(L, 1);
        }
        return 0;
    }

    // ── Every other property ──
    overlay.update_gui_element(overlay_id, [&](GuiElement& e) {
        if      (prop == "Name")       { if (lua_isstring(L,3)) e.name = lua_tostring(L,3); }
        else if (prop == "Visible")    { e.visible = lua_toboolean(L,3); }
        else if (prop == "Text")       { if (lua_isstring(L,3)) e.text = lua_tostring(L,3); }
        else if (prop == "TextColor3") { read_color3(L,3,e.text_r,e.text_g,e.text_b); }
        else if (prop == "TextSize")   { if (lua_isnumber(L,3)) e.text_size=(float)lua_tonumber(L,3); }
        else if (prop == "TextTransparency")        { if (lua_isnumber(L,3)) e.text_transparency=(float)lua_tonumber(L,3); }
        else if (prop == "TextStrokeTransparency")  { if (lua_isnumber(L,3)) e.text_stroke_transparency=(float)lua_tonumber(L,3); }
        else if (prop == "TextStrokeColor3")        { read_color3(L,3,e.text_stroke_r,e.text_stroke_g,e.text_stroke_b); }
        else if (prop == "TextXAlignment")  { if (lua_isnumber(L,3)) e.text_x_alignment=(int)lua_tointeger(L,3); }
        else if (prop == "TextYAlignment")  { if (lua_isnumber(L,3)) e.text_y_alignment=(int)lua_tointeger(L,3); }
        else if (prop == "TextWrapped")     { e.text_wrapped = lua_toboolean(L,3); }
        else if (prop == "TextScaled")      { e.text_scaled  = lua_toboolean(L,3); }
        else if (prop == "RichText")        { e.rich_text    = lua_toboolean(L,3); }
        else if (prop == "BackgroundColor3")       { read_color3(L,3,e.bg_r,e.bg_g,e.bg_b); }
        else if (prop == "BackgroundTransparency") { if (lua_isnumber(L,3)) e.bg_transparency=(float)lua_tonumber(L,3); }
        else if (prop == "BorderColor3")    { read_color3(L,3,e.border_r,e.border_g,e.border_b); }
        else if (prop == "BorderSizePixel") { if (lua_isnumber(L,3)) e.border_size=(int)lua_tointeger(L,3); }
        else if (prop == "Size") {
            read_udim2(L, 3, e.size_x_scale, e.size_x_offset,
                             e.size_y_scale, e.size_y_offset);
        }
        else if (prop == "Position") {
            read_udim2(L, 3, e.pos_x_scale, e.pos_x_offset,
                             e.pos_y_scale, e.pos_y_offset);
        }
        else if (prop == "AnchorPoint") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "X");
                if (lua_isnumber(L, -1)) e.anchor_x = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
                lua_getfield(L, 3, "Y");
                if (lua_isnumber(L, -1)) e.anchor_y = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
        }
        else if (prop == "Rotation")          { if (lua_isnumber(L,3)) e.rotation=(float)lua_tonumber(L,3); }
        else if (prop == "ClipsDescendants")  { e.clips_descendants = lua_toboolean(L,3); }
        else if (prop == "ZIndex")            { if (lua_isnumber(L,3)) e.z_index=(int)lua_tointeger(L,3); }
        else if (prop == "LayoutOrder")       { if (lua_isnumber(L,3)) e.layout_order=(int)lua_tointeger(L,3); }
        else if (prop == "Enabled")           { e.enabled = lua_toboolean(L,3); }
        else if (prop == "DisplayOrder")      { if (lua_isnumber(L,3)) e.display_order=(int)lua_tointeger(L,3); }
        else if (prop == "IgnoreGuiInset")    { e.ignore_gui_inset = lua_toboolean(L,3); }
        else if (prop == "ResetOnSpawn")      { /* accepted, no-op */ }
        else if (prop == "CornerRadius") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Offset");
                if (lua_isnumber(L, -1)) e.corner_radius = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
            } else if (lua_isnumber(L, 3)) {
                e.corner_radius = (float)lua_tonumber(L, 3);
            }
        }
        else if (prop == "Thickness") {
            if (lua_isnumber(L, 3)) e.stroke_thickness = (float)lua_tonumber(L, 3);
        }
        else if (prop == "Color") {
            read_color3(L, 3, e.stroke_r, e.stroke_g, e.stroke_b);
        }
        else if (prop == "Transparency") {
            if (lua_isnumber(L, 3)) e.stroke_transparency = (float)lua_tonumber(L, 3);
        }
        else if (prop == "PaddingTop") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Offset");
                if (lua_isnumber(L, -1)) e.pad_top = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
        }
        else if (prop == "PaddingBottom") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Offset");
                if (lua_isnumber(L, -1)) e.pad_bottom = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
        }
        else if (prop == "PaddingLeft") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Offset");
                if (lua_isnumber(L, -1)) e.pad_left = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
        }
        else if (prop == "PaddingRight") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Offset");
                if (lua_isnumber(L, -1)) e.pad_right = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
        }
        else if (prop == "Image") {
            if (lua_isstring(L, 3)) e.image = lua_tostring(L, 3);
        }
        else if (prop == "ImageColor3") {
            read_color3(L, 3, e.image_r, e.image_g, e.image_b);
        }
        else if (prop == "ImageTransparency") {
            if (lua_isnumber(L, 3)) e.image_transparency = (float)lua_tonumber(L, 3);
        }
        else if (prop == "ScrollingEnabled") { e.scrolling_enabled = lua_toboolean(L, 3); }
        else if (prop == "CanvasSize") {
            if (lua_istable(L, 3)) {
                float xs, xo, ys, yo;
                read_udim2(L, 3, xs, xo, ys, yo);
                e.canvas_size_y = ys * 1000 + yo;
            }
        }
        else if (prop == "AutomaticSize")  { /* accepted, limited */ }
        else if (prop == "Padding") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Offset");
                if (lua_isnumber(L, -1)) e.pad_top = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
        }
        else if (prop == "FillDirection") { /* UIListLayout */ }
        else if (prop == "SortOrder")     { /* UIListLayout */ }
        else if (prop == "Active")        { /* accepted */ }
        else if (prop == "Selectable")    { /* accepted */ }
        else if (prop == "Draggable")     { /* accepted (deprecated) */ }
    });

    lua_rawset(L, 1);
    return 0;
}

int Closures::l_instance_destroy(lua_State* L) {
    lua_getfield(L, 1, "__id");
    if (lua_isnumber(L, -1)) {
        int inst_id = (int)lua_tointeger(L, -1);
        auto it = g_instance_to_overlay.find(inst_id);
        if (it != g_instance_to_overlay.end()) {
            Overlay::instance().remove_gui_element(it->second);
            g_instance_to_overlay.erase(it);
        }
    }
    lua_pop(L, 1);
    return 0;
}

int Closures::l_instance_clone(lua_State* L) {
    lua_getfield(L, 1, "ClassName");
    const char* cn = lua_tostring(L, -1);
    if (!cn) cn = "Frame";

    auto& overlay = Overlay::instance();
    int new_ov = overlay.create_gui_element(cn, cn);
    int new_id = g_next_instance_id++;
    g_instance_to_overlay[new_id] = new_ov;

    push_instance(L, new_id, cn);
    return 1;
}

int Closures::l_instance_getchildren(lua_State* L) {
    lua_newtable(L);
    return 1;
}

int Closures::l_instance_findfirstchild(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

int Closures::l_instance_waitforchild(lua_State* L) {
    const char* name = luaL_checkstring(L, 2);
    lua_getfield(L, 1, name);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 1);
    lua_pushnil(L);
    return 1;
}

int Closures::l_instance_isA(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 2);
    lua_getfield(L, 1, "ClassName");
    const char* cn = lua_tostring(L, -1);
    lua_pop(L, 1);
    lua_pushboolean(L, (cn && class_name) ? (strcmp(cn, class_name) == 0) : false);
    return 1;
}

// ═══════════════════════════════════════════════════════════════
//  Data-Type Closures
// ═══════════════════════════════════════════════════════════════

int Closures::l_color3_new(lua_State* L) {
    push_color3(L, luaL_optnumber(L,1,0), luaL_optnumber(L,2,0), luaL_optnumber(L,3,0));
    return 1;
}

int Closures::l_color3_fromRGB(lua_State* L) {
    push_color3(L, luaL_optnumber(L,1,0)/255.0,
                    luaL_optnumber(L,2,0)/255.0,
                    luaL_optnumber(L,3,0)/255.0);
    return 1;
}

int Closures::l_color3_fromHSV(lua_State* L) {
    double h = luaL_optnumber(L,1,0), s = luaL_optnumber(L,2,0), v = luaL_optnumber(L,3,0);
    double r,g,b;
    int i = (int)(h * 6.0);
    double f = h*6.0 - i, p = v*(1-s), q = v*(1-f*s), t = v*(1-(1-f)*s);
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
    push_udim2(L, luaL_optnumber(L,1,0), luaL_optnumber(L,2,0),
                   luaL_optnumber(L,3,0), luaL_optnumber(L,4,0));
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
    lua_pushnumber(L, luaL_optnumber(L,1,1));      lua_setfield(L,-2,"Time");
    lua_pushinteger(L,(int)luaL_optinteger(L,2,0)); lua_setfield(L,-2,"EasingStyle");
    lua_pushinteger(L,(int)luaL_optinteger(L,3,0)); lua_setfield(L,-2,"EasingDirection");
    lua_pushinteger(L,(int)luaL_optinteger(L,4,0)); lua_setfield(L,-2,"RepeatCount");
    lua_pushboolean(L, lua_toboolean(L,5));          lua_setfield(L,-2,"Reverses");
    lua_pushnumber(L, luaL_optnumber(L,6,0));        lua_setfield(L,-2,"DelayTime");
    lua_pushstring(L,"TweenInfo"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_numberrange_new(lua_State* L) {
    double mn = luaL_optnumber(L,1,0);
    lua_newtable(L);
    lua_pushnumber(L, mn);                         lua_setfield(L,-2,"Min");
    lua_pushnumber(L, luaL_optnumber(L,2,mn));     lua_setfield(L,-2,"Max");
    lua_pushstring(L,"NumberRange"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_colorsequence_new(lua_State* L) {
    lua_newtable(L);
    lua_pushstring(L,"ColorSequence"); lua_setfield(L,-2,"__type");
    return 1;
}

int Closures::l_numbersequence_new(lua_State* L) {
    lua_newtable(L);
    lua_pushstring(L,"NumberSequence"); lua_setfield(L,-2,"__type");
    return 1;
}

// ═══════════════════════════════════════════════════════════════
//  Drawing Closures
// ═══════════════════════════════════════════════════════════════

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
    lua_pushcfunction(L, l_drawing_index,    "__index");
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_drawing_newindex,  "__newindex");
    lua_setfield(L, -2, "__newindex");
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
            float r, g, b;
            read_color3(L, 3, r, g, b);
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
        else if (prop == "Center")       { obj.center  = lua_toboolean(L,3); }
        else if (prop == "Outline")      { obj.outline  = lua_toboolean(L,3); }
        else if (prop == "OutlineColor") {
            float r, g, b;
            read_color3(L, 3, r, g, b);
            obj.outline_r = r; obj.outline_g = g; obj.outline_b = b;
        }
        else if (prop == "Font")         { if (lua_isnumber(L,3)) obj.font=(int)lua_tointeger(L,3); }
        else if (prop == "Radius")       { if (lua_isnumber(L,3)) obj.radius=(float)lua_tonumber(L,3); }
        else if (prop == "Filled")       { obj.filled = lua_toboolean(L,3); }
        else if (prop == "NumSides")     { if (lua_isnumber(L,3)) obj.num_sides=(int)lua_tointeger(L,3); }
        else if (prop == "Rounding")     { if (lua_isnumber(L,3)) obj.rounding=(float)lua_tonumber(L,3); }
        else if (prop == "ZIndex")       { if (lua_isnumber(L,3)) obj.z_index=(int)lua_tointeger(L,3); }
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

// ═══════════════════════════════════════════════════════════════
//  Service / Game Closures
// ═══════════════════════════════════════════════════════════════

int Closures::l_game_getservice(lua_State* L) {
    const char* service_name = luaL_checkstring(L, 2);

    lua_newtable(L);
    lua_pushstring(L, service_name); lua_setfield(L, -2, "ClassName");
    lua_pushstring(L, service_name); lua_setfield(L, -2, "Name");

    std::string sn(service_name);

    if (sn == "Players") {
        lua_newtable(L);
        lua_pushstring(L, "Player");      lua_setfield(L, -2, "ClassName");
        lua_pushstring(L, "LocalPlayer"); lua_setfield(L, -2, "Name");
        lua_pushinteger(L, 1);            lua_setfield(L, -2, "UserId");
        lua_pushstring(L, "Player1");     lua_setfield(L, -2, "DisplayName");

        int pg_inst = g_next_instance_id++;
        auto& ov = Overlay::instance();
        int pg_ov = ov.create_gui_element("PlayerGui", "PlayerGui");
        g_instance_to_overlay[pg_inst] = pg_ov;
        push_instance(L, pg_inst, "PlayerGui");
        lua_setfield(L, -2, "PlayerGui");

        lua_setfield(L, -2, "LocalPlayer");
    }
    else if (sn == "CoreGui") {
        int cg_inst = g_next_instance_id++;
        lua_pushinteger(L, cg_inst); lua_setfield(L, -2, "__id");
        lua_pushstring(L, "CoreGui"); lua_setfield(L, -2, "ClassName");
    }
    else if (sn == "UserInputService") {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            lua_pushboolean(L, false); return 1;
        }, "IsKeyDown");
        lua_setfield(L, -2, "IsKeyDown");
    }
    else if (sn == "TweenService") {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            lua_newtable(L);
            lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "Play");
            lua_setfield(L, -2, "Play");
            lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "Cancel");
            lua_setfield(L, -2, "Cancel");
            lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "Pause");
            lua_setfield(L, -2, "Pause");
            return 1;
        }, "Create");
        lua_setfield(L, -2, "Create");
    }
    else if (sn == "RunService") {
        // RenderStepped
        lua_newtable(L);
        lua_pushcfunction(L, [](lua_State* L) -> int {
            lua_newtable(L);
            lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "Disconnect");
            lua_setfield(L, -2, "Disconnect");
            return 1;
        }, "Connect");
        lua_setfield(L, -2, "Connect");
        lua_setfield(L, -2, "RenderStepped");

        // Heartbeat
        lua_newtable(L);
        lua_pushcfunction(L, [](lua_State* L) -> int {
            lua_newtable(L);
            lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "Disconnect");
            lua_setfield(L, -2, "Disconnect");
            return 1;
        }, "Connect");
        lua_setfield(L, -2, "Connect");
        lua_setfield(L, -2, "Heartbeat");
    }
    else if (sn == "HttpService") {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            size_t len;
            const char* js = luaL_checklstring(L, 2, &len);
            lua_pushlstring(L, js, len);
            return 1;
        }, "JSONDecode");
        lua_setfield(L, -2, "JSONDecode");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            lua_pushstring(L, "{}"); return 1;
        }, "JSONEncode");
        lua_setfield(L, -2, "JSONEncode");
    }

    // generic __index metatable
    lua_newtable(L);
    lua_pushcfunction(L, [](lua_State* L) -> int {
        lua_pushnil(L); return 1;
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
    lua_rawget(L, 1);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 1);

    std::string k(key);
    if (k=="Players"||k=="Workspace"||k=="Lighting"||
        k=="ReplicatedStorage"||k=="StarterGui"||k=="CoreGui") {
        lua_getfield(L, 1, "GetService");
        lua_pushvalue(L, 1);
        lua_pushstring(L, key);
        lua_call(L, 2, 1);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// ═══════════════════════════════════════════════════════════════
//  Executor Closures
// ═══════════════════════════════════════════════════════════════

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
    lua_pushstring(L, "1.0.0");
    return 2;
}

int Closures::l_setclipboard(lua_State* L) {
    const char* text = luaL_checkstring(L, 1);
    std::string cmd = "echo -n '" + std::string(text) + "' | ";
    if (std::system("which wl-copy > /dev/null 2>&1") == 0)
        cmd += "wl-copy";
    else
        cmd += "xclip -selection clipboard";
    int ret = std::system(cmd.c_str());
    (void)ret;
    return 0;
}

int Closures::l_getnamecallmethod(lua_State* L) {
    const char* name = lua_namecallatom(L, nullptr);
    if (name) lua_pushstring(L, name);
    else      lua_pushnil(L);
    return 1;
}

int Closures::l_fireclickdetector(lua_State* L) {
    spdlog::debug("[Script] fireclickdetector called");
    return 0;
}

int Closures::l_firetouchinterest(lua_State* L) {
    spdlog::debug("[Script] firetouchinterest called");
    return 0;
}

int Closures::l_fireproximityprompt(lua_State* L) {
    spdlog::debug("[Script] fireproximityprompt called");
    return 0;
}

int Closures::l_gethui(lua_State* L) {
    static int hui_inst_id    = 0;
    static int hui_overlay_id = 0;
    if (hui_inst_id == 0) {
        auto& overlay = Overlay::instance();
        hui_overlay_id = overlay.create_gui_element("Folder", "HiddenUI");
        hui_inst_id    = g_next_instance_id++;
        g_instance_to_overlay[hui_inst_id] = hui_overlay_id;
    }
    push_instance(L, hui_inst_id, "Folder");
    lua_pushstring(L, "CoreGui"); lua_setfield(L, -2, "ClassName");
    return 1;
}

int Closures::l_http_request(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    // URL
    lua_getfield(L, 1, "Url");
    if (lua_isnil(L, -1)) { lua_pop(L,1); lua_getfield(L,1,"url"); }
    const char* url = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    // Method
    lua_getfield(L, 1, "Method");
    if (lua_isnil(L, -1)) { lua_pop(L,1); lua_getfield(L,1,"method"); }
    const char* method = luaL_optstring(L, -1, "GET");
    lua_pop(L, 1);

    // Body
    lua_getfield(L, 1, "Body");
    if (lua_isnil(L, -1)) { lua_pop(L,1); lua_getfield(L,1,"body"); }
    const char* body = lua_isstring(L, -1) ? lua_tostring(L, -1) : nullptr;
    lua_pop(L, 1);

    // Headers
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
        status_code = response_body.empty() ? 0 : 200;
        success = !response_body.empty();
    } else if (ms == "POST") {
        std::string bs = body ? body : "";
        std::string ct = "application/json";
        auto it = headers.find("Content-Type");
        if (it != headers.end()) ct = it->second;
        std::map<std::string,std::string> req_headers = headers;
        req_headers["Content-Type"] = ct;
        auto resp = http.post(url, bs, req_headers);
        response_body = resp.body;
        status_code = response_body.empty() ? 0 : 200;
        success = !response_body.empty();
    } else {
        auto resp = http.get(url, headers);
        response_body = resp.body;
        status_code = 200; success = true;
    }

    lua_newtable(L);
    lua_pushinteger(L, status_code);                        lua_setfield(L,-2,"StatusCode");
    lua_pushstring(L, success ? "OK" : "Error");            lua_setfield(L,-2,"StatusMessage");
    lua_pushboolean(L, success);                            lua_setfield(L,-2,"Success");
    lua_pushlstring(L, response_body.data(), response_body.size());
    lua_setfield(L,-2,"Body");
    lua_newtable(L); lua_setfield(L,-2,"Headers");
    return 1;
}

// ═══════════════════════════════════════════════════════════════
//  Closure-Manipulation Closures
// ═══════════════════════════════════════════════════════════════

// ── internal trampolines (private) ──

int Closures::wrap_closure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);                                 // upvalue 1
    lua_pushcclosure(L, closure_handler, "wrapclosure_proxy", 1);
    return 1;
}

int Closures::closure_handler(lua_State* L) {
    int nargs = lua_gettop(L);
    int base  = nargs;
    lua_pushvalue(L, lua_upvalueindex(1));
    for (int i = 1; i <= nargs; i++) lua_pushvalue(L, i);
    lua_call(L, nargs, LUA_MULTRET);
    return lua_gettop(L) - base;
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
    // Delegate to l_loadstring which already handles
    // Luau compilation + hook-table marking.
    return l_loadstring(L);
}

// ── public closure-manipulation API ──

int Closures::l_newcclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    lua_pushvalue(L, 1);       // upvalue 1 – wrapped func
    lua_pushboolean(L, 1);     // upvalue 2 – marker
    lua_pushcclosure(L, newcclosure_handler, "newcclosure_proxy", 2);

    // register in hook table
    get_hook_table(L);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);             // pop hook table

    return 1;
}

int Closures::l_hookfunction(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    // Save a reference to the original before hooking
    lua_pushvalue(L, 1);
    int orig_ref = lua_ref(L, -1);
    lua_pop(L, 1);

    // Record the mapping original → hook in the hook table
    get_hook_table(L);
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 2);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    // Return a callable that invokes the original
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

    // fetch old metamethod
    lua_getfield(L, -1, method);
    int old_ref = LUA_NOREF;
    if (!lua_isnil(L, -1)) {
        old_ref = lua_ref(L, -1);
    }
    lua_pop(L, 1);

    // install new
    lua_pushvalue(L, 3);
    lua_setfield(L, -2, method);
    lua_pop(L, 1);  // pop metatable

    // return old (or stub)
    if (old_ref != LUA_NOREF) {
        lua_getref(L, old_ref);
        lua_unref(L, old_ref);
    } else {
        lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "hookmetamethod_stub");
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
    if (!lua_isfunction(L, 1)) {
        lua_pushboolean(L, 0);
        return 1;
    }

    // 1) check hook table
    get_hook_table(L);
    lua_pushvalue(L, 1);
    lua_rawget(L, -2);
    if (!lua_isnil(L, -1)) { lua_pop(L, 2); lua_pushboolean(L, 1); return 1; }
    lua_pop(L, 2);

    // 2) C closures registered by us are executor closures
    if (lua_iscfunction(L, 1)) {
        lua_pushboolean(L, 1);
        return 1;
    }

    // 3) Lua closures – check source heuristic
    lua_Debug ar;
    memset(&ar, 0, sizeof(ar));
    lua_pushvalue(L, 1);
    if (lua_getinfo(L, 0, "s", &ar) && ar.source) {
        std::string src(ar.source);
        if (src.find("=env_setup")    != std::string::npos ||
            src.find("=sandbox")      != std::string::npos ||
            src.find("=input")        != std::string::npos ||
            src.find("=cloned")       != std::string::npos ||
            src.find("=newlclosure")  != std::string::npos ||
            src.find("=hooked")       != std::string::npos ||
            src.find("=loadstring")   != std::string::npos) {
            lua_pushboolean(L, 1);
            return 1;
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
                src.find("=env_setup") != std::string::npos ||
                src.find("=sandbox")   != std::string::npos) {
                lua_pushboolean(L, 1);
                return 1;
            }
            if (src[0] == '@') {
                lua_pushboolean(L, 0);
                return 1;
            }
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
        if (!lua_getinfo(L, level, "slna", &ar)) {
            lua_pushnil(L);
            return 1;
        }
    } else if (lua_isfunction(L, 1)) {
        lua_pushvalue(L, 1);
        lua_getinfo(L, 0, "slna", &ar);
    } else {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    if (ar.source) {
        lua_pushstring(L, ar.source);   lua_setfield(L, -2, "source");
        lua_pushstring(L, ar.source);   lua_setfield(L, -2, "short_src");
    }
    if (ar.name) {
        lua_pushstring(L, ar.name);     lua_setfield(L, -2, "name");
    }
    if (ar.what) {
        lua_pushstring(L, ar.what);     lua_setfield(L, -2, "what");
        lua_pushboolean(L, strcmp(ar.what, "C") == 0);
        lua_setfield(L, -2, "is_c");
    }

    lua_pushinteger(L, ar.currentline);     lua_setfield(L, -2, "currentline");
    lua_pushinteger(L, ar.linedefined);     lua_setfield(L, -2, "linedefined");

    // Luau lua_Debug exposes nupvals, nparams, isvararg
    lua_pushinteger(L, ar.nupvals);         lua_setfield(L, -2, "nups");
    lua_pushinteger(L, ar.nparams);         lua_setfield(L, -2, "numparams");
    lua_pushboolean(L, ar.isvararg);        lua_setfield(L, -2, "is_vararg");

    return 1;
}

int Closures::checkclosure(lua_State* L) {
    return l_isexecutorclosure(L);
}

int Closures::get_script_closure(lua_State* L) {
    lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "script_closure_stub");
    return 1;
}

int Closures::getscriptclosure(lua_State* L) {
    lua_pushcfunction(L, [](lua_State*) -> int { return 0; }, "script_closure_stub");
    return 1;
}

int Closures::compare_closures(lua_State* L) {
    lua_pushboolean(L, lua_rawequal(L, 1, 2));
    return 1;
}

int Closures::clone_function(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    lua_pushvalue(L, 1);  // upvalue – the function to clone
    lua_pushcclosure(L, [](lua_State* Ls) -> int {
        int nargs = lua_gettop(Ls);
        lua_pushvalue(Ls, lua_upvalueindex(1));
        for (int i = 1; i <= nargs; i++) lua_pushvalue(Ls, i);
        lua_call(Ls, nargs, LUA_MULTRET);
        return lua_gettop(Ls) - nargs;
    }, "cloned_fn", 1);
    return 1;
}

int Closures::get_calling_script(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

int Closures::newlclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    static const char* wrapper_src =
        "local f = ...\n"
        "return function(...)\n"
        "    return f(...)\n"
        "end\n";

    if (!compile_and_load(L, wrapper_src, "=newlclosure")) {
        luaL_error(L, "newlclosure: failed to compile wrapper");
        return 0;
    }

    lua_pushvalue(L, 1);          // pass original as arg
    lua_call(L, 1, 1);           // call wrapper builder → returns closure
    return 1;
}

// ═══════════════════════════════════════════════════════════════
//  File-System Closures
// ═══════════════════════════════════════════════════════════════

static bool path_safe(const std::string& path) {
    try {
        auto resolved  = std::filesystem::weakly_canonical(path);
        auto workspace = std::filesystem::weakly_canonical(WORKSPACE_DIR);
        return resolved.string().find(workspace.string()) == 0;
    } catch (...) { return false; }
}

int Closures::l_readfile(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    std::string path = get_workspace_path(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal detected"); return 0; }

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
    std::string path = get_workspace_path(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal detected"); return 0; }

    std::filesystem::path fp(path);
    if (fp.has_parent_path())
        std::filesystem::create_directories(fp.parent_path());

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) { luaL_error(L, "Cannot write file: %s", fn); return 0; }
    f.write(data, (std::streamsize)len);
    f.close();
    spdlog::debug("[Script] writefile: {} ({} bytes)", fn, len);
    return 0;
}

int Closures::l_isfile(lua_State* L) {
    lua_pushboolean(L, std::filesystem::is_regular_file(
        get_workspace_path(luaL_checkstring(L, 1))));
    return 1;
}

int Closures::l_isfolder(lua_State* L) {
    lua_pushboolean(L, std::filesystem::is_directory(
        get_workspace_path(luaL_checkstring(L, 1))));
    return 1;
}

int Closures::l_makefolder(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    std::string path = get_workspace_path(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal detected"); return 0; }
    std::filesystem::create_directories(path);
    return 0;
}

int Closures::l_listfiles(lua_State* L) {
    const char* fn = luaL_optstring(L, 1, "");
    std::string path = get_workspace_path(fn);

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
        spdlog::warn("[Script] listfiles error: {}", e.what());
    }
    return 1;
}

int Closures::l_delfile(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    std::string path = get_workspace_path(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal detected"); return 0; }
    try { std::filesystem::remove_all(path); }
    catch (const std::exception& e) { luaL_error(L, "Cannot delete: %s", e.what()); }
    return 0;
}

int Closures::l_appendfile(lua_State* L) {
    const char* fn = luaL_checkstring(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    std::string path = get_workspace_path(fn);
    if (!path_safe(path)) { luaL_error(L, "Path traversal detected"); return 0; }

    std::ofstream f(path, std::ios::binary | std::ios::app);
    if (!f.is_open()) { luaL_error(L, "Cannot append file: %s", fn); return 0; }
    f.write(data, (std::streamsize)len);
    f.close();
    return 0;
}

int Closures::l_setfpscap(lua_State* L) {
    int fps = (int)luaL_optinteger(L, 1, 60);
    spdlog::debug("[Script] setfpscap({})", fps);
    (void)fps;
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  Task-Library Closures
// ═══════════════════════════════════════════════════════════════

int Closures::l_task_wait(lua_State* L) {
    double sec = luaL_optnumber(L, 1, 0.03);
    if (sec < 0) sec = 0;
    if (sec > 30) sec = 30;

    auto start = std::chrono::steady_clock::now();
    if (sec < 0.001) {
        std::this_thread::yield();
    } else {
        double rem = sec;
        while (rem > 0) {
            double chunk = std::min(rem, 0.01);
            std::this_thread::sleep_for(std::chrono::duration<double>(chunk));
            rem -= chunk;
        }
    }
    double actual = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();
    lua_pushnumber(L, actual);
    return 1;
}

int Closures::l_task_spawn(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    lua_State* thr = lua_newthread(L);
    luaL_sandboxthread(thr);

    lua_pushvalue(L, 1);
    lua_xmove(L, thr, 1);

    int nargs = lua_gettop(L) - 2;  // -1 func, -1 thread
    for (int i = 2; i <= lua_gettop(L) - 1; i++)
        lua_pushvalue(L, i);
    if (nargs > 0) lua_xmove(L, thr, nargs);

    int status = lua_resume(thr, nullptr, nargs);
    if (status != 0 && status != LUA_YIELD) {
        const char* err = lua_tostring(thr, -1);
        spdlog::error("[Script] task.spawn error: {}",
                      err ? err : "unknown");
    }
    return 1;  // return thread
}

int Closures::l_task_defer(lua_State* L) {
    return l_task_spawn(L);   // simplified – runs immediately
}

int Closures::l_task_delay(lua_State* L) {
    double dt = luaL_checknumber(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (dt < 0)  dt = 0;
    if (dt > 30) dt = 30;

    if (dt > 0)
        std::this_thread::sleep_for(std::chrono::duration<double>(dt));

    lua_State* thr = lua_newthread(L);
    luaL_sandboxthread(thr);

    lua_pushvalue(L, 2);
    lua_xmove(L, thr, 1);
    lua_pushnumber(thr, dt);

    int status = lua_resume(thr, nullptr, 1);
    if (status != 0 && status != LUA_YIELD) {
        const char* err = lua_tostring(thr, -1);
        spdlog::error("[Script] task.delay error: {}",
                      err ? err : "unknown");
    }
    return 1;  // return thread
}

int Closures::l_task_cancel(lua_State* L) {
    if (!lua_isthread(L, 1)) {
        luaL_error(L, "Expected thread argument");
        return 0;
    }
    lua_State* thr = lua_tothread(L, 1);
    if (thr) lua_resetthread(thr);
    return 0;
}

} // namespace oss

