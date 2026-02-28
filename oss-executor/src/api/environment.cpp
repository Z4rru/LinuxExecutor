#include "environment.hpp"
#include "../core/lua_engine.hpp"
#include "../utils/http.hpp"
#include "../utils/logger.hpp"
#include "../ui/overlay.hpp"
#include "closures.hpp"
#include <cmath>
#include <cstring>
#include <sstream>
#include <map>
#include "Luau/Compiler.h"

// Luau compat: lua_pushcfunction requires 3 args; accept 2 or 3
#undef lua_pushcfunction
#define lua_pushcfunction(L, fn, ...) lua_pushcclosurek(L, fn, #fn, 0, NULL)

namespace oss {

// Luau compat: replaces luaL_dostring (compile + load + pcall)
static int oss_dostring(lua_State* L, const char* code, const char* name) {
    Luau::CompileOptions opts;
    opts.optimizationLevel = 1;
    std::string bc = Luau::compile(std::string(code), opts);
    if (bc.empty()) { lua_pushstring(L, "compile error"); return 1; }
    if (bc[0] == 0) { lua_pushstring(L, bc.c_str() + 1); return 1; }
    if (luau_load(L, name, bc.data(), bc.size(), 0) != 0) return 1;
    return lua_pcall(L, 0, 0, 0);
}

static int lua_typeof(lua_State* L) {
    if (lua_getmetatable(L, 1)) {
        lua_getfield(L, -1, "__type");
        if (lua_isstring(L, -1)) return 1;
        lua_pop(L, 2);
    }
    lua_pushstring(L, luaL_typename(L, 1));
    return 1;
}

static int lua_http_get(lua_State* L) {
    int url_index = 1;
    int arg1_type = lua_type(L, 1);
    if (arg1_type == LUA_TTABLE || arg1_type == LUA_TUSERDATA) url_index = 2;
    if (lua_gettop(L) < url_index) { luaL_error(L, "HttpGet: expected URL argument"); return 0; }
    const char* url = luaL_checkstring(L, url_index);
    if (!url || strlen(url) == 0) { luaL_error(L, "HttpGet: URL cannot be empty"); return 0; }
    std::string surl(url);
    if (surl.rfind("http://", 0) != 0 && surl.rfind("https://", 0) != 0)
        luaL_error(L, "HttpGet: URL must start with http:// or https://"); 
        return 0;
    try {
        auto response = Http::instance().get(surl);
        if (response.success()) {
            lua_pushlstring(L, response.body.data(), response.body.size());
        } else {
            luaL_error(L, "HttpGet failed: HTTP %ld for '%s'%s%s",
                response.status_code, surl.c_str(),
                response.error.empty() ? "" : " - ",
                response.error.empty() ? "" : response.error.c_str());
            return 0;
        }
    } catch (const std::exception& e) {
        luaL_error(L, "HttpGet exception: %s", e.what()); return 0;
    }
    return 1;
}

static int lua_http_request(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_getfield(L, 1, "Url");
    if (!lua_isstring(L, -1)) { lua_pop(L, 1); lua_getfield(L, 1, "url"); }
    const char* url = luaL_optstring(L, -1, "");
    lua_pop(L, 1);
    lua_getfield(L, 1, "Method");
    if (!lua_isstring(L, -1)) { lua_pop(L, 1); lua_getfield(L, 1, "method"); }
    std::string method = luaL_optstring(L, -1, "GET");
    lua_pop(L, 1);
    std::map<std::string, std::string> req_headers;
    lua_getfield(L, 1, "Headers");
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            if (lua_isstring(L, -2) && lua_isstring(L, -1))
                req_headers[lua_tostring(L, -2)] = lua_tostring(L, -1);
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);
    HttpResponse resp;
    if (method == "POST") {
        lua_getfield(L, 1, "Body");
        std::string body = luaL_optstring(L, -1, "");
        lua_pop(L, 1);
        resp = Http::instance().post(url, body, req_headers);
    } else {
        resp = Http::instance().get(url, req_headers);
    }
    lua_newtable(L);
    lua_pushinteger(L, static_cast<lua_Integer>(resp.status_code));
    lua_setfield(L, -2, "StatusCode");
    lua_pushlstring(L, resp.body.data(), resp.body.size());
    lua_setfield(L, -2, "Body");
    lua_pushboolean(L, resp.success());
    lua_setfield(L, -2, "Success");
    lua_newtable(L);
    for (const auto& [k, v] : resp.headers) {
        lua_pushstring(L, v.c_str());
        lua_setfield(L, -2, k.c_str());
    }
    lua_setfield(L, -2, "Headers");
    return 1;
}

static int lua_identify_executor(lua_State* L) {
    lua_pushstring(L, "OSS Executor");
    lua_pushstring(L, "2.0.0");
    return 2;
}

static int lua_drawing_new_bridge(lua_State* L) {
    int type_id = static_cast<int>(luaL_checkinteger(L, 1));
    auto type = static_cast<DrawingObject::Type>(type_id);
    int id = Overlay::instance().create_object(type);
    lua_pushinteger(L, id);
    return 1;
}

static int lua_drawing_set_bridge(lua_State* L) {
    int id = static_cast<int>(luaL_checkinteger(L, 1));
    const char* key = luaL_checkstring(L, 2);
    std::string k(key);

    auto read_vec2 = [L](int idx, double& x, double& y) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "X"); x = lua_tonumber(L, -1); lua_pop(L, 1);
            lua_getfield(L, idx, "Y"); y = lua_tonumber(L, -1); lua_pop(L, 1);
        }
    };
    auto read_color = [L](int idx, double& r, double& g, double& b) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "R"); r = lua_tonumber(L, -1); lua_pop(L, 1);
            lua_getfield(L, idx, "G"); g = lua_tonumber(L, -1); lua_pop(L, 1);
            lua_getfield(L, idx, "B"); b = lua_tonumber(L, -1); lua_pop(L, 1);
        }
    };

    Overlay::instance().update_object(id, [&](DrawingObject& obj) {
        if (k == "Visible") obj.visible = lua_toboolean(L, 3);
        else if (k == "Thickness") obj.thickness = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "Transparency") obj.transparency = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "ZIndex") obj.z_index = static_cast<int>(lua_tointeger(L, 3));
        else if (k == "Color") read_color(3, obj.color_r, obj.color_g, obj.color_b);
        else if (k == "OutlineColor") read_color(3, obj.outline_r, obj.outline_g, obj.outline_b);
        else if (k == "From") read_vec2(3, obj.from_x, obj.from_y);
        else if (k == "To") read_vec2(3, obj.to_x, obj.to_y);
        else if (k == "Position") read_vec2(3, obj.pos_x, obj.pos_y);
        else if (k == "PointA") read_vec2(3, obj.pa_x, obj.pa_y);
        else if (k == "PointB") read_vec2(3, obj.pb_x, obj.pb_y);
        else if (k == "PointC") read_vec2(3, obj.pc_x, obj.pc_y);
        else if (k == "Text") { if (lua_isstring(L, 3)) obj.text = lua_tostring(L, 3); }
        else if (k == "Size") {
            if (lua_isnumber(L, 3)) obj.text_size = static_cast<float>(lua_tonumber(L, 3));
            else if (lua_istable(L, 3)) read_vec2(3, obj.size_x, obj.size_y);
        }
        else if (k == "Center") obj.center = lua_toboolean(L, 3);
        else if (k == "Outline") obj.outline = lua_toboolean(L, 3);
        else if (k == "Filled") obj.filled = lua_toboolean(L, 3);
        else if (k == "Radius") obj.radius = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "NumSides") obj.num_sides = static_cast<int>(lua_tointeger(L, 3));
        else if (k == "Font") obj.font = static_cast<int>(lua_tointeger(L, 3));
        else if (k == "Rounding") obj.rounding = static_cast<float>(lua_tonumber(L, 3));
    });
    return 0;
}

static int lua_drawing_remove_bridge(lua_State* L) {
    int id = static_cast<int>(luaL_checkinteger(L, 1));
    Overlay::instance().remove_object(id);
    return 0;
}

// ── GUI Bridge Functions ──

static int lua_gui_create(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 1);
    const char* name = luaL_optstring(L, 2, class_name);
    int id = Overlay::instance().create_gui_element(class_name, name);
    lua_pushinteger(L, id);
    return 1;
}

static int lua_gui_set(lua_State* L) {
    int id = static_cast<int>(luaL_checkinteger(L, 1));
    const char* key = luaL_checkstring(L, 2);
    std::string k(key);

    auto read_color3 = [L](int idx, float& r, float& g, float& b) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "R"); r = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            lua_getfield(L, idx, "G"); g = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            lua_getfield(L, idx, "B"); b = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
        }
    };

    auto read_udim2 = [L](int idx, float& xs, float& xo, float& ys, float& yo) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "X");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "Scale"); xs = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
                lua_getfield(L, -1, "Offset"); xo = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            }
            lua_pop(L, 1);
            lua_getfield(L, idx, "Y");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "Scale"); ys = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
                lua_getfield(L, -1, "Offset"); yo = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }
    };

    auto read_udim = [L](int idx) -> float {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "Offset");
            float v = static_cast<float>(lua_tonumber(L, -1));
            lua_pop(L, 1);
            return v;
        }
        return 0;
    };

    auto read_vec2 = [L](int idx, float& x, float& y) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "X"); x = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            lua_getfield(L, idx, "Y"); y = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
        }
    };

    Overlay::instance().update_gui_element(id, [&](GuiElement& elem) {
        if (k == "Visible") elem.visible = lua_toboolean(L, 3);
        else if (k == "Name") { if (lua_isstring(L, 3)) elem.name = lua_tostring(L, 3); }
        else if (k == "BackgroundColor3") read_color3(3, elem.bg_r, elem.bg_g, elem.bg_b);
        else if (k == "BackgroundTransparency") elem.bg_transparency = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "BorderColor3") read_color3(3, elem.border_r, elem.border_g, elem.border_b);
        else if (k == "BorderSizePixel") elem.border_size = static_cast<int>(lua_tointeger(L, 3));
        else if (k == "Size") read_udim2(3, elem.size_x_scale, elem.size_x_offset, elem.size_y_scale, elem.size_y_offset);
        else if (k == "Position") read_udim2(3, elem.pos_x_scale, elem.pos_x_offset, elem.pos_y_scale, elem.pos_y_offset);
        else if (k == "AnchorPoint") read_vec2(3, elem.anchor_x, elem.anchor_y);
        else if (k == "Rotation") elem.rotation = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "ClipsDescendants") elem.clips_descendants = lua_toboolean(L, 3);
        else if (k == "ZIndex") elem.z_index = static_cast<int>(lua_tointeger(L, 3));
        else if (k == "LayoutOrder") elem.layout_order = static_cast<int>(lua_tointeger(L, 3));
        else if (k == "Text") { if (lua_isstring(L, 3)) elem.text = lua_tostring(L, 3); }
        else if (k == "TextColor3") read_color3(3, elem.text_r, elem.text_g, elem.text_b);
        else if (k == "TextSize") elem.text_size = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "TextTransparency") elem.text_transparency = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "TextStrokeTransparency") elem.text_stroke_transparency = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "TextStrokeColor3") read_color3(3, elem.text_stroke_r, elem.text_stroke_g, elem.text_stroke_b);
        else if (k == "TextWrapped") elem.text_wrapped = lua_toboolean(L, 3);
        else if (k == "TextScaled") elem.text_scaled = lua_toboolean(L, 3);
        else if (k == "RichText") elem.rich_text = lua_toboolean(L, 3);
        else if (k == "TextXAlignment") {
            // Handle Enum value
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Value");
                if (lua_isnumber(L, -1)) elem.text_x_alignment = static_cast<int>(lua_tointeger(L, -1));
                lua_pop(L, 1);
                lua_getfield(L, 3, "Name");
                if (lua_isstring(L, -1)) {
                    std::string n = lua_tostring(L, -1);
                    if (n == "Left") elem.text_x_alignment = 0;
                    else if (n == "Center") elem.text_x_alignment = 1;
                    else if (n == "Right") elem.text_x_alignment = 2;
                }
                lua_pop(L, 1);
            } else if (lua_isnumber(L, 3)) {
                elem.text_x_alignment = static_cast<int>(lua_tointeger(L, 3));
            }
        }
        else if (k == "TextYAlignment") {
            if (lua_istable(L, 3)) {
                lua_getfield(L, 3, "Name");
                if (lua_isstring(L, -1)) {
                    std::string n = lua_tostring(L, -1);
                    if (n == "Top") elem.text_y_alignment = 0;
                    else if (n == "Center") elem.text_y_alignment = 1;
                    else if (n == "Bottom") elem.text_y_alignment = 2;
                }
                lua_pop(L, 1);
            } else if (lua_isnumber(L, 3)) {
                elem.text_y_alignment = static_cast<int>(lua_tointeger(L, 3));
            }
        }
        else if (k == "Image") { if (lua_isstring(L, 3)) elem.image = lua_tostring(L, 3); }
        else if (k == "ImageColor3") read_color3(3, elem.image_r, elem.image_g, elem.image_b);
        else if (k == "ImageTransparency") elem.image_transparency = static_cast<float>(lua_tonumber(L, 3));
        else if (k == "Enabled") elem.enabled = lua_toboolean(L, 3);
        else if (k == "DisplayOrder") elem.display_order = static_cast<int>(lua_tointeger(L, 3));
        else if (k == "IgnoreGuiInset") elem.ignore_gui_inset = lua_toboolean(L, 3);
        else if (k == "ResetOnSpawn") { /* accepted, no effect */ }
        else if (k == "Active") { /* accepted, no effect in overlay */ }
        else if (k == "Selectable") { /* accepted, no effect in overlay */ }
        else if (k == "Font") { /* accepted, future: map font enum */ }
        else if (k == "AutomaticSize") { /* accepted, future: auto sizing */ }
        else if (k == "CornerRadius") {
            // UICorner's CornerRadius is a UDim
            elem.corner_radius = read_udim(3);
        }
        else if (k == "Thickness") {
            // UIStroke
            elem.stroke_thickness = static_cast<float>(lua_tonumber(L, 3));
            elem.has_stroke = true;
        }
        else if (k == "Color") {
            // UIStroke Color or UIGradient - context dependent
            // For UIStroke applied to parent:
            if (elem.class_name == "UIStroke") {
                read_color3(3, elem.stroke_r, elem.stroke_g, elem.stroke_b);
            }
        }
        else if (k == "Transparency" && elem.class_name == "UIStroke") {
            elem.stroke_transparency = static_cast<float>(lua_tonumber(L, 3));
        }
        else if (k == "PaddingTop") elem.pad_top = read_udim(3);
        else if (k == "PaddingBottom") elem.pad_bottom = read_udim(3);
        else if (k == "PaddingLeft") elem.pad_left = read_udim(3);
        else if (k == "PaddingRight") elem.pad_right = read_udim(3);
        else if (k == "Padding") {
            // UIListLayout Padding (UDim)
            float p = read_udim(3);
            elem.pad_top = p;
        }
        else if (k == "CanvasSize") {
            float dummy_xs = 0, dummy_xo = 0, ys = 0, yo = 0;  // ← initialized
            read_udim2(3, dummy_xs, dummy_xo, ys, yo);
            elem.canvas_size_y = yo;
        }
        else if (k == "CanvasPosition") {
            float sx = 0, sy = 0;  // ← initialized
            read_vec2(3, sx, sy);
            elem.scroll_position = sy;
        }
        else if (k == "ScrollingEnabled") elem.scrolling_enabled = lua_toboolean(L, 3);
        // Silently accept other properties without error
    });
    return 0;
}

static int lua_gui_set_parent(lua_State* L) {
    int child_id = static_cast<int>(luaL_checkinteger(L, 1));
    int parent_id = static_cast<int>(luaL_checkinteger(L, 2));
    Overlay::instance().set_gui_parent(child_id, parent_id);
    return 0;
}

static int lua_gui_remove(lua_State* L) {
    int id = static_cast<int>(luaL_checkinteger(L, 1));
    Overlay::instance().remove_gui_element(id);
    return 0;
}

static int lua_gui_clear(lua_State* L) {
    (void)L;
    Overlay::instance().clear_gui_elements();
    return 0;
}

static int lua_gui_get_screen_size(lua_State* L) {
    lua_pushinteger(L, Overlay::instance().screen_width());
    lua_pushinteger(L, Overlay::instance().screen_height());
    return 2;
}

// ── Debug functions ──

static int lua_debug_getinfo(lua_State* L) {
    lua_Debug ar;
    memset(&ar, 0, sizeof(ar));

    if (lua_isnumber(L, 1)) {
        int level = static_cast<int>(lua_tointeger(L, 1));
        if (!lua_getinfo(L, level, "slna", &ar)) {
            lua_pushnil(L);
            return 1;
        }
    } else if (lua_isfunction(L, 1)) {
        lua_pushvalue(L, 1);
        lua_getinfo(L, -1, "slna", &ar);
        lua_pop(L, 1);
    } else {
        luaL_error(L, "debug.getinfo: expected number or function");
        return 0;
    }

    lua_newtable(L);

    if (ar.source) {
        lua_pushstring(L, ar.source);
        lua_setfield(L, -2, "source");
        lua_pushstring(L, ar.short_src);
        lua_setfield(L, -2, "short_src");
    }
    if (ar.name) {
        lua_pushstring(L, ar.name);
        lua_setfield(L, -2, "name");
    }
    if (ar.what) {
        lua_pushstring(L, ar.what);
        lua_setfield(L, -2, "what");
    }
    lua_pushinteger(L, ar.currentline);
    lua_setfield(L, -2, "currentline");
    lua_pushinteger(L, ar.linedefined);
    lua_setfield(L, -2, "linedefined");
    lua_pushinteger(L, ar.nupvals);
    lua_setfield(L, -2, "nups");
    lua_pushinteger(L, ar.nparams);
    lua_setfield(L, -2, "numparams");
    lua_pushboolean(L, ar.isvararg);
    lua_setfield(L, -2, "is_vararg");

    return 1;
}

static int lua_debug_getupvalue(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int idx = static_cast<int>(luaL_checkinteger(L, 2));
    const char* name = lua_getupvalue(L, 1, idx);
    if (name) {
        lua_pushstring(L, name);
        lua_insert(L, -2);
        return 2;
    }
    lua_pushnil(L);
    return 1;
}

static int lua_debug_setupvalue(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int idx = static_cast<int>(luaL_checkinteger(L, 2));
    luaL_checkany(L, 3);
    lua_pushvalue(L, 3);
    const char* name = lua_setupvalue(L, 1, idx);
    if (name) {
        lua_pushstring(L, name);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

static int lua_debug_getupvalues(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_newtable(L);
    int idx = 1;
    while (true) {
        const char* name = lua_getupvalue(L, 1, idx);
        if (!name) break;
        lua_rawseti(L, -2, idx);
        ++idx;
    }
    return 1;
}

static int lua_debug_setupvalues(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checktype(L, 2, LUA_TTABLE);
    int idx = 1;
    lua_pushnil(L);
    while (lua_next(L, 2)) {
        lua_pushvalue(L, -1);
        lua_setupvalue(L, 1, idx);
        lua_pop(L, 1);
        ++idx;
    }
    return 0;
}

static int lua_debug_getconstant(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checkinteger(L, 2);
    lua_pushnil(L);
    return 1;
}

static int lua_debug_getconstants(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_newtable(L);
    return 1;
}

static int lua_debug_setconstant(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checkinteger(L, 2);
    luaL_checkany(L, 3);
    return 0;
}

static int lua_debug_getproto(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checkinteger(L, 2);
    lua_pushnil(L);
    return 1;
}

static int lua_debug_getprotos(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_newtable(L);
    return 1;
}

static int lua_debug_getstack(lua_State* L) {
    int level = static_cast<int>(luaL_checkinteger(L, 1));
    int idx = static_cast<int>(luaL_optinteger(L, 2, 0));

    if (idx > 0) {
        const char* name = lua_getlocal(L, level, idx);
        if (name) return 1;
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    int i = 1;
    while (true) {
        const char* name = lua_getlocal(L, level, i);
        if (!name) break;
        lua_setfield(L, -2, name);
        ++i;
    }
    return 1;
}

static int lua_debug_setstack(lua_State* L) {
    int level = static_cast<int>(luaL_checkinteger(L, 1));
    int idx = static_cast<int>(luaL_checkinteger(L, 2));
    luaL_checkany(L, 3);

    lua_pushvalue(L, 3);
    lua_setlocal(L, level, idx);
    return 0;
}

static int lua_debug_getmetatable(lua_State* L) {
    luaL_checkany(L, 1);
    if (!lua_getmetatable(L, 1))
        lua_pushnil(L);
    return 1;
}

static int lua_debug_setmetatable(lua_State* L) {
    luaL_checkany(L, 1);
    if (lua_isnoneornil(L, 2))
        lua_pushnil(L);
    else
        luaL_checktype(L, 2, LUA_TTABLE);
    lua_setmetatable(L, 1);
    lua_pushvalue(L, 1);
    return 1;
}

static int lua_debug_getregistry(lua_State* L) {
    lua_pushvalue(L, LUA_REGISTRYINDEX);
    return 1;
}

static int lua_debug_traceback(lua_State* L) {
    const char* msg = luaL_optstring(L, 1, "");
    lua_pushstring(L, msg);
    return 1;
}

static int lua_debug_profilebegin(lua_State* L) {
    (void)luaL_checkstring(L, 1);
    return 0;
}

static int lua_debug_profileend(lua_State*) {
    return 0;
}

static int lua_cache_invalidate(lua_State* L) {
    luaL_checkany(L, 1);
    return 0;
}

static int lua_cache_iscached(lua_State* L) {
    luaL_checkany(L, 1);
    lua_pushboolean(L, 0);
    return 1;
}

static int lua_cache_replace(lua_State* L) {
    luaL_checkany(L, 1);
    luaL_checkany(L, 2);
    return 0;
}

static int lua_getrawmetatable(lua_State* L) {
    luaL_checkany(L, 1);
    if (!lua_getmetatable(L, 1))
        lua_pushnil(L);
    return 1;
}

static int lua_setrawmetatable(lua_State* L) {
    luaL_checkany(L, 1);
    if (lua_isnoneornil(L, 2))
        lua_pushnil(L);
    else
        luaL_checktype(L, 2, LUA_TTABLE);
    lua_setmetatable(L, 1);
    lua_pushvalue(L, 1);
    return 1;
}

static int lua_setreadonly(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    bool readonly = lua_toboolean(L, 2);

    lua_getfield(L, LUA_REGISTRYINDEX, "__readonly_tables");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, "__readonly_tables");
    }

    lua_pushvalue(L, 1);
    if (readonly)
        lua_pushboolean(L, 1);
    else
        lua_pushnil(L);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    return 0;
}

static int lua_isreadonly(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    lua_getfield(L, LUA_REGISTRYINDEX, "__readonly_tables");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_pushvalue(L, 1);
    lua_rawget(L, -2);
    lua_pushboolean(L, lua_toboolean(L, -1));
    return 1;
}

static int lua_getnamecallmethod(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "__namecall_method");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_pushstring(L, "");
    }
    return 1;
}

static int lua_getconnections(lua_State* L) {
    lua_newtable(L);
    return 1;
}

static int lua_fireclickdetector(lua_State*) { return 0; }
static int lua_firetouchinterest(lua_State*) { return 0; }
static int lua_fireproximityprompt(lua_State*) { return 0; }
static int lua_setfpscap(lua_State*) { return 0; }

static int lua_getfps(lua_State* L) {
    lua_pushinteger(L, 60);
    return 1;
}

static int lua_getgenv(lua_State* L) {
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

static int lua_getrenv(lua_State* L) {
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

static int lua_getreg(lua_State* L) {
    lua_pushvalue(L, LUA_REGISTRYINDEX);
    return 1;
}

static int lua_getgc(lua_State* L) {
    lua_newtable(L);
    return 1;
}

static int lua_gethui(lua_State* L) {
    lua_getglobal(L, "game");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        return 1;
    }
    lua_getfield(L, -1, "GetService");
    lua_pushvalue(L, -2);
    lua_pushstring(L, "CoreGui");
    lua_call(L, 2, 1);
    lua_remove(L, -2); // Fix: remove 'game' from beneath result
    return 1;
}

static int lua_getinstances(lua_State* L) {
    lua_newtable(L);
    return 1;
}

static int lua_getnilinstances(lua_State* L) {
    lua_newtable(L);
    return 1;
}

static int lua_getscripts(lua_State* L) {
    lua_newtable(L);
    return 1;
}

static int lua_getrunningscripts(lua_State* L) {
    lua_newtable(L);
    return 1;
}

static int lua_getloadedmodules(lua_State* L) {
    lua_newtable(L);
    return 1;
}

static int lua_getcallingscript(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

static int lua_printidentity(lua_State* L) {
    lua_pushstring(L, "Current identity is 7");
    return 1;
}

static int lua_isfolder(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    lua_getglobal(L, "listfiles");
    if (lua_isfunction(L, -1)) {
        lua_pushstring(L, path);
        int status = lua_pcall(L, 1, 1, 0);
        if (status == 0 && lua_istable(L, -1)) {
            lua_pushboolean(L, 1);
            return 1;
        }
    }
    lua_settop(L, 1);
    lua_pushboolean(L, 0);
    return 1;
}

static int lua_delfile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    (void)path;
    return 0;
}

static int lua_websocket_connect(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    (void)url;

    lua_newtable(L);

    lua_newtable(L);
    lua_setfield(L, -2, "OnMessage");

    lua_newtable(L);
    lua_setfield(L, -2, "OnClose");

    lua_pushcfunction(L, [](lua_State* Ls) -> int {
        (void)Ls;
        return 0;
    });
    lua_setfield(L, -2, "Send");

    lua_pushcfunction(L, [](lua_State* Ls) -> int {
        (void)Ls;
        return 0;
    });
    lua_setfield(L, -2, "Close");

    return 1;
}

// ── The Roblox mock Lua code ──
// Now with GUI bridge integration: Instance.new for GUI classes calls
// _oss_gui_create, property writes call _oss_gui_set, Parent assignment
// calls _oss_gui_set_parent, and Destroy calls _oss_gui_remove.

static const char* ROBLOX_MOCK_LUA = R"LUA(

local Signal={}
Signal.__index=Signal
Signal.__type="RBXScriptSignal"
function Signal.new(name)
    return setmetatable({_name=name or "Signal",_connections={}},Signal)
end
function Signal:Connect(fn)
    if type(fn)~="function" then return end
    local conn=setmetatable({Connected=true,_fn=fn,_signal=self},{
        __type="RBXScriptConnection",
        __index={Disconnect=function(self) self.Connected=false end}
    })
    table.insert(self._connections,conn)
    return conn
end
Signal.connect=Signal.Connect
function Signal:Wait() return 0 end
function Signal:Fire(...)
    for _,conn in ipairs(self._connections) do
        if conn.Connected then pcall(conn._fn,...) end
    end
end

local Vector3={}
Vector3.__type="Vector3"
function Vector3.new(x,y,z)
    return setmetatable({
        X=x or 0,Y=y or 0,Z=z or 0,x=x or 0,y=y or 0,z=z or 0,
        Magnitude=math.sqrt((x or 0)^2+(y or 0)^2+(z or 0)^2)
    },Vector3)
end
Vector3.zero=Vector3.new(0,0,0)
Vector3.one=Vector3.new(1,1,1)
function Vector3:Lerp(g,a) return Vector3.new(self.X+(g.X-self.X)*a,self.Y+(g.Y-self.Y)*a,self.Z+(g.Z-self.Z)*a) end
function Vector3:Dot(o) return self.X*o.X+self.Y*o.Y+self.Z*o.Z end
function Vector3:Cross(o) return Vector3.new(self.Y*o.Z-self.Z*o.Y,self.Z*o.X-self.X*o.Z,self.X*o.Y-self.Y*o.X) end
function Vector3.__add(a,b) return Vector3.new(a.X+b.X,a.Y+b.Y,a.Z+b.Z) end
function Vector3.__sub(a,b) return Vector3.new(a.X-b.X,a.Y-b.Y,a.Z-b.Z) end
function Vector3.__mul(a,b)
    if type(a)=="number" then return Vector3.new(a*b.X,a*b.Y,a*b.Z) end
    if type(b)=="number" then return Vector3.new(a.X*b,a.Y*b,a.Z*b) end
    return Vector3.new(a.X*b.X,a.Y*b.Y,a.Z*b.Z)
end
function Vector3.__div(a,b)
    if type(b)=="number" then return Vector3.new(a.X/b,a.Y/b,a.Z/b) end
    return Vector3.new(a.X/b.X,a.Y/b.Y,a.Z/b.Z)
end
function Vector3.__unm(a) return Vector3.new(-a.X,-a.Y,-a.Z) end
function Vector3.__eq(a,b) return a.X==b.X and a.Y==b.Y and a.Z==b.Z end
function Vector3.__tostring(v) return string.format("%.4f, %.4f, %.4f",v.X,v.Y,v.Z) end
function Vector3.__len(v) return v.Magnitude end
Vector3.__index=function(self,key)
    if key=="Unit" then
        local m=self.Magnitude
        if m==0 then return Vector3.new(0,0,0) end
        return Vector3.new(self.X/m,self.Y/m,self.Z/m)
    end
    return rawget(Vector3,key)
end

local Vector2={}
Vector2.__type="Vector2"
function Vector2.new(x,y)
    return setmetatable({X=x or 0,Y=y or 0,x=x or 0,y=y or 0,
        Magnitude=math.sqrt((x or 0)^2+(y or 0)^2)},Vector2)
end
Vector2.zero=Vector2.new(0,0)
Vector2.one=Vector2.new(1,1)
function Vector2.__add(a,b) return Vector2.new(a.X+b.X,a.Y+b.Y) end
function Vector2.__sub(a,b) return Vector2.new(a.X-b.X,a.Y-b.Y) end
function Vector2.__mul(a,b)
    if type(a)=="number" then return Vector2.new(a*b.X,a*b.Y) end
    if type(b)=="number" then return Vector2.new(a.X*b,a.Y*b) end
    return Vector2.new(a.X*b.X,a.Y*b.Y)
end
function Vector2.__div(a,b)
    if type(b)=="number" then return Vector2.new(a.X/b,a.Y/b) end
    return Vector2.new(a.X/b.X,a.Y/b.Y)
end
function Vector2.__tostring(v) return string.format("%.4f, %.4f",v.X,v.Y) end
Vector2.__index=function(self,key)
    if key=="Unit" then
        local m=self.Magnitude
        if m==0 then return Vector2.new(0,0) end
        return Vector2.new(self.X/m,self.Y/m)
    end
    return rawget(Vector2,key)
end

local Color3={}
Color3.__index=Color3
Color3.__type="Color3"
function Color3.new(r,g,b) return setmetatable({R=r or 0,G=g or 0,B=b or 0},Color3) end
function Color3.fromRGB(r,g,b) return Color3.new((r or 0)/255,(g or 0)/255,(b or 0)/255) end
function Color3.fromHSV(h,s,v)
    local c=v*s local x=c*(1-math.abs((h*6)%2-1)) local m=v-c
    local r,g,b=m,m,m local sector=math.floor(h*6)%6
    if sector==0 then r,g=r+c,g+x elseif sector==1 then r,g=r+x,g+c
    elseif sector==2 then g,b=g+c,b+x elseif sector==3 then g,b=g+x,b+c
    elseif sector==4 then r,b=r+x,b+c else r,b=r+c,b+x end
    return Color3.new(r,g,b)
end
function Color3:Lerp(goal,alpha)
    return Color3.new(self.R+(goal.R-self.R)*alpha,self.G+(goal.G-self.G)*alpha,self.B+(goal.B-self.B)*alpha)
end
function Color3:ToHSV()
    local r,g,b=self.R,self.G,self.B local max=math.max(r,g,b) local min=math.min(r,g,b)
    local d=max-min local h,s,v=0,(max==0) and 0 or d/max,max
    if d>0 then
        if max==r then h=(g-b)/d%6 elseif max==g then h=(b-r)/d+2 else h=(r-g)/d+4 end
        h=h/6
    end
    return h,s,v
end
function Color3.__tostring(c) return string.format("%.4f, %.4f, %.4f",c.R,c.G,c.B) end
function Color3.__eq(a,b) return a.R==b.R and a.G==b.G and a.B==b.B end

local UDim={}
UDim.__index=UDim
UDim.__type="UDim"
function UDim.new(s,o) return setmetatable({Scale=s or 0,Offset=o or 0},UDim) end

local UDim2={}
UDim2.__index=UDim2
UDim2.__type="UDim2"
function UDim2.new(xs,xo,ys,yo)
    return setmetatable({X=UDim.new(xs or 0,xo or 0),Y=UDim.new(ys or 0,yo or 0),
        Width=UDim.new(xs or 0,xo or 0),Height=UDim.new(ys or 0,yo or 0)},UDim2)
end
function UDim2.fromScale(xs,ys) return UDim2.new(xs,0,ys,0) end
function UDim2.fromOffset(xo,yo) return UDim2.new(0,xo,0,yo) end
function UDim2.__tostring(u) return string.format("{%g, %d}, {%g, %d}",u.X.Scale,u.X.Offset,u.Y.Scale,u.Y.Offset) end

local CFrame={}
CFrame.__index=CFrame
CFrame.__type="CFrame"
function CFrame.new(x,y,z)
    if type(x)=="table" and x.X then
        return setmetatable({Position=x,X=x.X,Y=x.Y,Z=x.Z,
            LookVector=Vector3.new(0,0,-1),RightVector=Vector3.new(1,0,0),
            UpVector=Vector3.new(0,1,0),p=x},CFrame)
    end
    local pos=Vector3.new(x or 0,y or 0,z or 0)
    return setmetatable({Position=pos,X=pos.X,Y=pos.Y,Z=pos.Z,
        LookVector=Vector3.new(0,0,-1),RightVector=Vector3.new(1,0,0),
        UpVector=Vector3.new(0,1,0),p=pos},CFrame)
end
CFrame.identity=CFrame.new(0,0,0)
function CFrame:Inverse() return CFrame.new(-self.X,-self.Y,-self.Z) end
function CFrame:Lerp(g,a) return CFrame.new(self.X+(g.X-self.X)*a,self.Y+(g.Y-self.Y)*a,self.Z+(g.Z-self.Z)*a) end
function CFrame:PointToWorldSpace(v) return Vector3.new(self.X+v.X,self.Y+v.Y,self.Z+v.Z) end
function CFrame:PointToObjectSpace(v) return Vector3.new(v.X-self.X,v.Y-self.Y,v.Z-self.Z) end
function CFrame:ToEulerAnglesXYZ() return 0,0,0 end
function CFrame:ToEulerAnglesYXZ() return 0,0,0 end
function CFrame:ToOrientation() return 0,0,0 end
function CFrame:GetComponents() return self.X,self.Y,self.Z,1,0,0,0,1,0,0,0,1 end
function CFrame.lookAt(pos,target,up)
    up=up or Vector3.new(0,1,0)
    local cf=CFrame.new(pos.X,pos.Y,pos.Z)
    local dir=target-pos
    local m=dir.Magnitude
    if m>0 then rawset(cf,"LookVector",Vector3.new(dir.X/m,dir.Y/m,dir.Z/m))
    else rawset(cf,"LookVector",Vector3.new(0,0,-1)) end
    return cf
end
function CFrame.__mul(a,b)
    if getmetatable(b)==Vector3 then return Vector3.new(a.X+b.X,a.Y+b.Y,a.Z+b.Z) end
    return CFrame.new(a.X+b.X,a.Y+b.Y,a.Z+b.Z)
end
function CFrame.__tostring(cf) return string.format("%.4f, %.4f, %.4f, ...",cf.X,cf.Y,cf.Z) end

local _instance_events={}
for _,v in ipairs({
    "Changed","ChildAdded","ChildRemoved","AncestryChanged","Destroying",
    "MouseButton1Click","MouseButton1Down","MouseButton1Up",
    "MouseButton2Click","MouseButton2Down","MouseButton2Up",
    "MouseEnter","MouseLeave","MouseMoved","MouseWheelForward","MouseWheelBackward",
    "InputBegan","InputEnded","InputChanged",
    "TouchTap","TouchLongPress","TouchPan","TouchPinch","TouchRotate","TouchSwipe",
    "Activated","Deactivated","FocusLost","FocusGained",
    "Touched","TouchEnded","SelectionGained","SelectionLost",
    "CharacterAdded","CharacterRemoving","CharacterAppearanceLoaded",
    "PlayerAdded","PlayerRemoving","RenderStepped","Heartbeat","Stepped",
    "TextChanged","ReturnPressedFromOnScreenKeyboard"
}) do _instance_events[v]=true end

-- GUI class set for overlay bridge
local _gui_classes={
    ScreenGui=true,BillboardGui=true,SurfaceGui=true,
    Frame=true,TextLabel=true,TextButton=true,TextBox=true,
    ImageLabel=true,ImageButton=true,ScrollingFrame=true,
    ViewportFrame=true,CanvasGroup=true,
    UICorner=true,UIStroke=true,UIGradient=true,UIPadding=true,
    UIListLayout=true,UIGridLayout=true,UIScale=true,
    UIAspectRatioConstraint=true,UISizeConstraint=true,UITextSizeConstraint=true
}

-- Properties that should be forwarded to the C++ overlay bridge
local _gui_bridge_props={
    Visible=true,Name=true,
    BackgroundColor3=true,BackgroundTransparency=true,
    BorderColor3=true,BorderSizePixel=true,
    Size=true,Position=true,AnchorPoint=true,
    Rotation=true,ClipsDescendants=true,ZIndex=true,LayoutOrder=true,
    Text=true,TextColor3=true,TextSize=true,TextTransparency=true,
    TextStrokeTransparency=true,TextStrokeColor3=true,
    TextWrapped=true,TextScaled=true,RichText=true,
    TextXAlignment=true,TextYAlignment=true,
    Image=true,ImageColor3=true,ImageTransparency=true,
    Enabled=true,DisplayOrder=true,IgnoreGuiInset=true,
    ResetOnSpawn=true,Active=true,Selectable=true,Font=true,
    AutomaticSize=true,CornerRadius=true,Thickness=true,Color=true,
    Transparency=true,PaddingTop=true,PaddingBottom=true,
    PaddingLeft=true,PaddingRight=true,Padding=true,
    CanvasSize=true,CanvasPosition=true,ScrollingEnabled=true,
    SortOrder=true,FillDirection=true,
    HorizontalAlignment=true,VerticalAlignment=true,
}

local function make_instance(class_name,name,parent)
    local children={}
    local properties={}
    local events={}
    local inst={}
    local is_gui = _gui_classes[class_name] or false
    local gui_id = 0

    -- Create overlay element for GUI classes
    if is_gui and _oss_gui_create then
        gui_id = _oss_gui_create(class_name, name or class_name)
    end

    local mt={__type="Instance",__tostring=function() return name or class_name end}

    local function find_child(_,child_name)
        for _,c in ipairs(children) do
            if type(c)=="table" then
                if c.Name==child_name or tostring(c)==child_name then return c end
            elseif tostring(c)==child_name then return c end
        end
        return nil
    end

    mt.__index=function(self,key)
        if key=="Name" then return name or class_name end
        if key=="ClassName" then return class_name end
        if key=="Parent" then return parent end
        if key=="_gui_id" then return gui_id end
        if key=="IsA" then return function(_,check) return check==class_name or check=="Instance" or check=="GuiObject" or check=="BasePart" end end
        if key=="FindFirstChild" then return find_child end
        if key=="FindFirstChildOfClass" then
            return function(_,cls)
                for _,c in ipairs(children) do
                    if type(c)=="table" and c.ClassName==cls then return c end
                end
                return nil
            end
        end
        if key=="FindFirstChildWhichIsA" then
            return function(_,cls)
                for _,c in ipairs(children) do
                    if type(c)=="table" then
                        local isa=c.IsA
                        if isa and isa(c,cls) then return c end
                        if c.ClassName==cls then return c end
                    end
                end
                return nil
            end
        end
        if key=="FindFirstAncestor" then
            return function(self2,n)
                local p=parent
                while p do
                    if type(p)=="table" and (p.Name==n or tostring(p)==n) then return p end
                    p=type(p)=="table" and p.Parent or nil
                end
                return nil
            end
        end
        if key=="FindFirstAncestorOfClass" then
            return function(self2,cls)
                local p=parent
                while p do
                    if type(p)=="table" and p.ClassName==cls then return p end
                    p=type(p)=="table" and p.Parent or nil
                end
                return nil
            end
        end
        if key=="WaitForChild" then return find_child end
        if key=="GetChildren" or key=="getChildren" then return function() return children end end
        if key=="GetDescendants" then
            return function()
                local result={}
                local function collect(list)
                    for _,c in ipairs(list) do
                        table.insert(result,c)
                        if type(c)=="table" then
                            local gc=c.GetChildren
                            if gc then collect(gc()) end
                        end
                    end
                end
                collect(children)
                return result
            end
        end
        if key=="Clone" then return function() return make_instance(class_name,name,nil) end end
        if key=="Destroy" or key=="Remove" then
            return function()
                if is_gui and gui_id>0 and _oss_gui_remove then
                    pcall(_oss_gui_remove, gui_id)
                end
                -- Remove from parent's children
                if parent and type(parent)=="table" then
                    local pc=rawget(parent,"_children")
                    if pc then
                        for i=#pc,1,-1 do
                            if pc[i]==inst then table.remove(pc,i) break end
                        end
                    end
                end
                parent=nil
            end
        end
        if key=="ClearAllChildren" then
            return function()
                for _,c in ipairs(children) do
                    if type(c)=="table" then
                        local d=c.Destroy
                        if d then pcall(d) end
                    end
                end
                children={}
            end
        end
        if key=="GetFullName" then
            return function()
                local parts={name or class_name}
                local p=parent
                while p do
                    if type(p)=="table" then
                        table.insert(parts,1,p.Name or tostring(p))
                        p=p.Parent
                    else break end
                end
                return table.concat(parts,".")
            end
        end
        if key=="GetPropertyChangedSignal" then
            return function(_,prop_name)
                local sig_key="_PropChanged_"..tostring(prop_name or "")
                if not events[sig_key] then events[sig_key]=Signal.new(sig_key) end
                return events[sig_key]
            end
        end
        if key=="GetAttribute" then return function(_,attr) return properties["_attr_"..tostring(attr)] end end
        if key=="SetAttribute" then return function(_,attr,val) properties["_attr_"..tostring(attr)]=val end end
        if key=="GetAttributes" then
            return function()
                local attrs={}
                for k,v in pairs(properties) do
                    if k:sub(1,6)=="_attr_" then attrs[k:sub(7)]=v end
                end
                return attrs
            end
        end
        if key=="GetAttributeChangedSignal" then
            return function(_,attr)
                local sig_key="_AttrChanged_"..tostring(attr)
                if not events[sig_key] then events[sig_key]=Signal.new(sig_key) end
                return events[sig_key]
            end
        end
        if properties[key]~=nil then return properties[key] end
        if _instance_events[key] then
            if not events[key] then events[key]=Signal.new(key) end
            return events[key]
        end
        local child=find_child(nil,key)
        if child then return child end
        return nil
    end

    mt.__newindex=function(self,key,value)
        if key=="Name" then
            name=value
            if is_gui and gui_id>0 and _oss_gui_set then
                pcall(_oss_gui_set, gui_id, "Name", value)
            end
        elseif key=="Parent" then
            -- Remove from old parent's children list
            if parent and type(parent)=="table" then
                local pc=rawget(parent,"_children")
                if pc then
                    for i=#pc,1,-1 do
                        if pc[i]==inst then table.remove(pc,i) break end
                    end
                end
            end
            parent=value
            if type(value)=="table" then
                local gc=rawget(value,"_children")
                if gc then table.insert(gc,inst) end
            end
            -- Bridge: set parent in overlay
            if is_gui and gui_id>0 and _oss_gui_set_parent then
                local parent_gui_id=0
                if type(value)=="table" then
                    local pgid=value._gui_id
                    if pgid and pgid>0 then parent_gui_id=pgid end
                end
                pcall(_oss_gui_set_parent, gui_id, parent_gui_id)
            end
        else
            properties[key]=value
            -- Bridge: forward GUI property changes to overlay
            if is_gui and gui_id>0 and _oss_gui_set and _gui_bridge_props[key] then
                pcall(_oss_gui_set, gui_id, key, value)
            end
            -- If this is a UICorner/UIStroke/UIPadding being modified,
            -- also update the parent in the overlay
            if is_gui and gui_id>0 and parent and type(parent)=="table" then
                local pgid=parent._gui_id
                if pgid and pgid>0 and _oss_gui_set then
                    if class_name=="UICorner" and key=="CornerRadius" then
                        pcall(_oss_gui_set, pgid, "CornerRadius", value)
                    elseif class_name=="UIStroke" then
                        if key=="Thickness" or key=="Color" or key=="Transparency" then
                            pcall(_oss_gui_set, pgid, key, value)
                        end
                    elseif class_name=="UIPadding" then
                        if key=="PaddingTop" or key=="PaddingBottom" or key=="PaddingLeft" or key=="PaddingRight" then
                            pcall(_oss_gui_set, pgid, key, value)
                        end
                    end
                end
            end
            -- Fire property changed signal
            local sig_key="_PropChanged_"..key
            if events[sig_key] then events[sig_key]:Fire(value) end
        end
    end
    rawset(inst,"_children",children)
    rawset(inst,"_gui_id_raw",gui_id)
    setmetatable(inst,mt)
    return inst,children,properties
end

local EnumMock=setmetatable({},{
    __index=function(self,enum_type)
        local enum=setmetatable({},{
            __index=function(_,item_name) return {Name=item_name,Value=0,EnumType=enum_type} end,
            __type="Enum",__tostring=function() return "Enum."..enum_type end
        })
        rawset(self,enum_type,enum)
        return enum
    end,
    __type="Enums"
})

local InstanceModule={}
function InstanceModule.new(class_name,parent)
    local inst,children,props=make_instance(class_name,class_name,parent)
    if class_name=="ScreenGui" or class_name=="BillboardGui" or class_name=="SurfaceGui" then
        props.Enabled=true;props.ResetOnSpawn=true;props.DisplayOrder=0
        props.IgnoreGuiInset=false;props.ZIndexBehavior=EnumMock.ZIndexBehavior.Sibling
        -- Bridge initial properties
        if inst._gui_id and inst._gui_id>0 and _oss_gui_set then
            pcall(_oss_gui_set, inst._gui_id, "Enabled", true)
        end
    elseif class_name=="Frame" or class_name=="TextLabel" or class_name=="TextButton"
           or class_name=="ImageLabel" or class_name=="ImageButton" or class_name=="ScrollingFrame"
           or class_name=="TextBox" or class_name=="ViewportFrame" or class_name=="CanvasGroup" then
        props.Size=UDim2.new(0,100,0,100);props.Position=UDim2.new(0,0,0,0)
        props.BackgroundColor3=Color3.new(1,1,1);props.BackgroundTransparency=0
        props.Visible=true;props.Text="";props.TextColor3=Color3.new(0,0,0)
        props.TextSize=14;props.Font=0;props.ZIndex=1
        props.AnchorPoint=Vector2.new(0,0);props.BorderSizePixel=0;props.ClipsDescendants=false
        props.LayoutOrder=0;props.Rotation=0;props.AutomaticSize=EnumMock.AutomaticSize.None
        props.Active=false;props.Selectable=false
        -- Bridge initial GUI properties
        if inst._gui_id and inst._gui_id>0 and _oss_gui_set then
            pcall(_oss_gui_set, inst._gui_id, "Visible", true)
            pcall(_oss_gui_set, inst._gui_id, "Size", props.Size)
            pcall(_oss_gui_set, inst._gui_id, "Position", props.Position)
            pcall(_oss_gui_set, inst._gui_id, "BackgroundColor3", props.BackgroundColor3)
            pcall(_oss_gui_set, inst._gui_id, "BackgroundTransparency", props.BackgroundTransparency)
            pcall(_oss_gui_set, inst._gui_id, "ZIndex", props.ZIndex)
        end
        if class_name=="TextLabel" or class_name=="TextButton" or class_name=="TextBox" then
            props.TextWrapped=false;props.TextScaled=false;props.RichText=false
            props.TextXAlignment=EnumMock.TextXAlignment.Center
            props.TextYAlignment=EnumMock.TextYAlignment.Center
            props.TextTransparency=0;props.TextStrokeTransparency=1
            props.TextStrokeColor3=Color3.new(0,0,0)
            props.MaxVisibleGraphemes=-1;props.LineHeight=1
            props.ContentText=""
            props.TextBounds=Vector2.new(0,0)
            props.TextFits=true
        end
        if class_name=="ImageLabel" or class_name=="ImageButton" then
            props.Image="";props.ImageColor3=Color3.new(1,1,1);props.ImageTransparency=0
            props.ImageRectOffset=Vector2.new(0,0);props.ImageRectSize=Vector2.new(0,0)
            props.ScaleType=EnumMock.ScaleType.Stretch;props.SliceCenter=nil
        end
        if class_name=="ScrollingFrame" then
            props.CanvasSize=UDim2.new(0,0,0,0);props.CanvasPosition=Vector2.new(0,0)
            props.ScrollBarThickness=12;props.ScrollBarImageTransparency=0
            props.ScrollingDirection=EnumMock.ScrollingDirection.XY
            props.ScrollingEnabled=true
        end
    elseif class_name=="Part" or class_name=="MeshPart" or class_name=="UnionOperation" or class_name=="WedgePart" or class_name=="SpawnLocation" then
        props.Position=Vector3.new(0,0,0);props.Size=Vector3.new(4,1,2)
        props.CFrame=CFrame.new(0,0,0);props.Anchored=false;props.CanCollide=true
        props.Transparency=0;props.BrickColor="Medium stone grey"
        props.Color=Color3.fromRGB(163,162,165);props.Material=EnumMock.Material.Plastic
        props.CanQuery=true;props.CanTouch=true;props.Massless=false
        props.Velocity=Vector3.new(0,0,0);props.AssemblyLinearVelocity=Vector3.new(0,0,0)
        props.AssemblyAngularVelocity=Vector3.new(0,0,0)
    elseif class_name=="Model" or class_name=="Folder" then
        if class_name=="Model" then
            props.PrimaryPart=nil
            rawset(inst,"GetPivot",function() return CFrame.new(0,0,0) end)
            rawset(inst,"PivotTo",function() end)
            rawset(inst,"MoveTo",function() end)
            rawset(inst,"GetBoundingBox",function() return CFrame.new(),Vector3.new(4,4,4) end)
            rawset(inst,"SetPrimaryPartCFrame",function() end)
            rawset(inst,"GetExtentsSize",function() return Vector3.new(4,4,4) end)
        end
    elseif class_name=="UICorner" then
        props.CornerRadius=UDim.new(0,8)
    elseif class_name=="UIStroke" then
        props.Thickness=1;props.Color=Color3.new(0,0,0);props.Transparency=0
        props.ApplyStrokeMode=EnumMock.ApplyStrokeMode.Contextual
        props.LineJoinMode=EnumMock.LineJoinMode.Round
    elseif class_name=="UIListLayout" or class_name=="UIGridLayout" then
        props.SortOrder=EnumMock.SortOrder.LayoutOrder;props.Padding=UDim.new(0,0)
        props.FillDirection=EnumMock.FillDirection.Vertical
        props.HorizontalAlignment=EnumMock.HorizontalAlignment.Left
        props.VerticalAlignment=EnumMock.VerticalAlignment.Top
    elseif class_name=="UIPadding" then
        props.PaddingTop=UDim.new(0,0);props.PaddingBottom=UDim.new(0,0)
        props.PaddingLeft=UDim.new(0,0);props.PaddingRight=UDim.new(0,0)
    elseif class_name=="UIScale" then props.Scale=1
    elseif class_name=="UIAspectRatioConstraint" then props.AspectRatio=1;props.AspectType=EnumMock.AspectType.FitWithinMaxSize
    elseif class_name=="UISizeConstraint" then
        props.MinSize=Vector2.new(0,0);props.MaxSize=Vector2.new(math.huge,math.huge)
    elseif class_name=="UITextSizeConstraint" then
        props.MinTextSize=1;props.MaxTextSize=100
    elseif class_name=="UIGradient" then
        props.Color=nil;props.Transparency=nil
        props.Offset=Vector2.new(0,0);props.Rotation=0
    elseif class_name=="Sound" then
        props.SoundId="";props.Volume=0.5;props.PlaybackSpeed=1;props.Playing=false
        props.Looped=false;props.TimePosition=0;props.TimeLength=0
        rawset(inst,"Play",function() props.Playing=true end)
        rawset(inst,"Stop",function() props.Playing=false end)
        rawset(inst,"Pause",function() props.Playing=false end)
        rawset(inst,"Resume",function() props.Playing=true end)
    elseif class_name=="Animation" then
        props.AnimationId=""
    elseif class_name=="Animator" or class_name=="AnimationController" then
        rawset(inst,"LoadAnimation",function(_,anim)
            local track,_,tp=make_instance("AnimationTrack","AnimationTrack")
            tp.IsPlaying=false;tp.Length=1;tp.Speed=1;tp.TimePosition=0
            tp.Looped=false;tp.Priority=EnumMock.AnimationPriority.Action
            rawset(track,"Play",function() tp.IsPlaying=true end)
            rawset(track,"Stop",function() tp.IsPlaying=false end)
            rawset(track,"AdjustSpeed",function(_,s) tp.Speed=s end)
            rawset(track,"AdjustWeight",function() end)
            rawset(track,"GetMarkerReachedSignal",function() return Signal.new("MarkerReached") end)
            return track
        end)
    elseif class_name=="BindableEvent" then
        local sig=Signal.new("Event")
        props.Event=sig
        rawset(inst,"Fire",function(_,...) sig:Fire(...) end)
    elseif class_name=="BindableFunction" then
        props.OnInvoke=nil
        rawset(inst,"Invoke",function(_,...)
            if props.OnInvoke then return props.OnInvoke(...) end
        end)
    elseif class_name=="RemoteEvent" then
        props.OnClientEvent=Signal.new("OnClientEvent")
        rawset(inst,"FireServer",function() end)
    elseif class_name=="RemoteFunction" then
        props.OnClientInvoke=nil
        rawset(inst,"InvokeServer",function() return nil end)
    elseif class_name=="Highlight" then
        props.Adornee=nil;props.FillColor=Color3.new(1,0,0)
        props.FillTransparency=0.5;props.OutlineColor=Color3.new(1,1,1)
        props.OutlineTransparency=0;props.DepthMode=EnumMock.HighlightDepthMode.AlwaysOnTop
        props.Enabled=true
    elseif class_name=="BillboardGui" then
        props.Adornee=nil;props.Size=UDim2.new(0,100,0,100)
        props.StudsOffset=Vector3.new(0,0,0);props.AlwaysOnTop=false
        props.MaxDistance=math.huge;props.Enabled=true
    elseif class_name=="Beam" then
        props.Attachment0=nil;props.Attachment1=nil
        props.Color=nil;props.Width0=1;props.Width1=1
        props.FaceCamera=true;props.Enabled=true
    elseif class_name=="Attachment" then
        props.CFrame=CFrame.new();props.Position=Vector3.new()
        props.WorldCFrame=CFrame.new();props.WorldPosition=Vector3.new()
    end

    -- Auto-parent if parent was provided to Instance.new
    if parent and type(parent)=="table" then
        local pc=rawget(parent,"_children")
        if pc then table.insert(pc,inst) end
        -- Bridge: set parent in overlay
        if is_gui and gui_id>0 and _oss_gui_set_parent then
            local parent_gui_id=0
            local pgid=parent._gui_id
            if pgid and pgid>0 then parent_gui_id=pgid end
            pcall(_oss_gui_set_parent, gui_id, parent_gui_id)
        end
    end
    return inst
end

Drawing={Fonts={UI=0,System=1,Plex=2,Monospace=3}}
local _drawing_type_map={Line=0,Text=1,Circle=2,Square=3,Triangle=4,Quad=5,Image=6}

function Drawing.new(class_name)
    class_name=class_name or "Line"
    local type_id=_drawing_type_map[class_name] or 0
    local id=0
    if _oss_drawing_new then id=_oss_drawing_new(type_id) end
    local data={
        _id=id,_class=class_name,_removed=false,
        Visible=false,Color=Color3.new(1,1,1),
        Transparency=0,Thickness=1,ZIndex=0,
        From=Vector2.new(0,0),To=Vector2.new(0,0),
        Text="",Size=14,Center=false,Outline=false,
        OutlineColor=Color3.new(0,0,0),
        Position=Vector2.new(0,0),
        TextBounds=Vector2.new(0,0),Font=0,
        Radius=50,NumSides=32,Filled=false,
        PointA=Vector2.new(0,0),PointB=Vector2.new(0,0),
        PointC=Vector2.new(0,0),PointD=Vector2.new(0,0),
        Data="",Rounding=0,
    }
    local mt={
        __type="Drawing",
        __tostring=function() return "Drawing" end,
        __index=function(_,key)
            if key=="Remove" or key=="Destroy" then
                return function()
                    if data._removed then return end
                    data._removed=true
                    data.Visible=false
                    if _oss_drawing_set and id>0 then pcall(_oss_drawing_set,id,"Visible",false) end
                    if _oss_drawing_remove and id>0 then pcall(_oss_drawing_remove,id) end
                end
            end
            return data[key]
        end,
        __newindex=function(_,key,value)
            if data._removed then return end
            data[key]=value
            if _oss_drawing_set and id>0 then pcall(_oss_drawing_set,id,key,value) end
        end,
    }
    return setmetatable({},mt)
end
function Drawing.clear()
    if _oss_drawing_clear then _oss_drawing_clear() end
end

local service_cache={}

local function get_camera()
    local cam,_,props=make_instance("Camera","Camera")
    props.CFrame=CFrame.new(0,10,0)
    props.ViewportSize=Vector2.new(1920,1080)
    props.FieldOfView=70;props.NearPlaneZ=0.1;props.FarPlaneZ=10000
    props.Focus=CFrame.new(0,0,0)
    props.CameraType=EnumMock.CameraType.Custom;props.CameraSubject=nil
    rawset(cam,"WorldToViewportPoint",function(_,v3) return Vector3.new(960,540,(v3 and v3.Z or 10)),true end)
    rawset(cam,"WorldToScreenPoint",function(self,v3) return self:WorldToViewportPoint(v3) end)
    rawset(cam,"ViewportPointToRay",function(_,x,y) return {Origin=Vector3.new(x or 0,y or 0,0),Direction=Vector3.new(0,0,-1)} end)
    rawset(cam,"ScreenPointToRay",function(_,x,y) return {Origin=Vector3.new(x or 0,y or 0,0),Direction=Vector3.new(0,0,-1)} end)
    return cam
end

local function make_service(name)
    if service_cache[name] then return service_cache[name] end
    local svc,children,props=make_instance(name,name)

    if name=="Players" then
        local lp,_,lp_props=make_instance("Player","LocalPlayer")
        lp_props.Name="LocalPlayer";lp_props.DisplayName="Player";lp_props.UserId=1
        lp_props.TeamColor=Color3.new(1,1,1);lp_props.Team=nil
        lp_props.AccountAge=365;lp_props.MembershipType=EnumMock.MembershipType.None
        lp_props.FollowUserId=0
        local char,char_children=make_instance("Model","LocalPlayer")
        local hrp,_,hrp_props=make_instance("Part","HumanoidRootPart",char)
        hrp_props.Position=Vector3.new(0,3,0);hrp_props.CFrame=CFrame.new(0,3,0);hrp_props.Size=Vector3.new(2,2,1)
        local head,_,head_props=make_instance("Part","Head",char)
        head_props.Position=Vector3.new(0,4.5,0);head_props.CFrame=CFrame.new(0,4.5,0);head_props.Size=Vector3.new(2,1,1)
        local hum,_,hum_props=make_instance("Humanoid","Humanoid",char)
        hum_props.Health=100;hum_props.MaxHealth=100;hum_props.WalkSpeed=16;hum_props.JumpPower=50;hum_props.JumpHeight=7.2
        hum_props.RigType=EnumMock.HumanoidRigType.R15;hum_props.HipHeight=2
        hum_props.AutoRotate=true;hum_props.Sit=false;hum_props.PlatformStand=false
        rawset(hum,"GetState",function() return EnumMock.HumanoidStateType.Running end)
        rawset(hum,"ChangeState",function() end)
        rawset(hum,"GetAppliedDescription",function() return make_instance("HumanoidDescription","HumanoidDescription") end)
        rawset(hum,"MoveTo",function() end)
        rawset(hum,"TakeDamage",function(_,d) hum_props.Health=math.max(0,hum_props.Health-d) end)
        rawset(hum,"EquipTool",function() end)
        rawset(hum,"UnequipTools",function() end)
        table.insert(char_children,hrp);table.insert(char_children,head);table.insert(char_children,hum)
        rawset(char,"GetPivot",function() return hrp_props.CFrame end)
        rawset(char,"PivotTo",function(_,cf) hrp_props.CFrame=cf;hrp_props.Position=cf.Position end)
        lp_props.Character=char
        rawset(lp,"GetMouse",function()
            local mouse,_,mp=make_instance("Mouse","Mouse")
            mp.X=0;mp.Y=0;mp.Hit=CFrame.new(0,0,0);mp.Target=nil;mp.UnitRay={Origin=Vector3.new(),Direction=Vector3.new(0,0,-1)}
            mp.Origin=CFrame.new();mp.ViewSizeX=1920;mp.ViewSizeY=1080
            mp.Button1Down=Signal.new("Button1Down");mp.Button1Up=Signal.new("Button1Up")
            mp.Button2Down=Signal.new("Button2Down");mp.Button2Up=Signal.new("Button2Up")
            mp.Move=Signal.new("Move");mp.WheelForward=Signal.new("WheelForward");mp.WheelBackward=Signal.new("WheelBackward")
            return mouse
        end)
        rawset(lp,"Kick",function() end)
        rawset(lp,"GetFriendsOnline",function() return {} end)
        rawset(lp,"IsFriendsWith",function() return false end)
        rawset(lp,"GetRankInGroup",function() return 0 end)
        rawset(lp,"GetRoleInGroup",function() return "Guest" end)
        rawset(lp,"IsInGroup",function() return false end)
        props.LocalPlayer=lp;table.insert(children,lp)
        rawset(svc,"GetPlayers",function() return {lp} end)
        rawset(svc,"GetPlayerByUserId",function(_,uid) if uid==1 then return lp end return nil end)
        rawset(svc,"GetPlayerFromCharacter",function(_,c) if c==char then return lp end return nil end)
        props.PlayerAdded=Signal.new("PlayerAdded");props.PlayerRemoving=Signal.new("PlayerRemoving")
    elseif name=="RunService" then
        props.RenderStepped=Signal.new("RenderStepped");props.Heartbeat=Signal.new("Heartbeat");props.Stepped=Signal.new("Stepped")
        props.PreRender=Signal.new("PreRender");props.PreAnimation=Signal.new("PreAnimation")
        props.PreSimulation=Signal.new("PreSimulation");props.PostSimulation=Signal.new("PostSimulation")
        rawset(svc,"IsClient",function() return true end)
        rawset(svc,"IsServer",function() return false end)
        rawset(svc,"IsStudio",function() return false end)
        rawset(svc,"IsRunMode",function() return false end)
        rawset(svc,"IsEdit",function() return false end)
        rawset(svc,"IsRunning",function() return true end)
        rawset(svc,"BindToRenderStep",function(_,n,p,fn) if type(fn)=="function" then props.RenderStepped:Connect(fn) end end)
        rawset(svc,"UnbindFromRenderStep",function() end)
    elseif name=="Workspace" then
        props.CurrentCamera=get_camera();props.Gravity=196.2;props.DistributedGameTime=0
        props.FallenPartsDestroyHeight=-500
        rawset(svc,"Raycast",function() return nil end)
        rawset(svc,"FindPartOnRay",function() return nil,Vector3.new() end)
        rawset(svc,"FindPartOnRayWithIgnoreList",function() return nil,Vector3.new() end)
        rawset(svc,"FindPartOnRayWithWhitelist",function() return nil,Vector3.new() end)
        rawset(svc,"GetServerTimeNow",function() return os.clock() end)
    elseif name=="UserInputService" then
        props.MouseEnabled=true;props.KeyboardEnabled=true;props.TouchEnabled=false;props.GamepadEnabled=false
        props.MouseBehavior=EnumMock.MouseBehavior.Default;props.MouseDeltaSensitivity=1
        props.MouseIconEnabled=true;props.BottomBarSize=Vector2.new(0,0)
        props.NavBarSize=Vector2.new(0,0);props.StatusBarSize=Vector2.new(0,0)
        props.InputBegan=Signal.new("InputBegan");props.InputEnded=Signal.new("InputEnded");props.InputChanged=Signal.new("InputChanged")
        props.WindowFocused=Signal.new("WindowFocused");props.WindowFocusReleased=Signal.new("WindowFocusReleased")
        rawset(svc,"GetMouseLocation",function() return Vector2.new(960,540) end)
        rawset(svc,"GetMouseDelta",function() return Vector2.new(0,0) end)
        rawset(svc,"IsKeyDown",function() return false end)
        rawset(svc,"IsMouseButtonPressed",function() return false end)
        rawset(svc,"GetKeysPressed",function() return {} end)
        rawset(svc,"GetMouseButtonsPressed",function() return {} end)
        rawset(svc,"GetGamepadConnected",function() return false end)
        rawset(svc,"GetGamepadState",function() return {} end)
        rawset(svc,"GetNavigationGamepads",function() return {} end)
        rawset(svc,"GetConnectedGamepads",function() return {} end)
        rawset(svc,"GetFocusedTextBox",function() return nil end)
        rawset(svc,"GetStringForKeyCode",function(_,kc) return tostring(kc) end)
    elseif name=="CoreGui" or name=="StarterGui" then
        rawset(svc,"SetCoreGuiEnabled",function() end)
        rawset(svc,"GetCoreGuiEnabled",function() return true end)
        rawset(svc,"SetCore",function() end)
        rawset(svc,"GetCore",function() return nil end)
        rawset(svc,"RegisterSetCore",function() end)
        rawset(svc,"RegisterGetCore",function() end)
    elseif name=="TweenService" then
        rawset(svc,"Create",function(_,inst2,info,pt)
            local tween,_,tp=make_instance("Tween","Tween")
            tp.PlaybackState=EnumMock.PlaybackState.Begin
            rawset(tween,"Play",function()
                tp.PlaybackState=EnumMock.PlaybackState.Playing
                -- Apply tween properties immediately for GUI visibility
                if pt and type(inst2)=="table" then
                    for k,v in pairs(pt) do
                        inst2[k]=v
                    end
                end
                -- Fire Completed after a brief delay simulation
                if tp.Completed then
                    tp.PlaybackState=EnumMock.PlaybackState.Completed
                    tp.Completed:Fire(EnumMock.PlaybackState.Completed)
                end
            end)
            rawset(tween,"Cancel",function() tp.PlaybackState=EnumMock.PlaybackState.Cancelled end)
            rawset(tween,"Pause",function() tp.PlaybackState=EnumMock.PlaybackState.Paused end)
            tp.Completed=Signal.new("Completed")
            return tween
        end)
        rawset(svc,"GetValue",function(_,alpha,style,dir)
            return alpha
        end)
    elseif name=="HttpService" then
        rawset(svc,"JSONEncode",function(_,obj)
            local function encode(v)
                if v==nil then return "null" end
                local t=type(v)
                if t=="string" then
                    return '"'..v:gsub('\\','\\\\'):gsub('"','\\"'):gsub('\n','\\n'):gsub('\r','\\r'):gsub('\t','\\t')..'"'
                end
                if t=="number" then
                    if v~=v then return '"NaN"' end
                    if v==math.huge then return '1e309' end
                    if v==-math.huge then return '-1e309' end
                    return tostring(v)
                end
                if t=="boolean" then return tostring(v) end
                if t=="table" then
                    local is_array=true
                    local max_i=0
                    for k,_ in pairs(v) do
                        if type(k)~="number" or k<1 or k~=math.floor(k) then
                            is_array=false;break
                        end
                        if k>max_i then max_i=k end
                    end
                    if is_array and max_i==#v then
                        local parts={}
                        for i=1,#v do parts[i]=encode(v[i]) end
                        return "["..table.concat(parts,",").."]"
                    else
                        local parts={}
                        for k2,v2 in pairs(v) do
                            table.insert(parts, encode(tostring(k2))..":"..encode(v2))
                        end
                        return "{"..table.concat(parts,",").."}"
                    end
                end
                return '"'..tostring(v)..'"'
            end
            return encode(obj)
        end)
        rawset(svc,"JSONDecode",function(_,str)
            if type(str)~="string" then return {} end
            -- Proper JSON parser
            local pos=1
            local function skip_ws()
                while pos<=#str do
                    local c=str:sub(pos,pos)
                    if c==" " or c=="\t" or c=="\n" or c=="\r" then pos=pos+1
                    else break end
                end
            end
            local parse_value -- forward declaration
            local function parse_string()
                if str:sub(pos,pos)~='"' then return nil end
                pos=pos+1
                local result={}
                while pos<=#str do
                    local c=str:sub(pos,pos)
                    if c=='"' then pos=pos+1;return table.concat(result) end
                    if c=='\\' then
                        pos=pos+1;c=str:sub(pos,pos)
                        if c=='"' then result[#result+1]='"'
                        elseif c=='\\' then result[#result+1]='\\'
                        elseif c=='/' then result[#result+1]='/'
                        elseif c=='n' then result[#result+1]='\n'
                        elseif c=='r' then result[#result+1]='\r'
                        elseif c=='t' then result[#result+1]='\t'
                        elseif c=='b' then result[#result+1]='\b'
                        elseif c=='f' then result[#result+1]='\f'
                        elseif c=='u' then
                            local hex=str:sub(pos+1,pos+4)
                            local code=tonumber(hex,16) or 0
                            if code<128 then result[#result+1]=string.char(code)
                            else result[#result+1]='?' end
                            pos=pos+4
                        end
                    else
                        result[#result+1]=c
                    end
                    pos=pos+1
                end
                return table.concat(result)
            end
            local function parse_number()
                local start=pos
                if str:sub(pos,pos)=='-' then pos=pos+1 end
                while pos<=#str and str:sub(pos,pos):match("[%d]") do pos=pos+1 end
                if pos<=#str and str:sub(pos,pos)=='.' then
                    pos=pos+1
                    while pos<=#str and str:sub(pos,pos):match("[%d]") do pos=pos+1 end
                end
                if pos<=#str and str:sub(pos,pos):lower()=='e' then
                    pos=pos+1
                    if str:sub(pos,pos)=='+' or str:sub(pos,pos)=='-' then pos=pos+1 end
                    while pos<=#str and str:sub(pos,pos):match("[%d]") do pos=pos+1 end
                end
                return tonumber(str:sub(start,pos-1))
            end
            local function parse_array()
                pos=pos+1 -- skip [
                local arr={}
                skip_ws()
                if str:sub(pos,pos)==']' then pos=pos+1;return arr end
                while true do
                    skip_ws()
                    local val=parse_value()
                    arr[#arr+1]=val
                    skip_ws()
                    if str:sub(pos,pos)==',' then pos=pos+1
                    elseif str:sub(pos,pos)==']' then pos=pos+1;break
                    else break end
                end
                return arr
            end
            local function parse_object()
                pos=pos+1 -- skip {
                local obj2={}
                skip_ws()
                if str:sub(pos,pos)=='}' then pos=pos+1;return obj2 end
                while true do
                    skip_ws()
                    local key=parse_string()
                    skip_ws()
                    if str:sub(pos,pos)==':' then pos=pos+1 end
                    skip_ws()
                    local val=parse_value()
                    if key then obj2[key]=val end
                    skip_ws()
                    if str:sub(pos,pos)==',' then pos=pos+1
                    elseif str:sub(pos,pos)=='}' then pos=pos+1;break
                    else break end
                end
                return obj2
            end
            parse_value=function()
                skip_ws()
                local c=str:sub(pos,pos)
                if c=='"' then return parse_string()
                elseif c=='{' then return parse_object()
                elseif c=='[' then return parse_array()
                elseif c=='t' then pos=pos+4;return true
                elseif c=='f' then pos=pos+5;return false
                elseif c=='n' then pos=pos+4;return nil
                elseif c=='-' or c:match("[%d]") then return parse_number()
                end
                return nil
            end
            local ok,result=pcall(parse_value)
            if ok then return result end
            return {}
        end)
        rawset(svc,"GenerateGUID",function(_,wrap)
            local g="xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
            g=g:gsub("[xy]",function(c)
                local v=(c=="x") and math.random(0,15) or math.random(8,11)
                return string.format("%x",v)
            end)
            if wrap==false then return g end
            return "{"..g.."}"
        end)
        rawset(svc,"UrlEncode",function(_,str2)
            return (str2:gsub("[^%w%-_%.~]",function(c) return string.format("%%%02X",string.byte(c)) end))
        end)
        rawset(svc,"RequestAsync",function(_,opts) return _G._oss_http_request(opts) end)
    elseif name=="ReplicatedStorage" or name=="ServerStorage" or name=="ServerScriptService"
        or name=="StarterPack" or name=="StarterPlayer" or name=="StarterPlayerScripts"
        or name=="StarterCharacterScripts" or name=="Lighting" or name=="SoundService"
        or name=="Chat" or name=="LocalizationService" or name=="TestService"
        or name=="ContentProvider" or name=="MarketplaceService" or name=="TeleportService"
        or name=="PolicyService" or name=="SocialService" then
    elseif name=="GuiService" then
        rawset(svc,"GetGuiInset",function() return Vector2.new(0,36),Vector2.new(0,0) end)
        rawset(svc,"IsTenFootInterface",function() return false end)
        props.MenuIsOpen=false
    elseif name=="PathfindingService" then
        rawset(svc,"CreatePath",function()
            local path,_,pp=make_instance("Path","Path")
            rawset(path,"ComputeAsync",function() end)
            rawset(path,"GetWaypoints",function() return {} end)
            pp.Status=EnumMock.PathStatus.Success
            pp.Blocked=Signal.new("Blocked")
            return path
        end)
    elseif name=="PhysicsService" then
        rawset(svc,"GetCollisionGroupName",function(_,id) return "Default" end)
        rawset(svc,"GetCollisionGroupId",function(_,name2) return 0 end)
        rawset(svc,"CollisionGroupContainsPart",function() return false end)
        rawset(svc,"SetPartCollisionGroup",function() end)
    elseif name=="Debris" then
        rawset(svc,"AddItem",function(_,item,lifetime) end)
    elseif name=="VirtualInputManager" then
        rawset(svc,"SendKeyEvent",function() end)
        rawset(svc,"SendMouseButtonEvent",function() end)
        rawset(svc,"SendMouseMoveEvent",function() end)
        rawset(svc,"SendMouseWheelEvent",function() end)
        rawset(svc,"SendTextInputCharacterEvent",function() end)
    elseif name=="Stats" then
        rawset(svc,"GetTotalMemoryUsageMb",function() return 512 end)
        rawset(svc,"GetMemoryUsageMbForTag",function() return 0 end)
    end

    service_cache[name]=svc
    return svc
end

local game_mt={__type="DataModel",__tostring=function() return "Game" end}
game_mt.__index=function(self,key)
    if key=="GetService" then return function(_,sn) return make_service(sn) end end
    if key=="FindService" then return function(_,sn) return make_service(sn) end end
    if key=="HttpGet" or key=="HttpGetAsync" then return _G._oss_http_get end
    if key=="HttpPost" or key=="HttpPostAsync" then return function(_,url,body) return "" end end
    if key=="PlaceId" then return 0 end
    if key=="PlaceVersion" then return 1 end
    if key=="GameId" then return 0 end
    if key=="JobId" then return "" end
    if key=="CreatorId" then return 0 end
    if key=="CreatorType" then return "User" end
    if key=="IsA" then return function(_,class) return class=="DataModel" or class=="Instance" end end
    if key=="FindFirstChild" or key=="WaitForChild" then return function(_,n) return make_service(n) end end
    if key=="GetChildren" or key=="GetDescendants" then return function() return {} end end
    if key=="BindToClose" then return function() end end
    if key=="IsLoaded" then return function() return true end end
    if key=="GetObjects" then return function() return {} end end
    if key=="ClassName" then return "DataModel" end
    if key=="Name" then return "Game" end
    if key=="GetPropertyChangedSignal" then return function(_,p) return Signal.new("PropChanged_"..p) end end
    local ok,svc=pcall(make_service,key)
    if ok and svc then return svc end
    return nil
end

game=setmetatable({},game_mt)
Game=game
workspace=make_service("Workspace")
Instance=InstanceModule
Enum=EnumMock

_G.Vector3=Vector3;_G.Vector2=Vector2
_G.Color3=Color3;_G.UDim=UDim;_G.UDim2=UDim2
_G.CFrame=CFrame;_G.Drawing=Drawing

-- Heartbeat/RenderStepped ticker: fire signals periodically
-- This runs via a coroutine-based approach using wait()
local _heartbeat_running=false
local function _start_heartbeat()
    if _heartbeat_running then return end
    _heartbeat_running=true
    local rs=make_service("RunService")
    local last_time=os.clock()
    -- We'll fire these from the wait() implementation
    _G._oss_tick_signals=function()
        local now=os.clock()
        local dt=now-last_time
        if dt<0.001 then dt=0.016 end
        last_time=now
        if rs and rs.RenderStepped then pcall(function() rs.RenderStepped:Fire(dt) end) end
        if rs and rs.Heartbeat then pcall(function() rs.Heartbeat:Fire(dt) end) end
        if rs and rs.Stepped then pcall(function() rs.Stepped:Fire(now,dt) end) end
        if rs and rs.PreRender then pcall(function() rs.PreRender:Fire(dt) end) end
        if rs and rs.PostSimulation then pcall(function() rs.PostSimulation:Fire(dt) end) end
    end
end
_start_heartbeat()

local _c_wait=wait
local _c_spawn=spawn
local _c_delay=delay

wait=function(t)
    t=t or 0.03
    -- Tick signals on every wait call
    if _G._oss_tick_signals then pcall(_G._oss_tick_signals) end
    if _c_wait then return _c_wait(t) end
    -- Busy-wait fallback with os.clock (not ideal but prevents instant return)
    local start=os.clock()
    while os.clock()-start<t do end
    local elapsed=os.clock()-start
    return elapsed,os.clock()
end

spawn=_c_spawn or function(fn,...) if type(fn)=="function" then pcall(fn,...) end end
delay=_c_delay or function(t,fn,...) if type(fn)=="function" then pcall(fn,...) end end
tick=tick or function() return os.clock() end
time=time or function() return os.clock() end
elapsedTime=elapsedTime or function() return os.clock() end
settings=settings or function() return {Rendering={QualityLevel=10}} end

shared=shared or {}
_G=_G or {}

TweenInfo={}
function TweenInfo.new(tv,s,d,rc,rev,dt)
    return {Time=tv or 1,EasingStyle=s or EnumMock.EasingStyle.Quad,
        EasingDirection=d or EnumMock.EasingDirection.Out,
        RepeatCount=rc or 0,Reverses=rev or false,DelayTime=dt or 0}
end

Ray={}
function Ray.new(o,d) return {Origin=o or Vector3.new(),Direction=d or Vector3.new(0,0,-1)} end

RaycastParams={}
function RaycastParams.new()
    return {FilterType=EnumMock.RaycastFilterType.Exclude,FilterDescendantsInstances={},IgnoreWater=true,CollisionGroup="Default"}
end

OverlapParams={}
function OverlapParams.new()
    return {FilterType=EnumMock.RaycastFilterType.Exclude,FilterDescendantsInstances={},CollisionGroup="Default"}
end

NumberRange={}
function NumberRange.new(mn,mx) return {Min=mn or 0,Max=mx or mn or 0} end

NumberSequenceKeypoint={}
function NumberSequenceKeypoint.new(t,v,e) return {Time=t or 0,Value=v or 0,Envelope=e or 0} end
NumberSequence={}
function NumberSequence.new(...)
    local args={...}
    if type(args[1])=="number" then
        return {Keypoints={NumberSequenceKeypoint.new(0,args[1]),NumberSequenceKeypoint.new(1,args[2] or args[1])}}
    end
    return {Keypoints=args[1] or {}}
end

ColorSequenceKeypoint={}
function ColorSequenceKeypoint.new(t,c) return {Time=t or 0,Value=c or Color3.new()} end
ColorSequence={}
function ColorSequence.new(...)
    local args={...}
    if getmetatable(args[1])==Color3 then
        return {Keypoints={ColorSequenceKeypoint.new(0,args[1]),ColorSequenceKeypoint.new(1,args[2] or args[1])}}
    end
    return {Keypoints=args[1] or {}}
end

BrickColor={}
function BrickColor.new(nr,g,b)
    if type(nr)=="string" then return {Name=nr,Color=Color3.new(0.64,0.64,0.64)} end
    return {Name="Custom",Color=Color3.fromRGB(nr or 0,g or 0,b or 0)}
end

PhysicalProperties={}
function PhysicalProperties.new(d,f,e,fw,ew)
    return {Density=d or 1,Friction=f or 0.3,Elasticity=e or 0.5,
        FrictionWeight=fw or 1,ElasticityWeight=ew or 1}
end

Rect={}
function Rect.new(x0,y0,x1,y1)
    return {Min=Vector2.new(x0 or 0,y0 or 0),Max=Vector2.new(x1 or 0,y1 or 0),
        Width=(x1 or 0)-(x0 or 0),Height=(y1 or 0)-(y0 or 0)}
end

Faces={}
function Faces.new(...) return {Top=false,Bottom=false,Left=false,Right=false,Back=false,Front=false} end

Axes={}
function Axes.new(...) return {X=false,Y=false,Z=false} end

Region3={}
function Region3.new(min,max)
    min=min or Vector3.new();max=max or Vector3.new()
    return {CFrame=CFrame.new((min.X+max.X)/2,(min.Y+max.Y)/2,(min.Z+max.Z)/2),
        Size=Vector3.new(max.X-min.X,max.Y-min.Y,max.Z-min.Z)}
end

Region3int16={}
function Region3int16.new(min,max) return {Min=min or Vector3.new(),Max=max or Vector3.new()} end

Vector3int16={}
function Vector3int16.new(x,y,z) return {X=x or 0,Y=y or 0,Z=z or 0} end

Vector2int16={}
function Vector2int16.new(x,y) return {X=x or 0,Y=y or 0} end

if not string.split then
    function string.split(str,sep)
        sep=sep or ","
        if sep=="" then
            local p={}
            for i=1,#str do p[i]=str:sub(i,i) end
            return p
        end
        local p={}
        local s=1
        while true do
            local i,j=string.find(str,sep,s,true)
            if not i then
                p[#p+1]=str:sub(s)
                break
            end
            p[#p+1]=str:sub(s,i-1)
            s=j+1
        end
        return p
    end
end

if not table.find then
    function table.find(t,value,init)
        for i=(init or 1),#t do if t[i]==value then return i end end
        return nil
    end
end
if not table.clone then
    function table.clone(t) local c={} for k,v in pairs(t) do c[k]=v end return setmetatable(c,getmetatable(t)) end
end
if not table.freeze then function table.freeze(t) return t end end
if not table.clear then function table.clear(t) for k in pairs(t) do t[k]=nil end end end
if not table.move then
    function table.move(a,f,e,t2,dest)
        dest=dest or a
        if f<t2 then for i=e,f,-1 do dest[t2+(i-f)]=a[i] end
        else for i=f,e do dest[t2+(i-f)]=a[i] end end
        return dest
    end
end
if not table.create then
    function table.create(n,val) local t={} for i=1,n do t[i]=val end return t end
end
if not table.pack then function table.pack(...) return {n=select("#",...),...} end end
if not table.unpack then table.unpack=unpack end
if not table.foreach then function table.foreach(t,f) for k,v in pairs(t) do local r=f(k,v) if r~=nil then return r end end end end
if not table.foreachi then function table.foreachi(t,f) for i=1,#t do local r=f(i,t[i]) if r~=nil then return r end end end end

if not math.clamp then function math.clamp(val,lo,hi) if val<lo then return lo end if val>hi then return hi end return val end end
if not math.sign then function math.sign(n) if n>0 then return 1 end if n<0 then return -1 end return 0 end end
if not math.round then function math.round(n) return math.floor(n+0.5) end end
do
    local _log=math.log
    math.log=function(x,base) if base then return _log(x)/_log(base) end return _log(x) end
end
if not math.noise then
    local function fade(t) return t*t*t*(t*(t*6-15)+10) end
    local function lerp2(a,b,t) return a+t*(b-a) end
    local _perm={}
    for i=0,255 do _perm[i]=i end
    for i=255,1,-1 do
        local j=math.random(0,i)
        _perm[i],_perm[j]=_perm[j],_perm[i]
    end
    for i=0,255 do _perm[i+256]=_perm[i] end
    local function grad(hash,x,y,z)
        local h=hash%16
        local u=(h<8) and x or y
        local v=(h<4) and y or ((h==12 or h==14) and x or z)
        return ((h%2==0) and u or -u)+((h%4<2) and v or -v)
    end
    math.noise=function(x,y,z)
        x=x or 0;y=y or 0;z=z or 0
        local X=math.floor(x)%256;local Y=math.floor(y)%256;local Z=math.floor(z)%256
        x=x-math.floor(x);y=y-math.floor(y);z=z-math.floor(z)
        local u,v,w=fade(x),fade(y),fade(z)
        local A=_perm[X]+Y;local AA=_perm[A]+Z;local AB=_perm[A+1]+Z
        local B=_perm[X+1]+Y;local BA=_perm[B]+Z;local BB=_perm[B+1]+Z
        return lerp2(
            lerp2(lerp2(grad(_perm[AA],x,y,z),grad(_perm[BA],x-1,y,z),u),
                  lerp2(grad(_perm[AB],x,y-1,z),grad(_perm[BB],x-1,y-1,z),u),v),
            lerp2(lerp2(grad(_perm[AA+1],x,y,z-1),grad(_perm[BA+1],x-1,y,z-1),u),
                  lerp2(grad(_perm[AB+1],x,y-1,z-1),grad(_perm[BB+1],x-1,y-1,z-1),u),v),w)
    end
end

if not bit32 then
    local ok,bitlib=pcall(require,"bit")
    if ok then
        bit32={band=bitlib.band,bor=bitlib.bor,bxor=bitlib.bxor,bnot=bitlib.bnot,
            lshift=bitlib.lshift,rshift=bitlib.rshift,arshift=bitlib.arshift,
            btest=function(a,b) return bitlib.band(a,b)~=0 end,
            extract=function(n,f,w) w=w or 1;return bitlib.band(bitlib.rshift(n,f),bitlib.lshift(1,w)-1) end,
            replace=function(n,v,f,w) w=w or 1;local m=bitlib.lshift(1,w)-1;return bitlib.bor(bitlib.band(n,bitlib.bnot(bitlib.lshift(m,f))),bitlib.lshift(bitlib.band(v,m),f)) end,
            countlz=function(n) if n==0 then return 32 end local c=0;while bitlib.band(n,0x80000000)==0 do n=bitlib.lshift(n,1);c=c+1 end return c end,
            countrz=function(n) if n==0 then return 32 end local c=0;while bitlib.band(n,1)==0 do n=bitlib.rshift(n,1);c=c+1 end return c end,
        }
    end
end

do
    local _real_loadstring=loadstring
    loadstring=function(src,name)
        if src==nil then
            local msg="loadstring: input is nil (did HttpGet/HttpGetAsync fail?)"
            warn(msg) return nil,msg
        end
        if type(src)~="string" then
            local msg="loadstring: expected string, got "..type(src)
            warn(msg) return nil,msg
        end
        if #src==0 then warn("[loadstring] empty source - remote script may have returned no data") end
        local fn,err=_real_loadstring(src,name)
        if not fn and err then warn("[loadstring] compile error: "..tostring(err)) end
        return fn,err
    end
end

)LUA";

void Environment::setup(LuaEngine& engine) {
    lua_State* L = engine.state();
    if (!L) {
        LOG_ERROR("Environment::setup called with null Lua state");
        return;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, "_oss_env_init");
    if (lua_toboolean(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    lua_pop(L, 1);

    lua_pushcfunction(L, lua_http_get);
    lua_setglobal(L, "_oss_http_get");
    lua_pushcfunction(L, lua_http_get);
    lua_setglobal(L, "HttpGet");
    lua_pushcfunction(L, lua_http_request);
    lua_setglobal(L, "_oss_http_request");
    lua_pushcfunction(L, lua_typeof);
    lua_setglobal(L, "typeof");
    lua_pushcfunction(L, lua_identify_executor);
    lua_setglobal(L, "identifyexecutor");
    lua_pushcfunction(L, lua_identify_executor);
    lua_setglobal(L, "getexecutorname");
    lua_pushcfunction(L, lua_printidentity);
    lua_setglobal(L, "printidentity");

    // Drawing bridge
    lua_pushcfunction(L, lua_drawing_new_bridge);
    lua_setglobal(L, "_oss_drawing_new");
    lua_pushcfunction(L, lua_drawing_set_bridge);
    lua_setglobal(L, "_oss_drawing_set");
    lua_pushcfunction(L, lua_drawing_remove_bridge);
    lua_setglobal(L, "_oss_drawing_remove");

    // GUI bridge
    lua_pushcfunction(L, lua_gui_create);
    lua_setglobal(L, "_oss_gui_create");
    lua_pushcfunction(L, lua_gui_set);
    lua_setglobal(L, "_oss_gui_set");
    lua_pushcfunction(L, lua_gui_set_parent);
    lua_setglobal(L, "_oss_gui_set_parent");
    lua_pushcfunction(L, lua_gui_remove);
    lua_setglobal(L, "_oss_gui_remove");
    lua_pushcfunction(L, lua_gui_clear);
    lua_setglobal(L, "_oss_gui_clear");
    lua_pushcfunction(L, lua_gui_get_screen_size);
    lua_setglobal(L, "_oss_gui_screen_size");

    setup_debug_lib(engine);
    setup_cache_lib(engine);
    setup_metatable_lib(engine);
    setup_input_lib(engine);
    setup_instance_lib(engine);
    setup_script_lib(engine);
    setup_websocket_lib(engine);
    setup_thread_lib(engine);
    setup_closure_lib(engine);

    int status = oss_dostring(L, ROBLOX_MOCK_LUA, "=roblox_mock");
    if (status != 0) {
        const char* err = lua_tostring(L, -1);
        LOG_ERROR("Failed to init Roblox mock: {}", err ? err : "unknown error");
        lua_pop(L, 1);
        return;
    }

    lua_pushboolean(L, 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "_oss_env_init");

    LOG_INFO("Roblox API mock environment initialized with GUI bridge");
}

void Environment::setup_debug_lib(LuaEngine& engine) {
    lua_State* L = engine.state();

    lua_getglobal(L, "debug");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
    }

    lua_pushcfunction(L, lua_debug_getinfo);
    lua_setfield(L, -2, "getinfo");
    lua_pushcfunction(L, lua_debug_getupvalue);
    lua_setfield(L, -2, "getupvalue");
    lua_pushcfunction(L, lua_debug_setupvalue);
    lua_setfield(L, -2, "setupvalue");
    lua_pushcfunction(L, lua_debug_getupvalues);
    lua_setfield(L, -2, "getupvalues");
    lua_pushcfunction(L, lua_debug_setupvalues);
    lua_setfield(L, -2, "setupvalues");
    lua_pushcfunction(L, lua_debug_getconstant);
    lua_setfield(L, -2, "getconstant");
    lua_pushcfunction(L, lua_debug_getconstants);
    lua_setfield(L, -2, "getconstants");
    lua_pushcfunction(L, lua_debug_setconstant);
    lua_setfield(L, -2, "setconstant");
    lua_pushcfunction(L, lua_debug_getproto);
    lua_setfield(L, -2, "getproto");
    lua_pushcfunction(L, lua_debug_getprotos);
    lua_setfield(L, -2, "getprotos");
    lua_pushcfunction(L, lua_debug_getstack);
    lua_setfield(L, -2, "getstack");
    lua_pushcfunction(L, lua_debug_setstack);
    lua_setfield(L, -2, "setstack");
    lua_pushcfunction(L, lua_debug_getmetatable);
    lua_setfield(L, -2, "getmetatable");
    lua_pushcfunction(L, lua_debug_setmetatable);
    lua_setfield(L, -2, "setmetatable");
    lua_pushcfunction(L, lua_debug_getregistry);
    lua_setfield(L, -2, "getregistry");
    lua_pushcfunction(L, lua_debug_traceback);
    lua_setfield(L, -2, "traceback");
    lua_pushcfunction(L, lua_debug_profilebegin);
    lua_setfield(L, -2, "profilebegin");
    lua_pushcfunction(L, lua_debug_profileend);
    lua_setfield(L, -2, "profileend");
    lua_setglobal(L, "debug");

    engine.register_function("getinfo", lua_debug_getinfo);
    engine.register_function("getupvalue", lua_debug_getupvalue);
    engine.register_function("setupvalue", lua_debug_setupvalue);
    engine.register_function("getupvalues", lua_debug_getupvalues);
    engine.register_function("setupvalues", lua_debug_setupvalues);
    engine.register_function("getconstant", lua_debug_getconstant);
    engine.register_function("getconstants", lua_debug_getconstants);
    engine.register_function("setconstant", lua_debug_setconstant);
    engine.register_function("getproto", lua_debug_getproto);
    engine.register_function("getprotos", lua_debug_getprotos);
    engine.register_function("getstack", lua_debug_getstack);
    engine.register_function("setstack", lua_debug_setstack);
}

void Environment::setup_cache_lib(LuaEngine& engine) {
    lua_State* L = engine.state();

    lua_newtable(L);
    lua_pushcfunction(L, lua_cache_invalidate);
    lua_setfield(L, -2, "invalidate");
    lua_pushcfunction(L, lua_cache_iscached);
    lua_setfield(L, -2, "iscached");
    lua_pushcfunction(L, lua_cache_replace);
    lua_setfield(L, -2, "replace");
    lua_setglobal(L, "cache");

    engine.register_function("cache_invalidate", lua_cache_invalidate);
    engine.register_function("cache_iscached", lua_cache_iscached);
    engine.register_function("cache_replace", lua_cache_replace);
}

void Environment::setup_metatable_lib(LuaEngine& engine) {
    engine.register_function("getrawmetatable", lua_getrawmetatable);
    engine.register_function("setrawmetatable", lua_setrawmetatable);
    engine.register_function("setreadonly", lua_setreadonly);
    engine.register_function("isreadonly", lua_isreadonly);
    engine.register_function("getnamecallmethod", lua_getnamecallmethod);
}

void Environment::setup_input_lib(LuaEngine& engine) {
    engine.register_function("fireclickdetector", lua_fireclickdetector);
    engine.register_function("firetouchinterest", lua_firetouchinterest);
    engine.register_function("fireproximityprompt", lua_fireproximityprompt);
    engine.register_function("setfpscap", lua_setfpscap);
    engine.register_function("getfps", lua_getfps);
}

void Environment::setup_instance_lib(LuaEngine& engine) {
    engine.register_function("getgenv", lua_getgenv);
    engine.register_function("getrenv", lua_getrenv);
    engine.register_function("getreg", lua_getreg);
    engine.register_function("getgc", lua_getgc);
    engine.register_function("gethui", lua_gethui);
    engine.register_function("getinstances", lua_getinstances);
    engine.register_function("getnilinstances", lua_getnilinstances);
    engine.register_function("getconnections", lua_getconnections);
}

void Environment::setup_script_lib(LuaEngine& engine) {
    engine.register_function("getscripts", lua_getscripts);
    engine.register_function("getrunningscripts", lua_getrunningscripts);
    engine.register_function("getloadedmodules", lua_getloadedmodules);
    engine.register_function("getcallingscript", lua_getcallingscript);
    engine.register_function("isfolder", lua_isfolder);
    engine.register_function("delfile", lua_delfile);
}

void Environment::setup_websocket_lib(LuaEngine& engine) {
    lua_State* L = engine.state();
    lua_newtable(L);
    lua_pushcfunction(L, lua_websocket_connect);
    lua_setfield(L, -2, "connect");
    lua_setglobal(L, "WebSocket");
}

void Environment::setup_thread_lib(LuaEngine& engine) {
    (void)engine;
}

void Environment::setup_closure_lib(LuaEngine& engine) {
    Closures::register_all(engine.state());
}

void Environment::setup_drawing_bridge(LuaEngine& engine) {
    lua_State* L = engine.state();
    lua_pushcfunction(L, lua_drawing_new_bridge);
    lua_setglobal(L, "_oss_drawing_new");
    lua_pushcfunction(L, lua_drawing_set_bridge);
    lua_setglobal(L, "_oss_drawing_set");
    lua_pushcfunction(L, lua_drawing_remove_bridge);
    lua_setglobal(L, "_oss_drawing_remove");
}

void Environment::setup_gui_bridge(LuaEngine& engine) {
    lua_State* L = engine.state();
    lua_pushcfunction(L, lua_gui_create);
    lua_setglobal(L, "_oss_gui_create");
    lua_pushcfunction(L, lua_gui_set);
    lua_setglobal(L, "_oss_gui_set");
    lua_pushcfunction(L, lua_gui_set_parent);
    lua_setglobal(L, "_oss_gui_set_parent");
    lua_pushcfunction(L, lua_gui_remove);
    lua_setglobal(L, "_oss_gui_remove");
    lua_pushcfunction(L, lua_gui_clear);
    lua_setglobal(L, "_oss_gui_clear");
    lua_pushcfunction(L, lua_gui_get_screen_size);
    lua_setglobal(L, "_oss_gui_screen_size");
}

void Environment::setup_roblox_mock(LuaEngine& engine) {
    lua_State* L = engine.state();
    int status = oss_dostring(L, ROBLOX_MOCK_LUA, "=roblox_mock");
    if (status != 0) {
        const char* err = lua_tostring(L, -1);
        LOG_ERROR("Failed to init Roblox mock: {}", err ? err : "unknown error");
        lua_pop(L, 1);
    }
}

Environment& Environment::instance() {
    static Environment env;
    return env;
}

void Environment::setup(lua_State* L) {
    if (!L) return;

    lua_getfield(L, LUA_REGISTRYINDEX, "_oss_env_init");
    if (lua_toboolean(L, -1)) { lua_pop(L, 1); return; }
    lua_pop(L, 1);

    // Core globals
    lua_pushcfunction(L, lua_http_get);       lua_setglobal(L, "_oss_http_get");
    lua_pushcfunction(L, lua_http_get);       lua_setglobal(L, "HttpGet");
    lua_pushcfunction(L, lua_http_request);   lua_setglobal(L, "_oss_http_request");
    lua_pushcfunction(L, lua_typeof);         lua_setglobal(L, "typeof");
    lua_pushcfunction(L, lua_identify_executor); lua_setglobal(L, "identifyexecutor");
    lua_pushcfunction(L, lua_identify_executor); lua_setglobal(L, "getexecutorname");
    lua_pushcfunction(L, lua_printidentity);  lua_setglobal(L, "printidentity");

    // Drawing bridge
    lua_pushcfunction(L, lua_drawing_new_bridge);    lua_setglobal(L, "_oss_drawing_new");
    lua_pushcfunction(L, lua_drawing_set_bridge);    lua_setglobal(L, "_oss_drawing_set");
    lua_pushcfunction(L, lua_drawing_remove_bridge); lua_setglobal(L, "_oss_drawing_remove");

    // GUI bridge
    lua_pushcfunction(L, lua_gui_create);          lua_setglobal(L, "_oss_gui_create");
    lua_pushcfunction(L, lua_gui_set);             lua_setglobal(L, "_oss_gui_set");
    lua_pushcfunction(L, lua_gui_set_parent);      lua_setglobal(L, "_oss_gui_set_parent");
    lua_pushcfunction(L, lua_gui_remove);          lua_setglobal(L, "_oss_gui_remove");
    lua_pushcfunction(L, lua_gui_clear);           lua_setglobal(L, "_oss_gui_clear");
    lua_pushcfunction(L, lua_gui_get_screen_size); lua_setglobal(L, "_oss_gui_screen_size");

    // Debug library
    lua_getglobal(L, "debug");
    if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_newtable(L); }
    lua_pushcfunction(L, lua_debug_getinfo);      lua_setfield(L, -2, "getinfo");
    lua_pushcfunction(L, lua_debug_getupvalue);   lua_setfield(L, -2, "getupvalue");
    lua_pushcfunction(L, lua_debug_setupvalue);   lua_setfield(L, -2, "setupvalue");
    lua_pushcfunction(L, lua_debug_getupvalues);  lua_setfield(L, -2, "getupvalues");
    lua_pushcfunction(L, lua_debug_setupvalues);  lua_setfield(L, -2, "setupvalues");
    lua_pushcfunction(L, lua_debug_getconstant);  lua_setfield(L, -2, "getconstant");
    lua_pushcfunction(L, lua_debug_getconstants); lua_setfield(L, -2, "getconstants");
    lua_pushcfunction(L, lua_debug_setconstant);  lua_setfield(L, -2, "setconstant");
    lua_pushcfunction(L, lua_debug_getproto);     lua_setfield(L, -2, "getproto");
    lua_pushcfunction(L, lua_debug_getprotos);    lua_setfield(L, -2, "getprotos");
    lua_pushcfunction(L, lua_debug_getstack);     lua_setfield(L, -2, "getstack");
    lua_pushcfunction(L, lua_debug_setstack);     lua_setfield(L, -2, "setstack");
    lua_pushcfunction(L, lua_debug_getmetatable); lua_setfield(L, -2, "getmetatable");
    lua_pushcfunction(L, lua_debug_setmetatable); lua_setfield(L, -2, "setmetatable");
    lua_pushcfunction(L, lua_debug_getregistry);  lua_setfield(L, -2, "getregistry");
    lua_pushcfunction(L, lua_debug_traceback);    lua_setfield(L, -2, "traceback");
    lua_pushcfunction(L, lua_debug_profilebegin); lua_setfield(L, -2, "profilebegin");
    lua_pushcfunction(L, lua_debug_profileend);   lua_setfield(L, -2, "profileend");
    lua_setglobal(L, "debug");

    // Flat debug globals
    lua_pushcfunction(L, lua_debug_getinfo);      lua_setglobal(L, "getinfo");
    lua_pushcfunction(L, lua_debug_getupvalue);   lua_setglobal(L, "getupvalue");
    lua_pushcfunction(L, lua_debug_setupvalue);   lua_setglobal(L, "setupvalue");
    lua_pushcfunction(L, lua_debug_getupvalues);  lua_setglobal(L, "getupvalues");
    lua_pushcfunction(L, lua_debug_setupvalues);  lua_setglobal(L, "setupvalues");
    lua_pushcfunction(L, lua_debug_getconstant);  lua_setglobal(L, "getconstant");
    lua_pushcfunction(L, lua_debug_getconstants); lua_setglobal(L, "getconstants");
    lua_pushcfunction(L, lua_debug_setconstant);  lua_setglobal(L, "setconstant");
    lua_pushcfunction(L, lua_debug_getproto);     lua_setglobal(L, "getproto");
    lua_pushcfunction(L, lua_debug_getprotos);    lua_setglobal(L, "getprotos");
    lua_pushcfunction(L, lua_debug_getstack);     lua_setglobal(L, "getstack");
    lua_pushcfunction(L, lua_debug_setstack);     lua_setglobal(L, "setstack");

    // Cache library
    lua_newtable(L);
    lua_pushcfunction(L, lua_cache_invalidate); lua_setfield(L, -2, "invalidate");
    lua_pushcfunction(L, lua_cache_iscached);   lua_setfield(L, -2, "iscached");
    lua_pushcfunction(L, lua_cache_replace);    lua_setfield(L, -2, "replace");
    lua_setglobal(L, "cache");
    lua_pushcfunction(L, lua_cache_invalidate); lua_setglobal(L, "cache_invalidate");
    lua_pushcfunction(L, lua_cache_iscached);   lua_setglobal(L, "cache_iscached");
    lua_pushcfunction(L, lua_cache_replace);    lua_setglobal(L, "cache_replace");

    // Metatable functions
    lua_pushcfunction(L, lua_getrawmetatable);  lua_setglobal(L, "getrawmetatable");
    lua_pushcfunction(L, lua_setrawmetatable);  lua_setglobal(L, "setrawmetatable");
    lua_pushcfunction(L, lua_setreadonly);       lua_setglobal(L, "setreadonly");
    lua_pushcfunction(L, lua_isreadonly);        lua_setglobal(L, "isreadonly");
    lua_pushcfunction(L, lua_getnamecallmethod); lua_setglobal(L, "getnamecallmethod");

    // Input functions
    lua_pushcfunction(L, lua_fireclickdetector);  lua_setglobal(L, "fireclickdetector");
    lua_pushcfunction(L, lua_firetouchinterest);  lua_setglobal(L, "firetouchinterest");
    lua_pushcfunction(L, lua_fireproximityprompt); lua_setglobal(L, "fireproximityprompt");
    lua_pushcfunction(L, lua_setfpscap);          lua_setglobal(L, "setfpscap");
    lua_pushcfunction(L, lua_getfps);             lua_setglobal(L, "getfps");

    // Instance functions
    lua_pushcfunction(L, lua_getgenv);          lua_setglobal(L, "getgenv");
    lua_pushcfunction(L, lua_getrenv);          lua_setglobal(L, "getrenv");
    lua_pushcfunction(L, lua_getreg);           lua_setglobal(L, "getreg");
    lua_pushcfunction(L, lua_getgc);            lua_setglobal(L, "getgc");
    lua_pushcfunction(L, lua_gethui);           lua_setglobal(L, "gethui");
    lua_pushcfunction(L, lua_getinstances);     lua_setglobal(L, "getinstances");
    lua_pushcfunction(L, lua_getnilinstances);  lua_setglobal(L, "getnilinstances");
    lua_pushcfunction(L, lua_getconnections);   lua_setglobal(L, "getconnections");

    // Script functions
    lua_pushcfunction(L, lua_getscripts);        lua_setglobal(L, "getscripts");
    lua_pushcfunction(L, lua_getrunningscripts); lua_setglobal(L, "getrunningscripts");
    lua_pushcfunction(L, lua_getloadedmodules);  lua_setglobal(L, "getloadedmodules");
    lua_pushcfunction(L, lua_getcallingscript);  lua_setglobal(L, "getcallingscript");
    lua_pushcfunction(L, lua_isfolder);          lua_setglobal(L, "isfolder");
    lua_pushcfunction(L, lua_delfile);           lua_setglobal(L, "delfile");

    // WebSocket
    lua_newtable(L);
    lua_pushcfunction(L, lua_websocket_connect); lua_setfield(L, -2, "connect");
    lua_setglobal(L, "WebSocket");

    // Closures
    Closures::register_all(L);

    // Run Roblox mock
    int status = oss_dostring(L, ROBLOX_MOCK_LUA, "=roblox_mock");
    if (status != 0) {
        const char* err = lua_tostring(L, -1);
        LOG_ERROR("Failed to init Roblox mock: {}", err ? err : "unknown error");
        lua_pop(L, 1);
        return;
    }

    lua_pushboolean(L, 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "_oss_env_init");
    LOG_INFO("Environment initialized via setup(lua_State*)");
}

} // namespace oss




