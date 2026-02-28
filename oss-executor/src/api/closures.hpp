#pragma once

#include <lua.h>
#include <lualib.h>

#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

namespace oss {

class Closures {
public:
    static void register_all(lua_State* L);

    struct HookEntry {
        int original_ref = LUA_NOREF;
        int hook_ref     = LUA_NOREF;
        std::string name;
    };

    // ── Globals ──────────────────────────────────────────────
    static int l_print(lua_State* L);
    static int l_warn(lua_State* L);
    static int l_wait(lua_State* L);
    static int l_delay(lua_State* L);
    static int l_spawn(lua_State* L);
    static int l_loadstring(lua_State* L);
    static int l_typeof(lua_State* L);
    static int l_tick(lua_State* L);

    // ── Instance ─────────────────────────────────────────────
    static int l_instance_new(lua_State* L);
    static int l_instance_index(lua_State* L);
    static int l_instance_newindex(lua_State* L);
    static int l_instance_destroy(lua_State* L);
    static int l_instance_clone(lua_State* L);
    static int l_instance_getchildren(lua_State* L);
    static int l_instance_findfirstchild(lua_State* L);
    static int l_instance_waitforchild(lua_State* L);
    static int l_instance_isA(lua_State* L);

    // ── Data Types ───────────────────────────────────────────
    static int l_color3_new(lua_State* L);
    static int l_color3_fromRGB(lua_State* L);
    static int l_color3_fromHSV(lua_State* L);
    static int l_udim2_new(lua_State* L);
    static int l_udim2_fromScale(lua_State* L);
    static int l_udim2_fromOffset(lua_State* L);
    static int l_udim_new(lua_State* L);
    static int l_vector2_new(lua_State* L);
    static int l_vector3_new(lua_State* L);
    static int l_cframe_new(lua_State* L);
    static int l_tweeninfo_new(lua_State* L);
    static int l_numberrange_new(lua_State* L);
    static int l_colorsequence_new(lua_State* L);
    static int l_numbersequence_new(lua_State* L);

    // ── Drawing ──────────────────────────────────────────────
    static int l_drawing_new(lua_State* L);
    static int l_drawing_index(lua_State* L);
    static int l_drawing_newindex(lua_State* L);
    static int l_drawing_remove(lua_State* L);
    static int l_cleardrawcache(lua_State* L);

    // ── Services / Game ──────────────────────────────────────
    static int l_game_getservice(lua_State* L);
    static int l_game_httpget(lua_State* L);
    static int l_game_index(lua_State* L);

    // ── Executor ─────────────────────────────────────────────
    static int l_getgenv(lua_State* L);
    static int l_getrenv(lua_State* L);
    static int l_getrawmetatable(lua_State* L);
    static int l_setrawmetatable(lua_State* L);
    static int l_identifyexecutor(lua_State* L);
    static int l_setclipboard(lua_State* L);
    static int l_http_request(lua_State* L);
    static int l_getnamecallmethod(lua_State* L);
    static int l_fireclickdetector(lua_State* L);
    static int l_firetouchinterest(lua_State* L);
    static int l_fireproximityprompt(lua_State* L);
    static int l_gethui(lua_State* L);
    static int l_setfpscap(lua_State* L);

    // ── Closure Manipulation ─────────────────────────────────
    static int l_isexecutorclosure(lua_State* L);
    static int l_hookfunction(lua_State* L);
    static int l_hookmetamethod(lua_State* L);
    static int l_newcclosure(lua_State* L);
    static int l_checkcaller(lua_State* L);
    static int l_getinfo(lua_State* L);
    static int iscclosure(lua_State* L);
    static int islclosure(lua_State* L);
    static int checkclosure(lua_State* L);
    static int getscriptclosure(lua_State* L);
    static int compare_closures(lua_State* L);
    static int clone_function(lua_State* L);
    static int get_calling_script(lua_State* L);
    static int newlclosure(lua_State* L);

    // ── File System ──────────────────────────────────────────
    static int l_readfile(lua_State* L);
    static int l_writefile(lua_State* L);
    static int l_isfile(lua_State* L);
    static int l_isfolder(lua_State* L);
    static int l_makefolder(lua_State* L);
    static int l_listfiles(lua_State* L);
    static int l_delfile(lua_State* L);
    static int l_appendfile(lua_State* L);

    // ── Task Library ─────────────────────────────────────────
    static int l_task_wait(lua_State* L);
    static int l_task_spawn(lua_State* L);
    static int l_task_defer(lua_State* L);
    static int l_task_delay(lua_State* L);
    static int l_task_cancel(lua_State* L);

private:
    // ── Internal closure plumbing ────────────────────────────
    static int wrap_closure(lua_State* L);
    static int closure_handler(lua_State* L);
    static int get_script_closure(lua_State* L);
    static int newcclosure_handler(lua_State* L);
    static int newlclosure_handler(lua_State* L);
    static int loadstring_enhanced(lua_State* L);

    static const char* EXECUTOR_MARKER;
    static const char* HOOK_TABLE_KEY;

    static void ensure_hook_table(lua_State* L);
    static int  get_hook_table(lua_State* L);
};

} // namespace oss
