#include "environment.hpp"
#include "core/lua_engine.hpp"
#include "utils/http.hpp"
#include "utils/logger.hpp"
#include <cmath>
#include <cstring>
#include <sstream>

namespace oss {

// ═══════════════════════════════════════════════════════════════
// FIX #6: PHANTOM EXEC — COMPREHENSIVE ROBLOX API MOCK
//
// The ESP script loaded via loadstring(game:HttpGet(...))() does:
//
//   local Players = game:GetService("Players")       ← needs GetService
//   local Camera  = workspace.CurrentCamera           ← needs workspace global
//   RunService.RenderStepped:Connect(function(dt)     ← needs event system
//       for _, player in pairs(Players:GetPlayers())  ← needs GetPlayers
//           ...
//
// BEFORE: game = { HttpGet = <cfunction> }
//         → game:GetService("Players") errors: "attempt to call nil"
//         → warn("Phantom exec:")
//
// AFTER:  Full proxy-based mock with:
//         • game:GetService(name) returning service stubs
//         • workspace global with CurrentCamera
//         • Signal objects with :Connect(), :Wait()
//         • Instance.new() returning proxy objects
//         • Vector3, CFrame, Color3, UDim2 math types
//         • typeof() checking __type metafield
//
// Scripts won't render ESP boxes (no real rendering backend),
// but they won't CRASH either.  They execute cleanly and the
// user sees "Script loaded" instead of "Phantom exec:".
// ═══════════════════════════════════════════════════════════════

// ── C-side helpers registered into Lua ──────────────────────────

// typeof() — checks for __type in metatable, falls back to type()
static int lua_typeof(lua_State* L) {
    if (lua_getmetatable(L, 1)) {
        lua_getfield(L, -1, "__type");
        if (lua_isstring(L, -1)) {
            return 1;   // return the __type string
        }
        lua_pop(L, 2);  // pop nil + metatable
    }
    lua_pushstring(L, luaL_typename(L, 1));
    return 1;
}

// game:HttpGet(url) — downloads URL body via libcurl
static int lua_http_get(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);

    // Accept both game:HttpGet(url) and game.HttpGet(url)
    // If called as method, arg 1 is self (table), arg 2 is url
    if (lua_istable(L, 1) || lua_isuserdata(L, 1)) {
        url = luaL_checkstring(L, 2);
    }

    try {
        auto response = Http::instance().get(url);
        if (response.success()) {
            lua_pushlstring(L, response.body.data(), response.body.size());
        } else {
            lua_pushstring(L, "");
            LOG_WARN("HttpGet failed for '{}': HTTP {}", url, response.status_code);
        }
    } catch (const std::exception& e) {
        lua_pushstring(L, "");
        LOG_ERROR("HttpGet exception for '{}': {}", url, e.what());
    }
    return 1;
}

// http.request{Url=..., Method=...} — syn.request compatible
static int lua_http_request(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    lua_getfield(L, 1, "Url");
    if (!lua_isstring(L, -1)) {
        lua_getfield(L, 1, "url");  // try lowercase
    }
    const char* url = luaL_optstring(L, -1, "");
    lua_pop(L, 1);

    lua_getfield(L, 1, "Method");
    if (!lua_isstring(L, -1)) {
        lua_getfield(L, 1, "method");
    }
    std::string method = luaL_optstring(L, -1, "GET");
    lua_pop(L, 1);

    HttpResponse resp;
    if (method == "POST") {
        lua_getfield(L, 1, "Body");
        std::string body = luaL_optstring(L, -1, "");
        lua_pop(L, 1);
        resp = Http::instance().post(url, body);
    } else {
        resp = Http::instance().get(url);
    }

    // Return {StatusCode=N, Body="...", Success=bool, Headers={}}
    lua_newtable(L);
    lua_pushinteger(L, resp.status_code);
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

// identifyexecutor() / getexecutorname()
static int lua_identify_executor(lua_State* L) {
    lua_pushstring(L, "OSS Executor");
    lua_pushstring(L, "2.0.0");
    return 2;
}

// ── The big Lua-side mock setup ─────────────────────────────────
// This runs once during Environment::setup() and creates the full
// Roblox API surface as Lua tables with metatables.

static const char* ROBLOX_MOCK_LUA = R"LUA(
-- ═════════════════════════════════════════════════════════════
-- ROBLOX API MOCK — runs inside LuaJIT sandbox
-- Makes loadstring(game:HttpGet(...))() not crash
-- ═════════════════════════════════════════════════════════════

-- ── Signal (RBXScriptSignal mock) ────────────────────────────
local Signal = {}
Signal.__index = Signal
Signal.__type  = "RBXScriptSignal"

function Signal.new(name)
    return setmetatable({
        _name = name or "Signal",
        _connections = {},
    }, Signal)
end

function Signal:Connect(fn)
    if type(fn) ~= "function" then return end
    local conn = setmetatable({
        Connected = true,
        _fn = fn,
        _signal = self,
    }, {
        __type = "RBXScriptConnection",
        __index = {
            Disconnect = function(self)
                self.Connected = false
            end,
        },
    })
    table.insert(self._connections, conn)
    return conn
end
Signal.connect = Signal.Connect

function Signal:Wait()
    return 0   -- immediate return, no yield
end

function Signal:Fire(...)
    for _, conn in ipairs(self._connections) do
        if conn.Connected then
            pcall(conn._fn, ...)
        end
    end
end

-- ── Vector3 ──────────────────────────────────────────────────
local Vector3 = {}
Vector3.__index = Vector3
Vector3.__type  = "Vector3"

function Vector3.new(x, y, z)
    return setmetatable({
        X = x or 0, Y = y or 0, Z = z or 0,
        x = x or 0, y = y or 0, z = z or 0,
        Magnitude = math.sqrt((x or 0)^2 + (y or 0)^2 + (z or 0)^2),
        Unit = nil,  -- set below
    }, Vector3)
end
Vector3.zero = Vector3.new(0, 0, 0)
Vector3.one  = Vector3.new(1, 1, 1)

function Vector3:Lerp(goal, alpha)
    return Vector3.new(
        self.X + (goal.X - self.X) * alpha,
        self.Y + (goal.Y - self.Y) * alpha,
        self.Z + (goal.Z - self.Z) * alpha
    )
end
function Vector3:Dot(other)
    return self.X * other.X + self.Y * other.Y + self.Z * other.Z
end
function Vector3:Cross(other)
    return Vector3.new(
        self.Y * other.Z - self.Z * other.Y,
        self.Z * other.X - self.X * other.Z,
        self.X * other.Y - self.Y * other.X
    )
end
function Vector3.__add(a, b)
    return Vector3.new(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
end
function Vector3.__sub(a, b)
    return Vector3.new(a.X - b.X, a.Y - b.Y, a.Z - b.Z)
end
function Vector3.__mul(a, b)
    if type(a) == "number" then return Vector3.new(a * b.X, a * b.Y, a * b.Z) end
    if type(b) == "number" then return Vector3.new(a.X * b, a.Y * b, a.Z * b) end
    return Vector3.new(a.X * b.X, a.Y * b.Y, a.Z * b.Z)
end
function Vector3.__div(a, b)
    if type(b) == "number" then return Vector3.new(a.X / b, a.Y / b, a.Z / b) end
    return Vector3.new(a.X / b.X, a.Y / b.Y, a.Z / b.Z)
end
function Vector3.__unm(a)
    return Vector3.new(-a.X, -a.Y, -a.Z)
end
function Vector3.__eq(a, b)
    return a.X == b.X and a.Y == b.Y and a.Z == b.Z
end
function Vector3.__tostring(v)
    return string.format("%.4f, %.4f, %.4f", v.X, v.Y, v.Z)
end

-- ── Vector2 ──────────────────────────────────────────────────
local Vector2 = {}
Vector2.__index = Vector2
Vector2.__type  = "Vector2"

function Vector2.new(x, y)
    return setmetatable({
        X = x or 0, Y = y or 0,
        x = x or 0, y = y or 0,
        Magnitude = math.sqrt((x or 0)^2 + (y or 0)^2),
    }, Vector2)
end
Vector2.zero = Vector2.new(0, 0)
Vector2.one  = Vector2.new(1, 1)

function Vector2.__add(a, b) return Vector2.new(a.X + b.X, a.Y + b.Y) end
function Vector2.__sub(a, b) return Vector2.new(a.X - b.X, a.Y - b.Y) end
function Vector2.__mul(a, b)
    if type(a) == "number" then return Vector2.new(a * b.X, a * b.Y) end
    if type(b) == "number" then return Vector2.new(a.X * b, a.Y * b) end
    return Vector2.new(a.X * b.X, a.Y * b.Y)
end
function Vector2.__div(a, b)
    if type(b) == "number" then return Vector2.new(a.X / b, a.Y / b) end
    return Vector2.new(a.X / b.X, a.Y / b.Y)
end
function Vector2.__tostring(v)
    return string.format("%.4f, %.4f", v.X, v.Y)
end

-- ── Color3 ───────────────────────────────────────────────────
local Color3 = {}
Color3.__index = Color3
Color3.__type  = "Color3"

function Color3.new(r, g, b)
    return setmetatable({ R = r or 0, G = g or 0, B = b or 0 }, Color3)
end
function Color3.fromRGB(r, g, b)
    return Color3.new((r or 0)/255, (g or 0)/255, (b or 0)/255)
end
function Color3.fromHSV(h, s, v)
    -- simplified HSV→RGB
    local c = v * s
    local x = c * (1 - math.abs((h * 6) % 2 - 1))
    local m = v - c
    local r, g, b = m, m, m
    local sector = math.floor(h * 6) % 6
    if     sector == 0 then r, g = r + c, g + x
    elseif sector == 1 then r, g = r + x, g + c
    elseif sector == 2 then g, b = g + c, b + x
    elseif sector == 3 then g, b = g + x, b + c
    elseif sector == 4 then r, b = r + x, b + c
    else                    r, b = r + c, b + x end
    return Color3.new(r, g, b)
end
function Color3:Lerp(goal, alpha)
    return Color3.new(
        self.R + (goal.R - self.R) * alpha,
        self.G + (goal.G - self.G) * alpha,
        self.B + (goal.B - self.B) * alpha
    )
end
function Color3.__tostring(c)
    return string.format("%.4f, %.4f, %.4f", c.R, c.G, c.B)
end

-- ── UDim / UDim2 ─────────────────────────────────────────────
local UDim = {}
UDim.__index = UDim
UDim.__type  = "UDim"
function UDim.new(scale, offset)
    return setmetatable({ Scale = scale or 0, Offset = offset or 0 }, UDim)
end

local UDim2 = {}
UDim2.__index = UDim2
UDim2.__type  = "UDim2"
function UDim2.new(xs, xo, ys, yo)
    return setmetatable({
        X = UDim.new(xs or 0, xo or 0),
        Y = UDim.new(ys or 0, yo or 0),
        Width  = UDim.new(xs or 0, xo or 0),
        Height = UDim.new(ys or 0, yo or 0),
    }, UDim2)
end
function UDim2.fromScale(xs, ys) return UDim2.new(xs, 0, ys, 0) end
function UDim2.fromOffset(xo, yo) return UDim2.new(0, xo, 0, yo) end
function UDim2.__tostring(u)
    return string.format("{%g, %d}, {%g, %d}",
        u.X.Scale, u.X.Offset, u.Y.Scale, u.Y.Offset)
end

-- ── CFrame ───────────────────────────────────────────────────
local CFrame = {}
CFrame.__index = CFrame
CFrame.__type  = "CFrame"

function CFrame.new(x, y, z)
    if type(x) == "table" and x.X then
        -- CFrame.new(Vector3)
        return setmetatable({
            Position   = x,
            X = x.X, Y = x.Y, Z = x.Z,
            LookVector = Vector3.new(0, 0, -1),
            RightVector= Vector3.new(1, 0, 0),
            UpVector   = Vector3.new(0, 1, 0),
            p          = x,
        }, CFrame)
    end
    local pos = Vector3.new(x or 0, y or 0, z or 0)
    return setmetatable({
        Position   = pos,
        X = pos.X, Y = pos.Y, Z = pos.Z,
        LookVector = Vector3.new(0, 0, -1),
        RightVector= Vector3.new(1, 0, 0),
        UpVector   = Vector3.new(0, 1, 0),
        p          = pos,
    }, CFrame)
end
CFrame.identity = CFrame.new(0, 0, 0)

function CFrame:Inverse() return CFrame.new(-self.X, -self.Y, -self.Z) end
function CFrame:Lerp(goal, alpha)
    return CFrame.new(
        self.X + (goal.X - self.X) * alpha,
        self.Y + (goal.Y - self.Y) * alpha,
        self.Z + (goal.Z - self.Z) * alpha
    )
end
function CFrame:PointToWorldSpace(v3)
    return Vector3.new(self.X + v3.X, self.Y + v3.Y, self.Z + v3.Z)
end
function CFrame:PointToObjectSpace(v3)
    return Vector3.new(v3.X - self.X, v3.Y - self.Y, v3.Z - self.Z)
end
function CFrame.__mul(a, b)
    if getmetatable(b) == Vector3 then
        return Vector3.new(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
    end
    return CFrame.new(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
end
function CFrame.__tostring(cf)
    return string.format("%.4f, %.4f, %.4f, ...", cf.X, cf.Y, cf.Z)
end

-- ── Instance mock ────────────────────────────────────────────
-- Creates a table that looks like a Roblox Instance:
--   • .Name, .ClassName, .Parent
--   • :IsA(), :FindFirstChild(), :GetChildren(), :Destroy()
--   • Arbitrary property read/write via __index/__newindex
--   • Children stored internally

local function make_instance(class_name, name, parent)
    local children = {}
    local properties = {}
    local events = {}

    local inst = {}
    local mt = {
        __type = "Instance",
        __tostring = function() return name or class_name end,
    }

    -- Property access
    mt.__index = function(self, key)
        if key == "Name"      then return name or class_name end
        if key == "ClassName" then return class_name end
        if key == "Parent"    then return parent end

        -- Methods
        if key == "IsA" then
            return function(_, check)
                return check == class_name or check == "Instance"
                       or check == "GuiObject" or check == "BasePart"
            end
        end
        if key == "FindFirstChild" then
            return function(_, child_name)
                for _, c in ipairs(children) do
                    if (type(c) == "table" and rawget(c, "Name") == child_name)
                       or tostring(c) == child_name then
                        return c
                    end
                end
                return nil
            end
        end
        if key == "FindFirstChildOfClass" then
            return function(_, cls)
                for _, c in ipairs(children) do
                    if type(c) == "table" and rawget(c, "ClassName") == cls then
                        return c
                    end
                end
                return nil
            end
        end
        if key == "WaitForChild" then
            return function(_, child_name)
                return rawget(mt, "__index")(self, "FindFirstChild")(self, child_name)
            end
        end
        if key == "GetChildren" or key == "getChildren" then
            return function() return children end
        end
        if key == "GetDescendants" then
            return function() return children end  -- simplified
        end
        if key == "Clone" then
            return function()
                return make_instance(class_name, name, nil)
            end
        end
        if key == "Destroy" or key == "Remove" then
            return function() end  -- no-op
        end
        if key == "ClearAllChildren" then
            return function() children = {} end
        end

        -- Events
        if key == "Changed" or key == "ChildAdded" or key == "ChildRemoved"
           or key == "AncestryChanged" or key == "Destroying" then
            if not events[key] then events[key] = Signal.new(key) end
            return events[key]
        end

        -- Stored properties
        if properties[key] ~= nil then return properties[key] end

        -- Unknown — return nil (not error)
        return nil
    end

    mt.__newindex = function(self, key, value)
        if key == "Name" then name = value
        elseif key == "Parent" then
            parent = value
        else
            properties[key] = value
        end
    end

    setmetatable(inst, mt)
    return inst, children, properties
end

-- ── Instance.new() ───────────────────────────────────────────
local InstanceModule = {}
function InstanceModule.new(class_name, parent)
    local inst, children, props = make_instance(class_name, class_name, parent)

    -- Set defaults based on class
    if class_name == "ScreenGui" or class_name == "BillboardGui"
       or class_name == "SurfaceGui" then
        props.Enabled = true
        props.ResetOnSpawn = true
    elseif class_name == "Frame" or class_name == "TextLabel"
           or class_name == "TextButton" or class_name == "ImageLabel" then
        props.Size = UDim2.new(0, 100, 0, 100)
        props.Position = UDim2.new(0, 0, 0, 0)
        props.BackgroundColor3 = Color3.new(1, 1, 1)
        props.BackgroundTransparency = 0
        props.Visible = true
        props.Text = ""
        props.TextColor3 = Color3.new(0, 0, 0)
        props.TextSize = 14
        props.Font = 0  -- Enum.Font.Legacy
        props.ZIndex = 1
    elseif class_name == "Part" or class_name == "MeshPart"
           or class_name == "UnionOperation" then
        props.Position = Vector3.new(0, 0, 0)
        props.Size = Vector3.new(4, 1, 2)
        props.CFrame = CFrame.new(0, 0, 0)
        props.Anchored = false
        props.CanCollide = true
        props.Transparency = 0
        props.BrickColor = "Medium stone grey"
        props.Color = Color3.fromRGB(163, 162, 165)
    elseif class_name == "Folder" then
        -- just a container
    elseif class_name == "UICorner" then
        props.CornerRadius = UDim.new(0, 8)
    elseif class_name == "UIStroke" then
        props.Thickness = 1
        props.Color = Color3.new(0, 0, 0)
        props.Transparency = 0
    end

    return inst
end

-- ── Drawing library mock ─────────────────────────────────────
-- ESP scripts use Drawing.new("Line"), Drawing.new("Text"), etc.
local DrawingMT = {}
DrawingMT.__index = DrawingMT
DrawingMT.__type  = "Drawing"

local Drawing = {
    Fonts = {
        UI     = 0,
        System = 1,
        Plex   = 2,
        Monospace = 3,
    }
}

function Drawing.new(class_name)
    local obj = {
        Visible      = false,
        Color        = Color3.new(1, 1, 1),
        Transparency = 0,
        Thickness    = 1,
        ZIndex       = 0,
        -- Line
        From         = Vector2.new(0, 0),
        To           = Vector2.new(0, 0),
        -- Text
        Text         = "",
        Size         = 14,
        Center       = false,
        Outline      = false,
        OutlineColor = Color3.new(0, 0, 0),
        Position     = Vector2.new(0, 0),
        TextBounds   = Vector2.new(0, 0),
        Font         = 0,
        -- Circle
        Radius       = 50,
        NumSides     = 32,
        Filled       = false,
        -- Square / Quad
        PointA       = Vector2.new(0, 0),
        PointB       = Vector2.new(0, 0),
        PointC       = Vector2.new(0, 0),
        PointD       = Vector2.new(0, 0),
        -- Image
        Data         = "",
        Rounding     = 0,
        -- Meta
        _class       = class_name or "Line",
    }

    function obj:Remove() self.Visible = false end
    function obj:Destroy() self.Visible = false end

    return setmetatable(obj, DrawingMT)
end

-- ── Enum mock ────────────────────────────────────────────────
local EnumMock = setmetatable({}, {
    __index = function(self, enum_type)
        local enum = setmetatable({}, {
            __index = function(_, item_name)
                return {
                    Name  = item_name,
                    Value = 0,
                    EnumType = enum_type,
                }
            end,
            __type = "Enum",
            __tostring = function() return "Enum." .. enum_type end,
        })
        rawset(self, enum_type, enum)
        return enum
    end,
    __type = "Enums",
})

-- ── Service stubs ────────────────────────────────────────────
local service_cache = {}

local function get_camera()
    local cam, _, props = make_instance("Camera", "Camera")
    props.CFrame          = CFrame.new(0, 10, 0)
    props.ViewportSize    = Vector2.new(1920, 1080)
    props.FieldOfView     = 70
    props.NearPlaneZ      = 0.1
    props.FarPlaneZ       = 10000
    props.Focus           = CFrame.new(0, 0, 0)
    props.CameraType      = EnumMock.CameraType.Custom
    props.CameraSubject   = nil

    -- Camera:WorldToViewportPoint / WorldToScreenPoint
    rawset(cam, "WorldToViewportPoint", function(_, v3)
        -- stub: return center of screen + depth + visible
        return Vector3.new(960, 540, (v3 and v3.Z or 10)), true
    end)
    rawset(cam, "WorldToScreenPoint", function(self, v3)
        return self:WorldToViewportPoint(v3)
    end)
    rawset(cam, "ViewportPointToRay", function(_, x, y)
        return {
            Origin    = Vector3.new(x or 0, y or 0, 0),
            Direction = Vector3.new(0, 0, -1),
        }
    end)

    return cam
end

local function make_service(name)
    if service_cache[name] then return service_cache[name] end

    local svc, children, props = make_instance(name, name)

    if name == "Players" then
        local lp, _, lp_props = make_instance("Player", "LocalPlayer")
        lp_props.Name            = "LocalPlayer"
        lp_props.DisplayName     = "Player"
        lp_props.UserId          = 1
        lp_props.TeamColor       = Color3.new(1, 1, 1)
        lp_props.Team            = nil

        -- Character stub
        local char, char_children = make_instance("Model", "LocalPlayer")
        local hrp, _, hrp_props   = make_instance("Part", "HumanoidRootPart", char)
        hrp_props.Position = Vector3.new(0, 3, 0)
        hrp_props.CFrame   = CFrame.new(0, 3, 0)
        hrp_props.Size     = Vector3.new(2, 2, 1)

        local head, _, head_props = make_instance("Part", "Head", char)
        head_props.Position = Vector3.new(0, 4.5, 0)
        head_props.CFrame   = CFrame.new(0, 4.5, 0)
        head_props.Size     = Vector3.new(2, 1, 1)

        local hum, _, hum_props = make_instance("Humanoid", "Humanoid", char)
        hum_props.Health    = 100
        hum_props.MaxHealth = 100
        hum_props.WalkSpeed = 16
        hum_props.JumpPower = 50

        table.insert(char_children, hrp)
        table.insert(char_children, head)
        table.insert(char_children, hum)

        lp_props.Character = char

        rawset(lp, "GetMouse", function()
            local mouse, _, mp = make_instance("Mouse", "Mouse")
            mp.X = 0
            mp.Y = 0
            mp.Hit = CFrame.new(0, 0, 0)
            mp.Target = nil
            return mouse
        end)

        props.LocalPlayer = lp
        table.insert(children, lp)

        rawset(svc, "GetPlayers", function()
            return { lp }
        end)

        -- Events
        props.PlayerAdded   = Signal.new("PlayerAdded")
        props.PlayerRemoving = Signal.new("PlayerRemoving")

    elseif name == "RunService" then
        props.RenderStepped  = Signal.new("RenderStepped")
        props.Heartbeat      = Signal.new("Heartbeat")
        props.Stepped        = Signal.new("Stepped")

        rawset(svc, "IsClient", function() return true end)
        rawset(svc, "IsServer", function() return false end)
        rawset(svc, "IsStudio", function() return false end)
        rawset(svc, "BindToRenderStep", function(_, name_arg, priority, fn)
            -- Store but don't fire
            if type(fn) == "function" then
                props.RenderStepped:Connect(fn)
            end
        end)
        rawset(svc, "UnbindFromRenderStep", function() end)

    elseif name == "Workspace" then
        props.CurrentCamera  = get_camera()
        props.Gravity        = 196.2
        props.DistributedGameTime = 0
        rawset(svc, "Raycast", function(_, origin, direction, params)
            return nil  -- no hit
        end)

    elseif name == "UserInputService" then
        props.MouseEnabled    = true
        props.KeyboardEnabled = true
        props.TouchEnabled    = false
        props.GamepadEnabled  = false
        props.MouseBehavior   = EnumMock.MouseBehavior.Default
        props.InputBegan      = Signal.new("InputBegan")
        props.InputEnded      = Signal.new("InputEnded")
        props.InputChanged    = Signal.new("InputChanged")

        rawset(svc, "GetMouseLocation", function()
            return Vector2.new(960, 540)
        end)
        rawset(svc, "IsKeyDown", function() return false end)
        rawset(svc, "IsMouseButtonPressed", function() return false end)

    elseif name == "CoreGui" or name == "StarterGui" then
        -- container for ScreenGuis
        rawset(svc, "SetCoreGuiEnabled", function() end)
        rawset(svc, "GetCoreGuiEnabled", function() return true end)

    elseif name == "TweenService" then
        rawset(svc, "Create", function(_, instance, info, props_table)
            local tween = {
                Play   = function() end,
                Cancel = function() end,
                Pause  = function() end,
                Completed = Signal.new("Completed"),
            }
            return tween
        end)

    elseif name == "HttpService" then
        rawset(svc, "JSONEncode", function(_, obj)
            -- minimal: just tostring tables
            if type(obj) == "string" then return '"' .. obj .. '"' end
            return tostring(obj)
        end)
        rawset(svc, "JSONDecode", function(_, str)
            -- can't do real JSON in pure Lua without a library
            return {}
        end)
        rawset(svc, "GenerateGUID", function(_, wrap)
            local g = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
            g = g:gsub("[xy]", function(c)
                local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
                return string.format("%x", v)
            end)
            if wrap == false then return g end
            return "{" .. g .. "}"
        end)

    elseif name == "ReplicatedStorage" or name == "ServerStorage"
           or name == "ServerScriptService" or name == "Lighting"
           or name == "SoundService" or name == "Chat"
           or name == "Teams" or name == "TestService"
           or name == "ProximityPromptService" then
        -- generic empty service
    end

    service_cache[name] = svc
    return svc
end

-- ── game object ──────────────────────────────────────────────
-- The actual `game` global that scripts interact with

local game_mt = {
    __type = "DataModel",
    __tostring = function() return "Game" end,
}

game_mt.__index = function(self, key)
    -- Methods
    if key == "GetService" then
        return function(_, service_name)
            return make_service(service_name)
        end
    end
    if key == "FindService" then
        return function(_, service_name)
            return make_service(service_name)
        end
    end

    -- HttpGet/HttpPost — connected to real HTTP via C
    if key == "HttpGet" or key == "HttpGetAsync" then
        return _G._oss_http_get   -- set from C side
    end
    if key == "HttpPost" or key == "HttpPostAsync" then
        return function(_, url, body)
            return ""  -- stub
        end
    end

    -- Properties
    if key == "PlaceId"      then return 0 end
    if key == "PlaceVersion" then return 1 end
    if key == "GameId"       then return 0 end
    if key == "JobId"        then return "" end
    if key == "CreatorId"    then return 0 end
    if key == "CreatorType"  then return "User" end

    -- IsA
    if key == "IsA" then
        return function(_, class)
            return class == "DataModel" or class == "Instance"
        end
    end

    -- FindFirstChild/WaitForChild — try as service
    if key == "FindFirstChild" or key == "WaitForChild" then
        return function(_, name)
            return make_service(name)
        end
    end

    if key == "GetChildren" or key == "GetDescendants" then
        return function() return {} end
    end

    if key == "BindToClose" then
        return function() end
    end

    -- Service shorthand: game.Workspace, game.Players, etc.
    local ok, svc = pcall(make_service, key)
    if ok and svc then return svc end

    return nil
end

game = setmetatable({}, game_mt)

-- ── Global aliases ───────────────────────────────────────────
workspace = make_service("Workspace")

-- Roblox globals
Instance = InstanceModule
Enum     = EnumMock

-- Overwrite type constructors
_G.Vector3 = Vector3
_G.Vector2 = Vector2
_G.Color3  = Color3
_G.UDim    = UDim
_G.UDim2   = UDim2
_G.CFrame  = CFrame
_G.Drawing = Drawing

-- Roblox global functions
wait = function(t)
    -- Can't truly yield in this sandbox, just return elapsed
    return t or 0, t or 0
end

spawn = function(fn)
    if type(fn) == "function" then pcall(fn) end
end

delay = function(t, fn)
    if type(fn) == "function" then pcall(fn) end
end

tick = function()
    return os.clock()
end

time = function()
    return os.clock()
end

-- task library
task = {
    wait  = function(t) return t or 0 end,
    spawn = function(fn, ...) if type(fn) == "function" then pcall(fn, ...) end end,
    defer = function(fn, ...) if type(fn) == "function" then pcall(fn, ...) end end,
    delay = function(t, fn, ...) if type(fn) == "function" then pcall(fn, ...) end end,
    cancel = function() end,
    synchronize = function() end,
    desynchronize = function() end,
}

-- shared / _G
shared = shared or {}
_G     = _G    or {}

-- TweenInfo
TweenInfo = {}
function TweenInfo.new(time_val, style, direction, repeat_count, reverses, delay_time)
    return {
        Time = time_val or 1,
        EasingStyle = style or EnumMock.EasingStyle.Quad,
        EasingDirection = direction or EnumMock.EasingDirection.Out,
        RepeatCount = repeat_count or 0,
        Reverses = reverses or false,
        DelayTime = delay_time or 0,
    }
end

-- Ray
Ray = {}
function Ray.new(origin, direction)
    return {
        Origin    = origin or Vector3.new(),
        Direction = direction or Vector3.new(0, 0, -1),
        Unit      = nil,
    }
end

-- RaycastParams
RaycastParams = {}
function RaycastParams.new()
    return {
        FilterType = EnumMock.RaycastFilterType.Exclude,
        FilterDescendantsInstances = {},
    }
end

-- NumberSequence / ColorSequence
NumberSequenceKeypoint = {}
function NumberSequenceKeypoint.new(t, v, e)
    return { Time = t or 0, Value = v or 0, Envelope = e or 0 }
end
NumberSequence = {}
function NumberSequence.new(...)
    local args = {...}
    if type(args[1]) == "number" then
        return { Keypoints = {
            NumberSequenceKeypoint.new(0, args[1]),
            NumberSequenceKeypoint.new(1, args[2] or args[1]),
        }}
    end
    return { Keypoints = args[1] or {} }
end

ColorSequenceKeypoint = {}
function ColorSequenceKeypoint.new(t, c)
    return { Time = t or 0, Value = c or Color3.new() }
end
ColorSequence = {}
function ColorSequence.new(...)
    local args = {...}
    if getmetatable(args[1]) == Color3 then
        return { Keypoints = {
            ColorSequenceKeypoint.new(0, args[1]),
            ColorSequenceKeypoint.new(1, args[2] or args[1]),
        }}
    end
    return { Keypoints = args[1] or {} }
end

-- BrickColor
BrickColor = {}
function BrickColor.new(name_or_r, g, b)
    if type(name_or_r) == "string" then
        return { Name = name_or_r, Color = Color3.new(0.64, 0.64, 0.64) }
    end
    return { Name = "Custom", Color = Color3.fromRGB(name_or_r or 0, g or 0, b or 0) }
end

-- string.split (Roblox extension)
if not string.split then
    function string.split(str, sep)
        sep = sep or ","
        local parts = {}
        local pattern = "([^" .. sep .. "]*)" .. sep .. "?"
        str:gsub(pattern, function(c)
            if #c > 0 or #parts == 0 then
                table.insert(parts, c)
            end
        end)
        return parts
    end
end

-- ── Executor-specific globals ────────────────────────────────
syn = {
    request = _G._oss_http_request or function() return {} end,
    crypt = {
        base64encode = function(s) return s end,
        base64decode = function(s) return s end,
    },
}

request      = syn.request
http_request = syn.request

getgenv = function() return _G end
getrenv = function() return _G end
getreg  = function() return {} end
getgc   = function() return {} end

gethui = function()
    return make_service("CoreGui")
end

isexecutorclosure = function() return false end
checkcaller       = function() return false end
islclosure        = function(f) return type(f) == "function" end
iscclosure        = function(f) return type(f) == "function" end

hookfunction = function(old, new) return old end
newcclosure  = function(fn) return fn end
hookmetamethod = function(obj, method, hook) return function() end end

getrawmetatable = function(t) return getmetatable(t) end
setrawmetatable = function(t, mt) return setmetatable(t, mt) end
setreadonly     = function() end
isreadonly      = function() return false end

fireclickdetector   = function() end
firetouchinterest   = function() end
fireproximityprompt = function() end

setclipboard = function() end
getclipboard = function() return "" end

-- File system stubs
readfile    = function(path) return "" end
writefile   = function(path, data) end
appendfile  = function(path, data) end
isfile      = function(path) return false end
isfolder    = function(path) return false end
listfiles   = function(path) return {} end
makefolder  = function(path) end
delfolder   = function(path) end
delfile     = function(path) end

-- ── Done ─────────────────────────────────────────────────────
-- The ESP script can now call:
--   game:GetService("Players")           → returns Player service mock
--   workspace.CurrentCamera               → returns Camera mock
--   RunService.RenderStepped:Connect(fn)  → stores fn, doesn't fire
--   Drawing.new("Line")                   → returns Drawing mock
--
-- Scripts execute without error.  Visuals won't render (no GPU backend
-- in sandbox), but the loadstring chain completes successfully.

)LUA";

// ═══════════════════════════════════════════════════════════════
// Environment::setup — registers C functions + runs Lua mock
// ═══════════════════════════════════════════════════════════════

void Environment::setup(LuaEngine& engine) {
    lua_State* L = engine.state();
    if (!L) {
        LOG_ERROR("Environment::setup called with null Lua state");
        return;
    }

    // ── Register C functions that need real system access ────

    // _oss_http_get — used by game:HttpGet() in the Lua mock
    lua_pushcfunction(L, lua_http_get);
    lua_setglobal(L, "_oss_http_get");

    // _oss_http_request — used by syn.request / http.request
    lua_pushcfunction(L, lua_http_request);
    lua_setglobal(L, "_oss_http_request");

    // typeof — checks __type in metatable
    lua_pushcfunction(L, lua_typeof);
    lua_setglobal(L, "typeof");

    // identifyexecutor / getexecutorname
    lua_pushcfunction(L, lua_identify_executor);
    lua_setglobal(L, "identifyexecutor");
    lua_pushcfunction(L, lua_identify_executor);
    lua_setglobal(L, "getexecutorname");

    // printidentity
    lua_pushcfunction(L, [](lua_State* L) -> int {
        lua_pushstring(L, "Current identity is 7");
        return 1;
    });
    lua_setglobal(L, "printidentity");

    // ── Run the Lua mock setup ──────────────────────────────
    int status = luaL_dostring(L, ROBLOX_MOCK_LUA);
    if (status != 0) {
        const char* err = lua_tostring(L, -1);
        LOG_ERROR("Failed to initialize Roblox mock environment: {}",
                  err ? err : "unknown error");
        lua_pop(L, 1);
    } else {
        LOG_INFO("Roblox API mock environment initialized successfully");
    }
}

} // namespace oss

