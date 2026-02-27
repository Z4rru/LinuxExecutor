#include "environment.hpp"
#include "../core/lua_engine.hpp"
#include "../utils/http.hpp"
#include "../utils/logger.hpp"
#include "../ui/overlay.hpp"
#include <cmath>
#include <cstring>
#include <sstream>

namespace oss {

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
    if (lua_gettop(L) < url_index) return luaL_error(L, "HttpGet: expected URL argument");
    const char* url = luaL_checkstring(L, url_index);
    if (!url || strlen(url) == 0) return luaL_error(L, "HttpGet: URL cannot be empty");
    std::string surl(url);
    if (surl.rfind("http://", 0) != 0 && surl.rfind("https://", 0) != 0)
        return luaL_error(L, "HttpGet: URL must start with http:// or https://");
    try {
        auto response = Http::instance().get(surl);
        if (response.success()) {
            lua_pushlstring(L, response.body.data(), response.body.size());
        } else {
            return luaL_error(L, "HttpGet failed: HTTP %d for '%s'%s%s",
                response.status_code, surl.c_str(),
                response.error.empty() ? "" : " - ",
                response.error.empty() ? "" : response.error.c_str());
        }
    } catch (const std::exception& e) {
        return luaL_error(L, "HttpGet exception: %s", e.what());
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

    auto read_vec2 = [L](int idx, float& x, float& y) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "X"); x = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            lua_getfield(L, idx, "Y"); y = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
        }
    };
    auto read_color = [L](int idx, float& r, float& g, float& b) {
        if (lua_istable(L, idx)) {
            lua_getfield(L, idx, "R"); r = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            lua_getfield(L, idx, "G"); g = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
            lua_getfield(L, idx, "B"); b = static_cast<float>(lua_tonumber(L, -1)); lua_pop(L, 1);
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

static const char* ROBLOX_MOCK_LUA = R"LUA(

local Signal = {}
Signal.__index = Signal
Signal.__type  = "RBXScriptSignal"
function Signal.new(name)
    return setmetatable({_name=name or "Signal",_connections={}}, Signal)
end
function Signal:Connect(fn)
    if type(fn)~="function" then return end
    local conn = setmetatable({Connected=true,_fn=fn,_signal=self},{
        __type="RBXScriptConnection",
        __index={Disconnect=function(self) self.Connected=false end}
    })
    table.insert(self._connections, conn)
    return conn
end
Signal.connect = Signal.Connect
function Signal:Wait() return 0 end
function Signal:Fire(...)
    for _,conn in ipairs(self._connections) do
        if conn.Connected then pcall(conn._fn,...) end
    end
end

local Vector3 = {}
Vector3.__index = Vector3
Vector3.__type  = "Vector3"
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

local Vector2 = {}
Vector2.__index = Vector2
Vector2.__type  = "Vector2"
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

local Color3 = {}
Color3.__index = Color3
Color3.__type  = "Color3"
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

local UDim = {}
UDim.__index = UDim
UDim.__type  = "UDim"
function UDim.new(s,o) return setmetatable({Scale=s or 0,Offset=o or 0},UDim) end

local UDim2 = {}
UDim2.__index = UDim2
UDim2.__type  = "UDim2"
function UDim2.new(xs,xo,ys,yo)
    return setmetatable({X=UDim.new(xs or 0,xo or 0),Y=UDim.new(ys or 0,yo or 0),
        Width=UDim.new(xs or 0,xo or 0),Height=UDim.new(ys or 0,yo or 0)},UDim2)
end
function UDim2.fromScale(xs,ys) return UDim2.new(xs,0,ys,0) end
function UDim2.fromOffset(xo,yo) return UDim2.new(0,xo,0,yo) end
function UDim2.__tostring(u) return string.format("{%g, %d}, {%g, %d}",u.X.Scale,u.X.Offset,u.Y.Scale,u.Y.Offset) end

local CFrame = {}
CFrame.__index = CFrame
CFrame.__type  = "CFrame"
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
    rawset(cf,"LookVector",(target-pos))
    return cf
end
function CFrame.__mul(a,b)
    if getmetatable(b)==Vector3 then return Vector3.new(a.X+b.X,a.Y+b.Y,a.Z+b.Z) end
    return CFrame.new(a.X+b.X,a.Y+b.Y,a.Z+b.Z)
end
function CFrame.__tostring(cf) return string.format("%.4f, %.4f, %.4f, ...",cf.X,cf.Y,cf.Z) end

local function make_instance(class_name,name,parent)
    local children={}
    local properties={}
    local events={}
    local inst={}
    local mt={__type="Instance",__tostring=function() return name or class_name end}
    mt.__index=function(self,key)
        if key=="Name" then return name or class_name end
        if key=="ClassName" then return class_name end
        if key=="Parent" then return parent end
        if key=="IsA" then return function(_,check) return check==class_name or check=="Instance" or check=="GuiObject" or check=="BasePart" end end
        if key=="FindFirstChild" then
            return function(_,child_name)
                for _,c in ipairs(children) do
                    if (type(c)=="table" and rawget(c,"Name")==child_name) or tostring(c)==child_name then return c end
                end
                return nil
            end
        end
        if key=="FindFirstChildOfClass" then
            return function(_,cls)
                for _,c in ipairs(children) do if type(c)=="table" and rawget(c,"ClassName")==cls then return c end end
                return nil
            end
        end
        if key=="FindFirstChildWhichIsA" then
            return function(_,cls)
                for _,c in ipairs(children) do
                    if type(c)=="table" then
                        local isa=rawget(c,"IsA")
                        if isa and isa(c,cls) then return c end
                        if rawget(c,"ClassName")==cls then return c end
                    end
                end
                return nil
            end
        end
        if key=="WaitForChild" then return function(_,cn) return rawget(mt,"__index")(self,"FindFirstChild")(self,cn) end end
        if key=="GetChildren" or key=="getChildren" then return function() return children end end
        if key=="GetDescendants" then return function() return children end end
        if key=="Clone" then return function() return make_instance(class_name,name,nil) end end
        if key=="Destroy" or key=="Remove" then return function() end end
        if key=="ClearAllChildren" then return function() children={} end end
        if key=="GetFullName" then return function() return name or class_name end end
        if key=="GetPropertyChangedSignal" then
            return function(_,prop_name)
                local sig_key="_PropChanged_"..tostring(prop_name or "")
                if not events[sig_key] then events[sig_key]=Signal.new(sig_key) end
                return events[sig_key]
            end
        end
        if key=="GetAttribute" then return function(_,attr) return properties["_attr_"..tostring(attr)] end end
        if key=="SetAttribute" then return function(_,attr,val) properties["_attr_"..tostring(attr)]=val end end
        if key=="GetAttributes" then return function() return {} end end
        if key=="Changed" or key=="ChildAdded" or key=="ChildRemoved" or key=="AncestryChanged" or key=="Destroying" then
            if not events[key] then events[key]=Signal.new(key) end
            return events[key]
        end
        if properties[key]~=nil then return properties[key] end
        return nil
    end
    mt.__newindex=function(self,key,value)
        if key=="Name" then name=value
        elseif key=="Parent" then parent=value
        else properties[key]=value end
    end
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
        props.Enabled=true;props.ResetOnSpawn=true
    elseif class_name=="Frame" or class_name=="TextLabel" or class_name=="TextButton"
           or class_name=="ImageLabel" or class_name=="ImageButton" or class_name=="ScrollingFrame" then
        props.Size=UDim2.new(0,100,0,100);props.Position=UDim2.new(0,0,0,0)
        props.BackgroundColor3=Color3.new(1,1,1);props.BackgroundTransparency=0
        props.Visible=true;props.Text="";props.TextColor3=Color3.new(0,0,0)
        props.TextSize=14;props.Font=0;props.ZIndex=1
        props.AnchorPoint=Vector2.new(0,0);props.BorderSizePixel=0;props.ClipsDescendants=false
    elseif class_name=="Part" or class_name=="MeshPart" or class_name=="UnionOperation" or class_name=="WedgePart" then
        props.Position=Vector3.new(0,0,0);props.Size=Vector3.new(4,1,2)
        props.CFrame=CFrame.new(0,0,0);props.Anchored=false;props.CanCollide=true
        props.Transparency=0;props.BrickColor="Medium stone grey"
        props.Color=Color3.fromRGB(163,162,165);props.Material=EnumMock.Material.Plastic
    elseif class_name=="UICorner" then props.CornerRadius=UDim.new(0,8)
    elseif class_name=="UIStroke" then props.Thickness=1;props.Color=Color3.new(0,0,0);props.Transparency=0
    elseif class_name=="UIListLayout" or class_name=="UIGridLayout" then
        props.SortOrder=EnumMock.SortOrder.LayoutOrder;props.Padding=UDim.new(0,0)
    end
    return inst
end

local Drawing={Fonts={UI=0,System=1,Plex=2,Monospace=3}}
local _drawing_type_map={Line=0,Text=1,Circle=2,Square=3,Triangle=4,Quad=5,Image=6}

function Drawing.new(class_name)
    class_name=class_name or "Line"
    local type_id=_drawing_type_map[class_name] or 0
    local id=0
    if _oss_drawing_new then id=_oss_drawing_new(type_id) end
    local data={
        _id=id,_class=class_name,
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
                    data.Visible=false
                    if _oss_drawing_set and id>0 then _oss_drawing_set(id,"Visible",false) end
                    if _oss_drawing_remove and id>0 then _oss_drawing_remove(id) end
                end
            end
            return data[key]
        end,
        __newindex=function(_,key,value)
            data[key]=value
            if _oss_drawing_set and id>0 then _oss_drawing_set(id,key,value) end
        end,
    }
    return setmetatable({},mt)
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
        local char,char_children=make_instance("Model","LocalPlayer")
        local hrp,_,hrp_props=make_instance("Part","HumanoidRootPart",char)
        hrp_props.Position=Vector3.new(0,3,0);hrp_props.CFrame=CFrame.new(0,3,0);hrp_props.Size=Vector3.new(2,2,1)
        local head,_,head_props=make_instance("Part","Head",char)
        head_props.Position=Vector3.new(0,4.5,0);head_props.CFrame=CFrame.new(0,4.5,0);head_props.Size=Vector3.new(2,1,1)
        local hum,_,hum_props=make_instance("Humanoid","Humanoid",char)
        hum_props.Health=100;hum_props.MaxHealth=100;hum_props.WalkSpeed=16;hum_props.JumpPower=50
        hum_props.RigType=EnumMock.HumanoidRigType.R15
        rawset(hum,"GetState",function() return EnumMock.HumanoidStateType.Running end)
        rawset(hum,"GetAppliedDescription",function() return make_instance("HumanoidDescription","HumanoidDescription") end)
        rawset(hum,"MoveTo",function() end)
        table.insert(char_children,hrp);table.insert(char_children,head);table.insert(char_children,hum)
        lp_props.Character=char
        rawset(lp,"GetMouse",function()
            local mouse,_,mp=make_instance("Mouse","Mouse")
            mp.X=0;mp.Y=0;mp.Hit=CFrame.new(0,0,0);mp.Target=nil
            return mouse
        end)
        props.LocalPlayer=lp;table.insert(children,lp)
        rawset(svc,"GetPlayers",function() return {lp} end)
        props.PlayerAdded=Signal.new("PlayerAdded");props.PlayerRemoving=Signal.new("PlayerRemoving")
    elseif name=="RunService" then
        props.RenderStepped=Signal.new("RenderStepped");props.Heartbeat=Signal.new("Heartbeat");props.Stepped=Signal.new("Stepped")
        rawset(svc,"IsClient",function() return true end)
        rawset(svc,"IsServer",function() return false end)
        rawset(svc,"IsStudio",function() return false end)
        rawset(svc,"BindToRenderStep",function(_,n,p,fn) if type(fn)=="function" then props.RenderStepped:Connect(fn) end end)
        rawset(svc,"UnbindFromRenderStep",function() end)
    elseif name=="Workspace" then
        props.CurrentCamera=get_camera();props.Gravity=196.2;props.DistributedGameTime=0
        rawset(svc,"Raycast",function() return nil end)
        rawset(svc,"FindPartOnRay",function() return nil,Vector3.new() end)
        rawset(svc,"FindPartOnRayWithIgnoreList",function() return nil,Vector3.new() end)
    elseif name=="UserInputService" then
        props.MouseEnabled=true;props.KeyboardEnabled=true;props.TouchEnabled=false;props.GamepadEnabled=false
        props.MouseBehavior=EnumMock.MouseBehavior.Default
        props.InputBegan=Signal.new("InputBegan");props.InputEnded=Signal.new("InputEnded");props.InputChanged=Signal.new("InputChanged")
        rawset(svc,"GetMouseLocation",function() return Vector2.new(960,540) end)
        rawset(svc,"IsKeyDown",function() return false end)
        rawset(svc,"IsMouseButtonPressed",function() return false end)
        rawset(svc,"GetKeysPressed",function() return {} end)
    elseif name=="CoreGui" or name=="StarterGui" then
        rawset(svc,"SetCoreGuiEnabled",function() end)
        rawset(svc,"GetCoreGuiEnabled",function() return true end)
    elseif name=="TweenService" then
        rawset(svc,"Create",function(_,inst,info,pt)
            return {Play=function()end,Cancel=function()end,Pause=function()end,Completed=Signal.new("Completed")}
        end)
    elseif name=="HttpService" then
        rawset(svc,"JSONEncode",function(_,obj)
            if type(obj)=="string" then return '"'..obj..'"' end
            if type(obj)=="number" or type(obj)=="boolean" then return tostring(obj) end
            if type(obj)=="table" then
                local parts={} local is_array=(#obj>0)
                if is_array then
                    for _,v in ipairs(obj) do
                        local s2=game:GetService("HttpService")
                        table.insert(parts,s2:JSONEncode(v))
                    end
                    return "["..table.concat(parts,",").."]"
                else
                    for k,v in pairs(obj) do
                        local s2=game:GetService("HttpService")
                        table.insert(parts,'"'..tostring(k)..'":'..s2:JSONEncode(v))
                    end
                    return "{"..table.concat(parts,",").."}"
                end
            end
            return tostring(obj)
        end)
        rawset(svc,"JSONDecode",function(_,str)
            if type(str)~="string" then return {} end
            local s=str:gsub("%[","{"):gsub("%]","}")
            s=s:gsub("null","nil"):gsub("true","true"):gsub("false","false")
            local fn=loadstring("return "..s)
            if fn then local ok,result=pcall(fn) if ok then return result end end
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
        rawset(svc,"UrlEncode",function(_,str)
            return (str:gsub("[^%w%-_%.~]",function(c) return string.format("%%%02X",string.byte(c)) end))
        end)
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

wait=function(t) return t or 0,t or 0 end
spawn=function(fn) if type(fn)=="function" then pcall(fn) end end
delay=function(t,fn) if type(fn)=="function" then pcall(fn) end end
tick=function() return os.clock() end
time=function() return os.clock() end
elapsedTime=function() return os.clock() end
settings=function() return {Rendering={QualityLevel=10}} end

task={
    wait=function(t) return t or 0 end,
    spawn=function(fn,...) if type(fn)=="function" then pcall(fn,...) end end,
    defer=function(fn,...) if type(fn)=="function" then pcall(fn,...) end end,
    delay=function(t,fn,...) if type(fn)=="function" then pcall(fn,...) end end,
    cancel=function() end,synchronize=function() end,desynchronize=function() end,
}

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
    return {FilterType=EnumMock.RaycastFilterType.Exclude,FilterDescendantsInstances={},IgnoreWater=true}
end

OverlapParams={}
function OverlapParams.new()
    return {FilterType=EnumMock.RaycastFilterType.Exclude,FilterDescendantsInstances={}}
end

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
function PhysicalProperties.new() return {} end

Rect={}
function Rect.new(x0,y0,x1,y1)
    return {Min=Vector2.new(x0 or 0,y0 or 0),Max=Vector2.new(x1 or 0,y1 or 0),
        Width=(x1 or 0)-(x0 or 0),Height=(y1 or 0)-(y0 or 0)}
end

if not string.split then
    function string.split(str,sep)
        sep=sep or ","
        local parts={}
        str:gsub("([^"..sep.."]*)"..sep.."?",function(c)
            if #c>0 or #parts==0 then table.insert(parts,c) end
        end)
        return parts
    end
end

syn={
    request=_G._oss_http_request or function() return {} end,
    crypt={base64encode=function(s) return s end,base64decode=function(s) return s end},
}
request=syn.request
http_request=syn.request

getgenv=function() return _G end
getrenv=function() return _G end
getreg=function() return {} end
getgc=function() return {} end
gethui=function() return make_service("CoreGui") end
getinstances=function() return {} end
getnilinstances=function() return {} end
getscripts=function() return {} end
getrunningscripts=function() return {} end
getloadedmodules=function() return {} end

isexecutorclosure=function() return false end
checkcaller=function() return false end
islclosure=function(f) return type(f)=="function" end
iscclosure=function(f) return type(f)=="function" end
hookfunction=function(old,new) return old end
hookmetamethod=function(_,_,new) return function() end end
newcclosure=function(fn) return fn end
getrawmetatable=function(t) return getmetatable(t) end
setrawmetatable=function(t,mt) return setmetatable(t,mt) end
setreadonly=function() end
isreadonly=function() return false end
getnamecallmethod=function() return "" end
checkclosure=function() return false end
getcallingscript=function() return nil end
getscriptclosure=function() return function() end end
getconnections=function(signal)
    if signal and signal._connections then
        local out={}
        for _,conn in ipairs(signal._connections) do
            table.insert(out,{
                Function=conn._fn,State=conn.Connected,
                Enable=function() conn.Connected=true end,
                Disable=function() conn.Connected=false end,
                Fire=function(...) pcall(conn._fn,...) end,
            })
        end
        return out
    end
    return {}
end

fireclickdetector=function() end
firetouchinterest=function() end
fireproximityprompt=function() end
setclipboard=setclipboard or function() end
getclipboard=getclipboard or function() return "" end
setfpscap=function() end
getfps=function() return 60 end

readfile=readfile or function() return "" end
writefile=writefile or function() end
appendfile=appendfile or function() end
isfile=isfile or function() return false end
isfolder=isfolder or function(p)
    local ok,r=pcall(function() return #(listfiles(p) or {})>=0 end)
    return ok and r
end
listfiles=listfiles or function() return {} end
makefolder=makefolder or function() end
delfolder=delfolder or function() end
delfile=delfile or function() end

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

if not math.clamp then function math.clamp(val,lo,hi) if val<lo then return lo end if val>hi then return hi end return val end end
if not math.sign then function math.sign(n) if n>0 then return 1 end if n<0 then return -1 end return 0 end end
if not math.round then function math.round(n) return math.floor(n+0.5) end end
do
    local _log=math.log
    math.log=function(x,base) if base then return _log(x)/_log(base) end return _log(x) end
end
if not math.noise then
    math.noise=function(x,y,z)
        x=x or 0;y=y or 0;z=z or 0
        return (math.sin(x*12.9898+y*78.233+z*37.719)*43758.5453)%1-0.5
    end
end

if not bit32 then
    local ok,bitlib=pcall(require,"bit")
    if ok then
        bit32={band=bitlib.band,bor=bitlib.bor,bxor=bitlib.bxor,bnot=bitlib.bnot,
            lshift=bitlib.lshift,rshift=bitlib.rshift,arshift=bitlib.arshift,
            btest=function(a,b) return bitlib.band(a,b)~=0 end}
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

    lua_pushcfunction(L, [](lua_State* state) -> int {
        lua_pushstring(state, "Current identity is 7");
        return 1;
    });
    lua_setglobal(L, "printidentity");

    lua_pushcfunction(L, lua_drawing_new_bridge);
    lua_setglobal(L, "_oss_drawing_new");
    lua_pushcfunction(L, lua_drawing_set_bridge);
    lua_setglobal(L, "_oss_drawing_set");
    lua_pushcfunction(L, lua_drawing_remove_bridge);
    lua_setglobal(L, "_oss_drawing_remove");

    int status = luaL_dostring(L, ROBLOX_MOCK_LUA);
    if (status != 0) {
        const char* err = lua_tostring(L, -1);
        LOG_ERROR("Failed to init Roblox mock: {}", err ? err : "unknown error");
        lua_pop(L, 1);
        return;
    }

    lua_pushboolean(L, 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "_oss_env_init");

    LOG_INFO("Roblox API mock environment initialized");
}

} // namespace oss
