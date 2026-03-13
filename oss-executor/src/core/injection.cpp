#include "injection.hpp"
#include "memory.hpp"
#include "utils/logger.hpp"

#include <chrono>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <string>
#include <sstream>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <elf.h>
#include <luacode.h>
#include <fcntl.h>
#include <poll.h>

namespace fs = std::filesystem;

namespace oss {

static constexpr size_t REGION_SCAN_CAP = 0x4000000;
static constexpr size_t REGION_MIN      = 0x1000;
static constexpr size_t REGION_MAX      = 0x80000000ULL;
static constexpr int    AUTOSCAN_TICKS  = 30;
static constexpr int    TICK_MS         = 100;
static constexpr const char* PAYLOAD_SOCK = "/tmp/oss_executor.sock";

static const std::string DIRECT_TARGETS[] = {
    "RobloxPlayer","RobloxPlayerBeta","RobloxPlayerBeta.exe",
    "RobloxPlayerLauncher","Roblox","sober",".sober-wrapped",
    "org.vinegarhq.Sober","vinegar"
};
static const std::string WINE_HOSTS[] = {
    "wine-preloader","wine64-preloader","wine","wine64"
};
static const std::string ROBLOX_TOKENS[] = {
    "RobloxPlayer","RobloxPlayerBeta","RobloxPlayerLauncher","Roblox.exe","roblox"
};
static const std::string PRIMARY_MARKERS[] = {
    "rbxasset://","CoreGui","LocalScript","ModuleScript","RenderStepped",
    "GetService","HumanoidRootPart","PlayerAdded","StarterGui",
    "ReplicatedStorage","TweenService","UserInputService"
};
static const std::string SECONDARY_MARKERS[] = {
    "Instance","workspace","Enum","Vector3","CFrame","game","Players","Lighting"
};
static const std::string PATH_KEYWORDS[] = {
    "Roblox","roblox","ROBLOX","Sober","sober","vinegar",".exe",".dll","wine"
};
static const std::string SELF_KEYWORDS[] = { "OSS","OSSExecutor","oss-executor","AppImage" };

static bool is_self_process(pid_t pid) { return pid==getpid()||pid==getppid(); }

static bool is_self_process_name(const std::string& name) {
    if (name.empty()) return false;
    for (const auto& kw : SELF_KEYWORDS)
        if (name.find(kw)!=std::string::npos) return true;
    return false;
}

static bool is_valid_target(pid_t pid, const std::string& comm,
                            const std::string& cmdline, const std::string& exe_path) {
    return !is_self_process(pid) && !is_self_process_name(comm) &&
           !is_self_process_name(cmdline) && !is_self_process_name(exe_path);
}

struct ProcessDetails { char state='?'; pid_t tracer_pid=0; };

static ProcessDetails get_process_details(pid_t pid) {
    ProcessDetails r;
    char path[64], buf[4096];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        if (n > 0) { buf[n]=0; char* cp=strrchr(buf,')'); if(cp&&cp[1]==' ') r.state=cp[2]; }
        close(fd);
    }
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        if (n > 0) { buf[n]=0; char* l=strstr(buf,"TracerPid:"); if(l) r.tracer_pid=atoi(l+10); }
        close(fd);
    }
    return r;
}

static pid_t get_tracer_pid(pid_t pid) { return get_process_details(pid).tracer_pid; }

static size_t dh_insn_len(const uint8_t* p) {
    if (p[0]==0xF3&&p[1]==0x0F&&p[2]==0x1E&&p[3]==0xFA) return 4;
    size_t i=0;
    while(i<4&&(p[i]==0x66||p[i]==0x67||p[i]==0xF0||p[i]==0xF2||p[i]==0xF3||
                p[i]==0x26||p[i]==0x2E||p[i]==0x36||p[i]==0x3E||p[i]==0x64||p[i]==0x65)) i++;
    bool rex_w=false;
    if(p[i]>=0x40&&p[i]<=0x4F){rex_w=(p[i]&0x08)!=0;i++;}
    uint8_t op=p[i++];
    auto mlen=[&](size_t s)->size_t{size_t j=s;if(j>=15)return 0;uint8_t m=p[j++];
        uint8_t mod=(m>>6)&3,rm=m&7;
        if(mod!=3&&rm==4){if(j>=15)return 0;uint8_t sib=p[j++];if(mod==0&&(sib&7)==5)j+=4;}
        if(mod==0&&rm==5)j+=4;else if(mod==1)j+=1;else if(mod==2)j+=4;return j;};
    if(op==0xC5){if(i>=14)return 0;i++;uint8_t vop=p[i++];if(vop==0x77)return i;if(i>=15)return 0;
        uint8_t m=p[i++];uint8_t mod=(m>>6)&3,rm=m&7;
        if(mod!=3&&rm==4){if(i>=15)return 0;uint8_t sib=p[i++];if(mod==0&&(sib&7)==5)i+=4;}
        if(mod==0&&rm==5)i+=4;else if(mod==1)i+=1;else if(mod==2)i+=4;
        if(vop==0xC6||vop==0xC2||vop==0xC4||vop==0xC5||vop==0x70||
           vop==0x71||vop==0x72||vop==0x73||vop==0xA4||vop==0xAC)i+=1;return i;}
    if(op==0xC4){if(i+1>=14)return 0;uint8_t vb1=p[i++];i++;uint8_t mmmmm=vb1&0x1F;
        if(i>=15)return 0;uint8_t vop=p[i++];if(i>=15)return 0;uint8_t m=p[i++];
        uint8_t mod=(m>>6)&3,rm=m&7;
        if(mod!=3&&rm==4){if(i>=15)return 0;uint8_t sib=p[i++];if(mod==0&&(sib&7)==5)i+=4;}
        if(mod==0&&rm==5)i+=4;else if(mod==1)i+=1;else if(mod==2)i+=4;
        if(mmmmm==3)i+=1;else if(mmmmm==1&&(vop==0xC6||vop==0xC2||vop==0xC4||vop==0xC5||
           vop==0x70||vop==0x71||vop==0x72||vop==0x73))i+=1;return i;}
    if(op==0x62){if(i+2>=14)return 0;uint8_t eb1=p[i++];i++;i++;uint8_t mmmmm=eb1&0x07;
        if(i>=15)return 0;uint8_t eop=p[i++];(void)eop;if(i>=15)return 0;
        uint8_t m=p[i++];uint8_t mod=(m>>6)&3,rm=m&7;
        if(mod!=3&&rm==4){if(i>=15)return 0;uint8_t sib=p[i++];if(mod==0&&(sib&7)==5)i+=4;}
        if(mod==0&&rm==5)i+=4;else if(mod==1)i+=1;else if(mod==2)i+=4;
        if(mmmmm==3)i+=1;return i;}
    if((op>=0x50&&op<=0x5F)||op==0x90||op==0xC3||op==0xCC||op==0xC9)return i;
    if(op==0xC2)return i+2;
    if(op>=0xB0&&op<=0xB7)return i+1;
    if(op>=0xB8&&op<=0xBF)return i+(rex_w?8:4);
    if(op==0xE8||op==0xE9)return i+4;
    if(op==0xEB||(op>=0x70&&op<=0x7F))return i+1;
    if(op==0x80||op==0x82||op==0x83||op==0xC0||op==0xC1)return mlen(i)+1;
    if(op==0x81||op==0xC7||op==0x69)return mlen(i)+4;
    if(op==0xC6||op==0x6B)return mlen(i)+1;
    if(op==0x0F){uint8_t op2=p[i++];
        if(op2>=0x80&&op2<=0x8F)return i+4;
        if(op2>=0x40&&op2<=0x4F)return mlen(i);
        if(op2>=0x90&&op2<=0x9F)return mlen(i);
        if(op2==0xB6||op2==0xB7||op2==0xBE||op2==0xBF||op2==0xAF)return mlen(i);
        if(op2==0xA3||op2==0xAB||op2==0xB3||op2==0xBB||op2==0xBC||op2==0xBD)return mlen(i);
        if(op2==0xA4||op2==0xAC)return mlen(i)+1;
        if(op2==0xA5||op2==0xAD)return mlen(i);
        if(op2==0xBA)return mlen(i)+1;
        if(op2==0x1F||op2==0x44||(op2>=0x10&&op2<=0x17)||(op2>=0x28&&op2<=0x2F))return mlen(i);
        if(op2==0x38){if(i>=15)return 0;i++;return mlen(i);}
        if(op2==0x3A){if(i>=15)return 0;i++;return mlen(i)+1;}
        return mlen(i);}
    if((op&0xC4)==0x00||(op&0xFE)==0x84||(op&0xFC)==0x88||op==0x8C||op==0x8E||
       op==0x8D||op==0x63||op==0x86||op==0x87||op==0x8F)return mlen(i);
    if(op>=0xD0&&op<=0xD3)return mlen(i);
    if(op==0xFE||op==0xFF)return mlen(i);
    if(op==0xF6){uint8_t m=p[i];return((m&0x38)==0)?mlen(i)+1:mlen(i);}
    if(op==0xF7){uint8_t m=p[i];return((m&0x38)==0)?mlen(i)+4:mlen(i);}
    if(op>=0xD8&&op<=0xDF)return mlen(i);
    if(op==0x9C||op==0x9D||op==0xF4||op==0xCB||op==0xF8||op==0xF9||
       op==0xFC||op==0xFD||op==0xF5||op==0x98||op==0x99||op==0x9E||
       op==0x9F||op==0xCE||op==0xCF||(op>=0x91&&op<=0x97))return i;
    if(op==0x68)return i+4;if(op==0x6A)return i+1;
    if(op==0x04||op==0x0C||op==0x14||op==0x1C||op==0x24||op==0x2C||
       op==0x34||op==0x3C||op==0xA8)return i+1;
    if(op==0x05||op==0x0D||op==0x15||op==0x1D||op==0x25||op==0x2D||
       op==0x35||op==0x3D||op==0xA9)return i+4;
    if(op>=0xA0&&op<=0xA3)return i+(rex_w?8:4);
    if(op==0xA4||op==0xA5||op==0xA6||op==0xA7||op==0xAA||op==0xAB||
       op==0xAC||op==0xAD||op==0xAE||op==0xAF)return i;
    if(op==0xCD)return i+1;
    if(op==0xE4||op==0xE5||op==0xE6||op==0xE7||op==0xE0||op==0xE1||op==0xE2||op==0xE3)return i+1;
    return 0;
}

static bool at_func_boundary(uint8_t prev) {
    return prev==0xC3||prev==0xCC||prev==0x90;
}

static bool has_prologue(const uint8_t* c, size_t avail) {
    size_t p=0;
    if(p+4<=avail&&c[p]==0xF3&&c[p+1]==0x0F&&c[p+2]==0x1E&&c[p+3]==0xFA) p+=4;
    if(p>=avail) return false;
    return c[p]==0x55||c[p]==0x53||
           (c[p]==0x41&&p+1<avail&&c[p+1]>=0x54&&c[p+1]<=0x57)||
           (c[p]==0x48&&p+2<avail&&c[p+1]==0x83&&c[p+2]==0xEC);
}

static size_t find_func_end(const uint8_t* buf, size_t len, size_t min_off=20) {
    size_t pos=0;
    while(pos+15<len&&pos<len-15) {
        size_t il=dh_insn_len(buf+pos); if(il==0) break;
        if(buf[pos]==0xC3) return pos+1;
        pos+=il;
    }
    for(size_t i=min_off;i+1<len;i++) {
        if(buf[i]!=0xC3) continue;
        uint8_t nx=buf[i+1];
        if(nx==0xCC||nx==0x90||nx==0x55||nx==0x53||nx==0x56||nx==0x57||
           nx==0xF3||nx==0x00||(nx==0x41&&i+2<len&&buf[i+2]>=0x50&&buf[i+2]<=0x57)||
           (nx==0x48&&i+2<len&&buf[i+2]==0x83)) return i+1;
    }
    return 0;
}

struct FuncSig {
    bool saves_rdi=false, saves_rsi=false, saves_rdx=false;
    int calls=0, leas=0;
    size_t func_size=0;
    bool has_tt9=false;
};

static FuncSig analyze_func_sig(const uint8_t* code, size_t off, size_t scan_sz,
                                 size_t max_body=250, size_t min_ret=20) {
    FuncSig s;
    for(size_t j=0;j<max_body&&off+j+8<scan_sz;j++){
        size_t i=off+j;
        if(code[i]==0xE8) s.calls++;
        if(i+6<scan_sz&&((code[i]==0x48||code[i]==0x4C)&&code[i+1]==0x8D&&(code[i+2]&0xC7)==0x05)) s.leas++;
        if(j<20&&i+2<scan_sz){
            if(code[i]==0x89&&(code[i+1]&0x38)==0x38) s.saves_rdi=true;
            if((code[i]==0x48||code[i]==0x49)&&code[i+1]==0x89&&(code[i+2]&0x38)==0x38) s.saves_rdi=true;
            if(code[i]==0x89&&(code[i+1]&0x38)==0x30) s.saves_rsi=true;
            if((code[i]==0x48||code[i]==0x49)&&code[i+1]==0x89&&(code[i+2]&0x38)==0x30) s.saves_rsi=true;
            if(code[i]==0x48&&code[i+1]==0x63&&(code[i+2]&0xC7)==0xC6) s.saves_rsi=true;
            if(code[i]==0x89&&(code[i+1]&0x38)==0x10) s.saves_rdx=true;
            if((code[i]==0x48||code[i]==0x49)&&code[i+1]==0x89&&(code[i+2]&0x38)==0x10) s.saves_rdx=true;
        }
        if(!s.has_tt9&&i+3<scan_sz&&code[i]==0x09&&code[i+1]==0x00&&code[i+2]==0x00&&code[i+3]==0x00&&j>=4){
            if(i>=1&&code[i-1]>=0xB8&&code[i-1]<=0xBF) s.has_tt9=true;
            if(i>=2&&(code[i-2]>=0x40&&code[i-2]<=0x4F)&&code[i-1]>=0xB8&&code[i-1]<=0xBF) s.has_tt9=true;
            if(i>=3&&(code[i-3]==0xC7||code[i-3]==0xC6)) s.has_tt9=true;
            if(i>=4&&(code[i-4]>=0x40&&code[i-4]<=0x4F)&&(code[i-3]==0xC7||code[i-3]==0xC6)) s.has_tt9=true;
        }
        if(!s.has_tt9&&code[i]==0x09&&j>=1){
            if(i>=1&&code[i-1]==0x6A) s.has_tt9=true;
            if(i>=2&&code[i-2]==0x83) s.has_tt9=true;
            if(i>=2&&code[i-2]==0xC6) s.has_tt9=true;
        }
        if(code[i]==0xC3&&j>=min_ret){s.func_size=j+1;break;}
    }
    return s;
}

static int shared_call_count(pid_t pid, uintptr_t fa, uintptr_t fb,
                              size_t max_a=1024, size_t max_b=1024) {
    uint8_t ba[1024], bb[1024];
    size_t sa=std::min(max_a,sizeof(ba)), sb=std::min(max_b,sizeof(bb));
    struct iovec la={ba,sa},ra={reinterpret_cast<void*>(fa),sa};
    struct iovec lb={bb,sb},rb={reinterpret_cast<void*>(fb),sb};
    if(process_vm_readv(pid,&la,1,&ra,1,0)!=(ssize_t)sa) return 0;
    if(process_vm_readv(pid,&lb,1,&rb,1,0)!=(ssize_t)sb) return 0;
    int shared=0;
    for(size_t i=0;i+5<=sa;i++){if(ba[i]!=0xE8)continue;
        int32_t da;memcpy(&da,&ba[i+1],4);uintptr_t ta=fa+i+5+(int64_t)da;
        for(size_t j=0;j+5<=sb;j++){if(bb[j]!=0xE8)continue;
            int32_t db;memcpy(&db,&bb[j+1],4);
            if(ta==fb+j+5+(int64_t)db){shared++;break;}}}
    return shared;
}

static bool first_call_reaches(pid_t pid, uintptr_t func, uintptr_t target, size_t max_search=80) {
    uint8_t buf[128];
    size_t rd=std::min(max_search+5,sizeof(buf));
    struct iovec l={buf,rd},r={reinterpret_cast<void*>(func),rd};
    if(process_vm_readv(pid,&l,1,&r,1,0)!=(ssize_t)rd) return false;
    for(size_t i=0;i+5<=rd;i++){
        if(buf[i]!=0xE8) continue;
        int32_t d;memcpy(&d,&buf[i+1],4);uintptr_t t=func+i+5+(int64_t)d;
        if(t==target) return true;
        uint8_t hop[25]; struct iovec hl={hop,25},hr={reinterpret_cast<void*>(t),25};
        if(process_vm_readv(pid,&hl,1,&hr,1,0)==25)
            for(int hi=0;hi<20;hi++){if(hop[hi]!=0xE8)continue;
                int32_t hd;memcpy(&hd,&hop[hi+1],4);
                if(t+hi+5+(int64_t)hd==target)return true;break;}
        break;
    }
    return false;
}

static uintptr_t last_call_in_func(const uint8_t* buf, size_t fend, uintptr_t base, uintptr_t exclude=0) {
    uintptr_t last=0;
    for(size_t i=0;i+5<=fend;i++){
        if(buf[i]!=0xE8) continue;
        int32_t d;memcpy(&d,&buf[i+1],4);
        uintptr_t t=base+i+5+(int64_t)d;
        if(t!=exclude) last=t;
    }
    return last;
}

struct ProxResult { uintptr_t addr=0; size_t fsz=0; int score=-1; };

template<typename Scorer>
static ProxResult scan_funcs_near(pid_t pid, const std::vector<MemoryRegion>& regions,
    uintptr_t anchor, int64_t max_range, const std::vector<uintptr_t>& exclude,
    Scorer scorer, int early_stop_score=20)
{
    ProxResult best;
    for(const auto& r:regions){
        if(best.addr&&best.score>=early_stop_score) break;
        if(!r.readable()||!r.executable()||r.size()<256) continue;
        uintptr_t s_lo=(anchor>(uintptr_t)max_range)?anchor-max_range:0;
        uintptr_t s_hi=anchor+max_range;
        uintptr_t r_lo=std::max(r.start,s_lo), r_hi=std::min(r.end,s_hi);
        if(r_lo>=r_hi) continue;
        size_t scan_sz=r_hi-r_lo;
        std::vector<uint8_t> code(scan_sz);
        struct iovec li={code.data(),scan_sz},ri={reinterpret_cast<void*>(r_lo),scan_sz};
        if(process_vm_readv(pid,&li,1,&ri,1,0)!=(ssize_t)scan_sz) continue;
        for(size_t off=1;off+260<scan_sz;off++){
            if(!at_func_boundary(code[off-1])) continue;
            uintptr_t addr=r_lo+off;
            bool skip=false; for(auto ex:exclude) if(addr==ex){skip=true;break;} if(skip) continue;
            if(!has_prologue(code.data()+off,scan_sz-off)) continue;
            int sc=scorer(pid,addr,code.data(),off,scan_sz,r.start);
            if(sc>best.score){best.score=sc;best.addr=addr;}
        }
    }
    return best;
}

static uintptr_t find_func_by_stringref(pid_t pid, Memory& mem,
    const std::vector<MemoryRegion>& regions, const char* const* needles,
    uintptr_t anchor, const std::vector<uintptr_t>& exclude)
{
    for(int si=0;needles[si];si++){
        const char* needle=needles[si]; size_t nlen=strlen(needle);
        for(const auto& r:regions){
            if(!r.readable()||r.size()<nlen) continue;
            size_t scan=std::min(r.size(),(size_t)0x4000000);
            std::vector<uint8_t> pat(needle,needle+nlen); std::string mask(nlen,'x');
            auto hit=mem.pattern_scan(pat,mask,r.start,scan);
            if(!hit) continue;
            uintptr_t str_addr=*hit;
            for(const auto& xr:regions){
                if(!xr.readable()||!xr.executable()||xr.size()<7) continue;
                uintptr_t r_lo=xr.start, r_hi=xr.end;
                if(anchor){
                    uintptr_t s_lo=(anchor>0x80000000ULL)?anchor-0x80000000ULL:0;
                    r_lo=std::max(xr.start,s_lo); r_hi=std::min(xr.end,anchor+0x80000000ULL);
                    if(r_lo>=r_hi) continue;
                }
                size_t xscan=r_hi-r_lo;
                constexpr size_t CHUNK=4096;
                std::vector<uint8_t> buf(CHUNK+16);
                for(size_t boff=0;boff+7<=xscan;boff+=CHUNK){
                    size_t avail=xscan-boff, rd=std::min(avail,CHUNK+(size_t)7);
                    struct iovec lo={buf.data(),rd},ro={reinterpret_cast<void*>(r_lo+boff),rd};
                    if(process_vm_readv(pid,&lo,1,&ro,1,0)!=(ssize_t)rd) continue;
                    for(size_t i=0;i+7<=rd;i++){
                        bool xf=false;
                        if((buf[i]==0x8D||buf[i]==0x8B)&&(buf[i+1]&0xC7)==0x05){
                            int32_t d;memcpy(&d,&buf[i+2],4);
                            if(r_lo+boff+i+6+(int64_t)d==str_addr) xf=true;}
                        if(!xf&&buf[i]>=0x40&&buf[i]<=0x4F&&(buf[i+1]==0x8D||buf[i+1]==0x8B)&&(buf[i+2]&0xC7)==0x05){
                            int32_t d;memcpy(&d,&buf[i+3],4);
                            if(r_lo+boff+i+7+(int64_t)d==str_addr) xf=true;}
                        if(!xf&&i+10<=rd&&buf[i]>=0x48&&buf[i]<=0x4F&&buf[i+1]>=0xB8&&buf[i+1]<=0xBF){
                            uintptr_t imm;memcpy(&imm,&buf[i+2],8);if(imm==str_addr)xf=true;}
                        if(!xf) continue;
                        uintptr_t xa=r_lo+boff+i, lim=(xa>4096)?xa-4096:0;
                        for(uintptr_t p=xa-1;p>=lim;p--){
                            uint8_t w[8]; struct iovec wl={w,8},wr={reinterpret_cast<void*>(p),8};
                            if(process_vm_readv(pid,&wl,1,&wr,1,0)!=8) continue;
                            bool cand=false;
                            if(w[0]==0xF3&&w[1]==0x0F&&w[2]==0x1E&&w[3]==0xFA&&w[4]==0x55) cand=true;
                            else if(w[0]==0x55&&w[1]==0x48&&w[2]==0x89&&w[3]==0xE5) cand=true;
                            else if((w[0]==0x55||w[0]==0x53||(w[0]==0x41&&w[1]>=0x54&&w[1]<=0x57))&&p>lim){
                                uint8_t pv;struct iovec pl={&pv,1},pr={reinterpret_cast<void*>(p-1),1};
                                if(process_vm_readv(pid,&pl,1,&pr,1,0)==1&&(pv==0xC3||pv==0xCC||pv==0x90))cand=true;}
                            if(!cand) continue;
                            bool excl=false; for(auto ex:exclude)if(p==ex){excl=true;break;} if(excl) continue;
                            uint8_t ib[64]; size_t ia=std::min((size_t)(xa+32-p),sizeof(ib));
                            struct iovec il={ib,ia},ir={reinterpret_cast<void*>(p),ia};
                            if(process_vm_readv(pid,&il,1,&ir,1,0)!=(ssize_t)ia) continue;
                            size_t dec=0;int cnt=0;
                            while(dec+15<=ia&&dec<32){size_t insn=dh_insn_len(ib+dec);if(insn==0||dec+insn>ia)break;dec+=insn;cnt++;}
                            if(cnt>=3) return p;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static uintptr_t find_elf_symbol_impl(const std::string& filepath, const std::string& symbol,
                                       uintptr_t load_bias=0, bool use_sections=false) {
    FILE* f=fopen(filepath.c_str(),"rb"); if(!f) return 0;
    Elf64_Ehdr ehdr;
    if(fread(&ehdr,sizeof(ehdr),1,f)!=1||memcmp(ehdr.e_ident,ELFMAG,SELFMAG)!=0||
       ehdr.e_ident[EI_CLASS]!=ELFCLASS64){fclose(f);return 0;}

    if(use_sections&&ehdr.e_shnum>0){
        std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
        fseek(f,(long)ehdr.e_shoff,SEEK_SET);
        if(fread(shdrs.data(),sizeof(Elf64_Shdr),ehdr.e_shnum,f)==ehdr.e_shnum){
            for(size_t si=0;si<shdrs.size();si++){
                if(shdrs[si].sh_type!=SHT_SYMTAB&&shdrs[si].sh_type!=SHT_DYNSYM) continue;
                uint32_t str_idx=shdrs[si].sh_link; if(str_idx>=shdrs.size()) continue;
                size_t strsz=shdrs[str_idx].sh_size; if(strsz==0) continue;
                std::vector<char> strtab(strsz);
                fseek(f,(long)shdrs[str_idx].sh_offset,SEEK_SET);
                if(fread(strtab.data(),1,strsz,f)!=strsz) continue;
                size_t entsz=shdrs[si].sh_entsize; if(entsz<sizeof(Elf64_Sym))entsz=sizeof(Elf64_Sym);
                size_t nsyms=shdrs[si].sh_size/entsz;
                for(size_t j=0;j<nsyms;j++){
                    Elf64_Sym sym;
                    fseek(f,(long)(shdrs[si].sh_offset+j*entsz),SEEK_SET);
                    if(fread(&sym,sizeof(sym),1,f)!=1) break;
                    if(sym.st_name==0||sym.st_name>=strsz||sym.st_shndx==SHN_UNDEF) continue;
                    if(ELF64_ST_TYPE(sym.st_info)!=STT_FUNC) continue;
                    if(symbol==strtab.data()+sym.st_name){fclose(f);return load_bias+sym.st_value;}
                }
            }
        }
        fclose(f); return 0;
    }

    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    fseek(f,(long)ehdr.e_phoff,SEEK_SET);
    if(fread(phdrs.data(),sizeof(Elf64_Phdr),ehdr.e_phnum,f)!=ehdr.e_phnum){fclose(f);return 0;}
    uintptr_t load_base=UINTPTR_MAX;
    for(auto& ph:phdrs) if(ph.p_type==PT_LOAD&&ph.p_vaddr<load_base) load_base=ph.p_vaddr;
    if(load_base==UINTPTR_MAX) load_base=0;
    Elf64_Phdr* dyn=nullptr;
    for(auto& ph:phdrs) if(ph.p_type==PT_DYNAMIC){dyn=&ph;break;}
    if(!dyn){fclose(f);return 0;}
    size_t dc=dyn->p_filesz/sizeof(Elf64_Dyn);
    std::vector<Elf64_Dyn> dyns(dc);
    fseek(f,(long)dyn->p_offset,SEEK_SET);
    if(fread(dyns.data(),sizeof(Elf64_Dyn),dc,f)!=dc){fclose(f);return 0;}
    uintptr_t symtab_va=0,strtab_va=0,hash_va=0; size_t strsz=0,syment=sizeof(Elf64_Sym);
    for(auto& d:dyns){switch(d.d_tag){
        case DT_SYMTAB:symtab_va=d.d_un.d_ptr;break;case DT_STRTAB:strtab_va=d.d_un.d_ptr;break;
        case DT_STRSZ:strsz=d.d_un.d_val;break;case DT_SYMENT:syment=d.d_un.d_val;break;
        case DT_HASH:hash_va=d.d_un.d_ptr;break;default:break;}}
    if(!symtab_va||!strtab_va||!strsz){fclose(f);return 0;}
    auto va_to_foff=[&](uintptr_t va)->int64_t{
        for(auto& ph:phdrs){if(ph.p_type!=PT_LOAD)continue;
            if(va>=ph.p_vaddr&&va<ph.p_vaddr+ph.p_filesz)
                return(int64_t)(ph.p_offset+(va-ph.p_vaddr));}return -1;};
    int64_t strtab_off=va_to_foff(strtab_va),symtab_off=va_to_foff(symtab_va);
    if(strtab_off<0||symtab_off<0){fclose(f);return 0;}
    std::vector<char> strtab(strsz);
    fseek(f,(long)strtab_off,SEEK_SET);
    if(fread(strtab.data(),1,strsz,f)!=strsz){fclose(f);return 0;}
    size_t nsyms=0;
    if(hash_va){int64_t ho=va_to_foff(hash_va);if(ho>=0){uint32_t h[2];fseek(f,(long)ho,SEEK_SET);
        if(fread(h,sizeof(h),1,f)==1) nsyms=h[1];}}
    if(nsyms==0) nsyms=32768;
    for(size_t i=0;i<nsyms;i++){
        Elf64_Sym sym; fseek(f,(long)(symtab_off+(int64_t)(i*syment)),SEEK_SET);
        if(fread(&sym,sizeof(sym),1,f)!=1) break;
        if(sym.st_name==0||sym.st_name>=strsz||ELF64_ST_TYPE(sym.st_info)!=STT_FUNC||sym.st_shndx==SHN_UNDEF) continue;
        if(symbol==(strtab.data()+sym.st_name)){fclose(f);return sym.st_value-load_base;}}
    fclose(f); return 0;
}

uintptr_t Injection::find_elf_symbol(const std::string& fp, const std::string& sym) {
    return find_elf_symbol_impl(fp, sym);
}

Injection& Injection::instance() { static Injection inst; return inst; }

std::string Injection::read_proc_cmdline(pid_t pid) {
    try{std::ifstream f("/proc/"+std::to_string(pid)+"/cmdline",std::ios::binary);if(!f)return{};
        std::string r((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
        std::replace(r.begin(),r.end(),'\0',' ');while(!r.empty()&&r.back()==' ')r.pop_back();return r;}
    catch(...){return{};}
}

std::string Injection::read_proc_comm(pid_t pid) {
    try{std::ifstream f("/proc/"+std::to_string(pid)+"/comm");if(!f)return{};
        std::string s;std::getline(f,s);while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();return s;}
    catch(...){return{};}
}

std::string Injection::read_proc_exe(pid_t pid) {
    try{return fs::read_symlink("/proc/"+std::to_string(pid)+"/exe").string();}catch(...){return{};}
}

bool Injection::has_roblox_token(const std::string& s) {
    for(const auto& t:ROBLOX_TOKENS) if(s.find(t)!=std::string::npos) return true;
    return false;
}

bool Injection::process_alive() const { pid_t p=memory_.get_pid(); return p>0&&kill(p,0)==0; }
bool Injection::is_attached() const { return memory_.is_valid()&&state_==InjectionState::Ready&&process_alive()&&payload_loaded_; }

void Injection::set_status_callback(StatusCallback cb) { std::lock_guard<std::mutex> lk(mtx_); status_cb_=std::move(cb); }

void Injection::set_state(InjectionState s, const std::string& msg) {
    state_=s; if(s==InjectionState::Failed) error_=msg;
    StatusCallback cb; {std::lock_guard<std::mutex> lk(mtx_);cb=status_cb_;}
    if(cb) cb(s,msg);
    LOG_INFO("[injection] {}",msg);
}

std::vector<pid_t> Injection::descendants(pid_t root) {
    std::vector<pid_t> all;
    auto children=[](pid_t parent){std::vector<pid_t> ch;
        try{for(const auto& e:fs::directory_iterator("/proc")){
            if(!e.is_directory()) continue;
            std::string dn=e.path().filename().string();
            if(!std::all_of(dn.begin(),dn.end(),::isdigit)) continue;
            pid_t pid=std::stoi(dn);
            if(pid==parent)continue;
            try{std::ifstream sf(e.path()/"stat");std::string line;std::getline(sf,line);
                auto ce=line.rfind(')');if(ce==std::string::npos)continue;
                std::istringstream iss(line.substr(ce+2));char st;pid_t pp;iss>>st>>pp;
                if(pp==parent)ch.push_back(pid);}catch(...){}}}catch(...){}return ch;};
    std::vector<pid_t> frontier=children(root);
    while(!frontier.empty()){std::vector<pid_t> next;
        for(auto p:frontier){all.push_back(p);auto c=children(p);next.insert(next.end(),c.begin(),c.end());}
        frontier=std::move(next);}
    return all;
}

ProcessInfo Injection::gather_info(pid_t pid) {
    ProcessInfo info; info.pid=pid;
    info.name=read_proc_comm(pid); info.cmdline=read_proc_cmdline(pid); info.exe_path=read_proc_exe(pid);
    try{std::ifstream sf("/proc/"+std::to_string(pid)+"/stat");std::string line;std::getline(sf,line);
        auto ce=line.rfind(')');if(ce!=std::string::npos){std::istringstream iss(line.substr(ce+2));char st;iss>>st>>info.parent_pid;}}catch(...){}
    auto cl=[](const std::string& h,const std::string& n){std::string a=h,b=n;
        std::transform(a.begin(),a.end(),a.begin(),::tolower);
        std::transform(b.begin(),b.end(),b.begin(),::tolower);return a.find(b)!=std::string::npos;};
    info.via_wine=cl(info.exe_path,"wine")||cl(info.name,"wine")||cl(info.cmdline,"wine");
    info.via_sober=cl(info.exe_path,"sober")||cl(info.cmdline,"sober")||cl(info.name,"sober")||
                   cl(info.exe_path,"vinegar")||cl(info.cmdline,"vinegar");
    info.via_flatpak=info.exe_path.find("/app/")!=std::string::npos||
                     info.exe_path.find("flatpak")!=std::string::npos;
    if(!info.via_sober&&info.parent_pid>1){
        std::string pc=read_proc_cmdline(info.parent_pid),pe=read_proc_exe(info.parent_pid);
        if(cl(pc,"sober")||cl(pe,"sober")||cl(pc,"vinegar")) info.via_sober=true;}
    return info;
}

void Injection::adopt_target(pid_t pid, const std::string& via) {
    std::string comm=read_proc_comm(pid),cmd=read_proc_cmdline(pid),exe=read_proc_exe(pid);
    if(!is_valid_target(pid,comm,cmd,exe)) return;
    if(dhook_.active&&memory_.get_pid()>0&&memory_.get_pid()!=pid) cleanup_direct_hook();
    memory_.set_pid(pid); proc_info_=gather_info(pid);
    set_state(InjectionState::Found,"Found Roblox "+via+" (PID "+std::to_string(pid)+")");
}

pid_t Injection::find_roblox_child(pid_t wrapper_pid) {
    auto children=descendants(wrapper_pid); if(children.empty()) return -1;
    for(auto cpid:children){if(is_self_process(cpid))continue;
        std::string cc=read_proc_comm(cpid),cm=read_proc_cmdline(cpid);
        if(has_roblox_token(cc)||has_roblox_token(cm)) return cpid;}
    for(auto cpid:children){if(is_self_process(cpid))continue;
        try{std::ifstream maps("/proc/"+std::to_string(cpid)+"/maps");std::string line;
            bool has_r=false;size_t tsz=0;
            while(std::getline(maps,line)){uintptr_t lo,hi;
                if(sscanf(line.c_str(),"%lx-%lx",&lo,&hi)==2)tsz+=(hi-lo);
                std::string lw=line;std::transform(lw.begin(),lw.end(),lw.begin(),::tolower);
                if(lw.find("roblox")!=std::string::npos)has_r=true;}
            if(has_r&&tsz>50*1024*1024) return cpid;}catch(...){};}
    pid_t best=-1;size_t bsz=0;
    for(auto cpid:children){if(is_self_process(cpid))continue;
        try{std::ifstream sm("/proc/"+std::to_string(cpid)+"/statm");size_t pg=0;
            if(sm>>pg){size_t b=pg*4096;if(b>bsz){bsz=b;best=cpid;}}}catch(...){};}
    if(best>0&&bsz>100*1024*1024) return best;
    return -1;
}

bool Injection::scan_direct() {
    for(const auto& t:DIRECT_TARGETS){
        for(auto p:Memory::find_all_processes(t)){
            if(is_self_process(p)||is_self_process_name(read_proc_comm(p))) continue;
            std::string exe=read_proc_exe(p),comm=read_proc_comm(p);
            if(comm=="bwrap"||exe.find("/bwrap")!=std::string::npos){
                pid_t ch=find_roblox_child(p);
                if(ch>0){adopt_target(ch,"Sober child");if(memory_.is_valid()){proc_info_.via_sober=true;return true;}}
                continue;}
            size_t vp=0;try{std::ifstream sm("/proc/"+std::to_string(p)+"/statm");sm>>vp;}catch(...){}
            if(vp>0&&vp*4096<20*1024*1024) continue;
            adopt_target(p,"direct '"+t+"'"); if(memory_.is_valid()) return true;}}
    return false;
}

bool Injection::scan_wine_cmdline() {
    for(const auto& h:WINE_HOSTS) for(auto pid:Memory::find_all_processes(h)){
        if(is_self_process(pid)) continue;
        if(has_roblox_token(read_proc_cmdline(pid))){adopt_target(pid,"via Wine cmdline");
            if(memory_.is_valid()){proc_info_.via_wine=true;return true;}}}
    return false;
}

bool Injection::scan_wine_regions() {
    for(const auto& h:WINE_HOSTS) for(auto pid:Memory::find_all_processes(h)){
        if(is_self_process(pid)) continue;
        Memory mem(pid);
        for(const auto& r:mem.get_regions()){std::string lp=r.path;
            std::transform(lp.begin(),lp.end(),lp.begin(),::tolower);
            if(lp.find("roblox")!=std::string::npos){adopt_target(pid,"via Wine memory region");
                if(memory_.is_valid()){proc_info_.via_wine=true;return true;}}}}
    return false;
}

bool Injection::scan_flatpak() {
    for(auto bpid:Memory::find_all_processes("bwrap")){
        if(is_self_process(bpid)) continue;
        std::string bl=read_proc_cmdline(bpid);std::transform(bl.begin(),bl.end(),bl.begin(),::tolower);
        if(bl.find("sober")==std::string::npos&&bl.find("vinegar")==std::string::npos&&
           bl.find("roblox")==std::string::npos) continue;
        pid_t ch=find_roblox_child(bpid);
        if(ch>0){adopt_target(ch,"via Sober/Flatpak");
            if(memory_.is_valid()){proc_info_.via_sober=true;proc_info_.via_flatpak=true;return true;}}}
    return false;
}

bool Injection::scan_brute() {
    try{for(const auto& e:fs::directory_iterator("/proc")){
        if(!e.is_directory()) continue;
        std::string d=e.path().filename().string();
        if(!std::all_of(d.begin(),d.end(),::isdigit)) continue;
        pid_t pid=std::stoi(d); if(pid<=1||is_self_process(pid)) continue;
        std::string comm=read_proc_comm(pid);if(is_self_process_name(comm))continue;
        std::string cmd=read_proc_cmdline(pid);if(is_self_process_name(cmd))continue;
        if(has_roblox_token(cmd)){adopt_target(pid,"via brute scan");if(memory_.is_valid())return true;}
    }}catch(...){}
    return false;
}

bool Injection::scan_for_roblox() {
    set_state(InjectionState::Scanning,"Scanning for Roblox...");
    if(scan_flatpak()||scan_direct()||scan_wine_cmdline()||scan_wine_regions()||scan_brute()) return true;
    set_state(InjectionState::Idle,"Roblox not found"); return false;
}

pid_t Injection::find_roblox_pid() {
    if(memory_.is_valid()&&process_alive()) return memory_.get_pid();
    return scan_for_roblox()?memory_.get_pid():-1;
}

bool Injection::write_to_process(uintptr_t addr, const void* data, size_t len) {
    pid_t pid=memory_.get_pid(); if(pid<=0) return false;
    struct iovec l={const_cast<void*>(data),len},r={reinterpret_cast<void*>(addr),len};
    if(process_vm_writev(pid,&l,1,&r,1,0)==(ssize_t)len) return true;
    std::string path="/proc/"+std::to_string(pid)+"/mem";
    int fd=open(path.c_str(),O_RDWR); if(fd<0) return false;
    ssize_t w=pwrite(fd,data,len,(off_t)addr); close(fd); return w==(ssize_t)len;
}

bool Injection::read_from_process(uintptr_t addr, void* buf, size_t len) {
    pid_t pid=memory_.get_pid(); if(pid<=0) return false;
    struct iovec l={buf,len},r={reinterpret_cast<void*>(addr),len};
    if(process_vm_readv(pid,&l,1,&r,1,0)==(ssize_t)len) return true;
    std::ifstream f("/proc/"+std::to_string(pid)+"/mem",std::ios::binary);
    if(!f) return false;
    f.seekg((std::streamoff)addr);
    f.read((char*)buf,(std::streamsize)len); return f.gcount()==(std::streamsize)len;
}

bool Injection::proc_mem_write(pid_t pid, uintptr_t addr, const void* data, size_t len) {
    std::string path="/proc/"+std::to_string(pid)+"/mem";
    int fd=open(path.c_str(),O_RDWR);
    if(fd>=0){ssize_t w=pwrite(fd,data,len,(off_t)addr);close(fd);if(w==(ssize_t)len)return true;}
    struct iovec l={const_cast<void*>(data),len},r={reinterpret_cast<void*>(addr),len};
    if(process_vm_writev(pid,&l,1,&r,1,0)==(ssize_t)len) return true;
    return elevated_mem_write(pid,addr,data,len);
}

bool Injection::proc_mem_read(pid_t pid, uintptr_t addr, void* buf, size_t len) {
    struct iovec l={buf,len},r={reinterpret_cast<void*>(addr),len};
    if(process_vm_readv(pid,&l,1,&r,1,0)==(ssize_t)len) return true;
    std::string path="/proc/"+std::to_string(pid)+"/mem";
    int fd=open(path.c_str(),O_RDONLY); if(fd<0) return false;
    ssize_t rd=pread(fd,buf,len,(off_t)addr); close(fd); return rd==(ssize_t)len;
}

bool Injection::start_elevated_helper() {
    if(elevated_pid_>0) return true;
    std::string script="/tmp/.oss_mem_helper.py";
    {std::ofstream sf(script,std::ios::trunc);
     sf<<"import os,sys\nsys.stdout.write('R\\n')\nsys.stdout.flush()\nwhile True:\n"
         "  l=sys.stdin.readline()\n  if not l:break\n  p=l.strip().split(' ',3)\n"
         "  if p[0]=='W':\n    try:\n      f=os.open('/proc/'+p[1]+'/mem',os.O_RDWR)\n"
         "      os.pwrite(f,bytes.fromhex(p[3]),int(p[2]))\n      os.close(f)\n"
         "      sys.stdout.write('K\\n')\n    except Exception as e:\n"
         "      sys.stdout.write('E '+str(e)+'\\n')\n    sys.stdout.flush()\n"
         "  elif p[0]=='Q':break\n";}
    chmod(script.c_str(),0644);
    int to_child[2],from_child[2];
    if(pipe(to_child)<0){unlink(script.c_str());return false;}
    if(pipe(from_child)<0){close(to_child[0]);close(to_child[1]);unlink(script.c_str());return false;}
    pid_t child=fork();
    if(child==0){close(to_child[1]);close(from_child[0]);
        dup2(to_child[0],STDIN_FILENO);dup2(from_child[1],STDOUT_FILENO);
        close(to_child[0]);close(from_child[1]);
        execlp("pkexec","pkexec","/usr/bin/python3","-u",script.c_str(),nullptr);_exit(127);}
    if(child<0){close(to_child[0]);close(to_child[1]);close(from_child[0]);close(from_child[1]);unlink(script.c_str());return false;}
    close(to_child[0]);close(from_child[1]);
    elevated_pid_=child;elevated_in_fd_=to_child[1];elevated_out_fd_=from_child[0];
    struct pollfd pfd={elevated_out_fd_,POLLIN,0};
    if(poll(&pfd,1,30000)<=0){stop_elevated_helper();return false;}
    char buf[16]={};ssize_t n=read(elevated_out_fd_,buf,sizeof(buf)-1);
    if(n<=0||buf[0]!='R'){stop_elevated_helper();return false;}
    LOG_INFO("Elevated helper ready"); return true;
}

bool Injection::elevated_mem_write(pid_t pid, uintptr_t addr, const void* data, size_t len) {
    if(elevated_pid_<=0&&!start_elevated_helper()) return false;
    std::string hex; hex.reserve(len*2);
    const uint8_t* bytes=(const uint8_t*)data;
    for(size_t i=0;i<len;i++){char h[3];snprintf(h,sizeof(h),"%02x",bytes[i]);hex+=h;}
    std::string cmd="W "+std::to_string(pid)+" "+std::to_string(addr)+" "+hex+"\n";
    if(write(elevated_in_fd_,cmd.c_str(),cmd.size())!=(ssize_t)cmd.size()) return false;
    struct pollfd pfd={elevated_out_fd_,POLLIN,0};
    if(poll(&pfd,1,5000)<=0) return false;
    char buf[256]={};ssize_t n=read(elevated_out_fd_,buf,sizeof(buf)-1);
    return n>0&&buf[0]=='K';
}

void Injection::stop_elevated_helper() {
    if(elevated_in_fd_>=0){(void)!write(elevated_in_fd_,"Q\n",2);close(elevated_in_fd_);elevated_in_fd_=-1;}
    if(elevated_out_fd_>=0){close(elevated_out_fd_);elevated_out_fd_=-1;}
    if(elevated_pid_>0){int st;
        if(waitpid(elevated_pid_,&st,WNOHANG)==0){kill(elevated_pid_,SIGTERM);usleep(100000);
            if(waitpid(elevated_pid_,&st,WNOHANG)==0){kill(elevated_pid_,SIGKILL);waitpid(elevated_pid_,&st,0);}}
        elevated_pid_=-1;}
    unlink("/tmp/.oss_mem_helper.py");
}

bool Injection::freeze_tracer(pid_t tp) {
    if(tp<=0) return false;
    if(kill(tp,SIGSTOP)!=0) return false;
    for(int i=0;i<50;i++){usleep(10000);auto pd=get_process_details(tp);
        if(pd.state=='T'||pd.state=='t') return true;}
    kill(tp,SIGCONT); return false;
}

void Injection::thaw_tracer(pid_t tp) { if(tp>0) kill(tp,SIGCONT); }

bool Injection::should_scan_region(const MemoryRegion& r) const {
    if(!r.readable()||r.size()<REGION_MIN||r.size()>REGION_MAX) return false;
    if(r.path.empty()||r.path[0]=='[') return true;
    for(const auto& kw:PATH_KEYWORDS) if(r.path.find(kw)!=std::string::npos) return true;
    if(r.path[0]=='/'&&r.path.find("/lib")!=std::string::npos) return false;
    return r.path[0]!='/';
}

bool Injection::cross_validate(uintptr_t rs, size_t rsz) {
    size_t chk=std::min(rsz,(size_t)0x200000); int hits=0;
    for(const auto& sec:SECONDARY_MARKERS){
        std::vector<uint8_t> pat(sec.begin(),sec.end());std::string mask(pat.size(),'x');
        if(memory_.pattern_scan(pat,mask,rs,chk).has_value()&&++hits>=2) return true;}
    return false;
}

bool Injection::locate_luau_vm() {
    auto regions=memory_.get_regions(); vm_scan_={}; vm_marker_addr_=0;
    uintptr_t ba=0;std::string bm,bp;uintptr_t bb=0;int bh=0;
    for(const auto& region:regions){
        if(!should_scan_region(region)) continue;
        vm_scan_.regions_scanned++;
        int rh=0;uintptr_t fh=0;std::string fm;
        for(const auto& marker:PRIMARY_MARKERS){
            std::vector<uint8_t> pat(marker.begin(),marker.end());std::string mask(pat.size(),'x');
            size_t sl=std::min(region.size(),REGION_SCAN_CAP); vm_scan_.bytes_scanned+=sl;
            auto res=memory_.pattern_scan(pat,mask,region.start,sl);
            if(!res) continue;
            rh++; if(fh==0){fh=*res;fm=marker;}
            if(rh>=3&&cross_validate(region.start,region.size())){
                vm_scan_.marker_addr=fh;vm_scan_.region_base=region.start;
                vm_scan_.marker_name=fm;vm_scan_.region_path=region.path.empty()?"[anon]":region.path;
                vm_scan_.validated=true;vm_marker_addr_=fh;return true;}}
        if(rh>bh){bh=rh;ba=fh;bm=fm;bp=region.path.empty()?"[anon]":region.path;bb=region.start;}}
    if(ba&&bh>=2){vm_scan_.marker_addr=ba;vm_scan_.region_base=bb;vm_scan_.marker_name=bm;
        vm_scan_.region_path=bp;vm_scan_.validated=false;vm_marker_addr_=ba;return true;}
    return false;
}

std::string Injection::find_payload_path() {
    std::vector<std::string> sp;
    char self[512]; ssize_t len=readlink("/proc/self/exe",self,sizeof(self)-1);
    if(len>0){self[len]='\0';fs::path ed=fs::path(self).parent_path();
        for(auto& s:{"liboss_payload.so","lib/liboss_payload.so","lib/oss-executor/liboss_payload.so",
                     "../lib/liboss_payload.so","../lib/oss-executor/liboss_payload.so","../build/liboss_payload.so"})
            sp.push_back((ed/s).string());}
    char cwd[512];if(getcwd(cwd,sizeof(cwd))){fs::path cd(cwd);
        for(auto& s:{"liboss_payload.so","build/liboss_payload.so","cmake-build-debug/liboss_payload.so","cmake-build-release/liboss_payload.so"})
            sp.push_back((cd/s).string());}
    for(auto& s:{"./liboss_payload.so","./build/liboss_payload.so","../build/liboss_payload.so",
                 "/usr/lib/oss-executor/liboss_payload.so","/usr/local/lib/oss-executor/liboss_payload.so"})
        sp.push_back(s);
    const char* home=getenv("HOME");
    if(home){sp.push_back(std::string(home)+"/.oss-executor/liboss_payload.so");
             sp.push_back(std::string(home)+"/.local/lib/oss-executor/liboss_payload.so");}
    const char* appdir=getenv("APPDIR");
    if(appdir){sp.push_back(std::string(appdir)+"/usr/lib/liboss_payload.so");
               sp.push_back(std::string(appdir)+"/usr/lib/oss-executor/liboss_payload.so");}
    for(const auto& p:sp) if(fs::exists(p)){LOG_INFO("Payload found: {}",fs::absolute(p).string());return fs::absolute(p).string();}
    LOG_WARN("Payload not found in {} paths",sp.size()); return "";
}

uintptr_t Injection::find_libc_function(pid_t pid, const std::string& fn) { return find_remote_symbol(pid,"c",fn); }

uintptr_t Injection::find_remote_symbol(pid_t pid, const std::string& lib_name, const std::string& symbol) {
    std::string bso6="lib"+lib_name+".so.6", bso="lib"+lib_name+".so";
    std::ifstream maps("/proc/"+std::to_string(pid)+"/maps"); if(!maps) return 0;
    uintptr_t rb=0;std::string lf;std::string line;
    while(std::getline(maps,line)){
        if(line.find(bso6)==std::string::npos&&line.find(bso)==std::string::npos) continue;
        unsigned long lo,fo;char perms[5]{};
        if(sscanf(line.c_str(),"%lx-%*x %4s %lx",&lo,perms,&fo)<3) continue;
        if(fo==0&&rb==0){rb=lo;auto sl=line.find('/');
            if(sl!=std::string::npos){lf=line.substr(sl);auto e=lf.find_last_not_of(" \n\r\t");if(e!=std::string::npos)lf=lf.substr(0,e+1);}}}
    if(rb==0) return 0;
    if(!lf.empty()){
        std::string ns="/proc/"+std::to_string(pid)+"/root"+lf;struct stat st;std::string ep;
        if(::stat(ns.c_str(),&st)==0) ep=ns; else if(::stat(lf.c_str(),&st)==0) ep=lf;
        if(!ep.empty()){uintptr_t so=find_elf_symbol_impl(ep,symbol);if(so)return rb+so;}}
    if(proc_info_.via_flatpak||proc_info_.via_sober) return 0;
    uintptr_t ls=0;
    void* h=dlopen(("lib"+lib_name+".so.6").c_str(),RTLD_LAZY|RTLD_NOLOAD);
    if(!h) h=dlopen(("lib"+lib_name+".so").c_str(),RTLD_LAZY|RTLD_NOLOAD);
    if(!h) h=dlopen(nullptr,RTLD_LAZY);
    if(h){void* sym=dlsym(h,symbol.c_str());if(sym)ls=(uintptr_t)sym;dlclose(h);}
    if(ls==0) return 0;
    uintptr_t lb=0; Dl_info info;
    if(dladdr((void*)ls,&info)) lb=(uintptr_t)info.dli_fbase;
    return lb?rb+(ls-lb):0;
}

std::string Injection::prepare_payload_for_injection(pid_t pid, const std::string& host_path) {
    if(!proc_info_.via_flatpak&&!proc_info_.via_sober) return host_path;
    std::string nst="/proc/"+std::to_string(pid)+"/root/tmp",nd=nst+"/liboss_payload.so";
    try{struct stat st;if(::stat(nst.c_str(),&st)!=0)return host_path;
        std::ifstream src(host_path,std::ios::binary);if(!src)return host_path;
        std::ofstream dst(nd,std::ios::binary|std::ios::trunc);if(!dst)return host_path;
        dst<<src.rdbuf();dst.close();::chmod(nd.c_str(),0755);return "/tmp/liboss_payload.so";}
    catch(...){return host_path;}
}

std::string Injection::resolve_socket_path() {
    if(proc_info_.via_flatpak||proc_info_.via_sober){pid_t pid=memory_.get_pid();
        if(pid>0){std::string ns="/proc/"+std::to_string(pid)+"/root"+PAYLOAD_SOCK;
            struct stat st;if(::stat(ns.c_str(),&st)==0)return ns;}}
    return PAYLOAD_SOCK;
}

struct ExeRegionInfo { uintptr_t text_end,padding_start,base; size_t padding_size; };

static bool find_code_cave(pid_t pid, const std::vector<MemoryRegion>& regions,
                           size_t needed, ExeRegionInfo& out) {
    for(size_t i=0;i+1<regions.size();i++){
        const auto& r=regions[i];
        if(!r.executable()||!r.readable()||r.path.empty()||r.path[0]=='[') continue;
        uintptr_t end=r.end, pe=(end+0xFFF)&~0xFFFULL;
        if(pe>end&&(pe-end)>=needed){
            std::vector<uint8_t> probe(needed,0);
            struct iovec l={probe.data(),needed},rv={reinterpret_cast<void*>(end),needed};
            if(process_vm_readv(pid,&l,1,&rv,1,0)==(ssize_t)needed){
                bool ok=true;for(auto b:probe)if(b!=0&&b!=0xCC){ok=false;break;}
                if(ok){out={end,end,r.start,pe-end};return true;}}}}
    for(const auto& r:regions){
        if(!r.executable()||!r.readable()||r.size()<needed+64) continue;
        size_t ss=std::min(r.size(),(size_t)0x10000);uintptr_t sstart=r.end-ss;
        std::vector<uint8_t> buf(ss);
        struct iovec l={buf.data(),ss},rv={reinterpret_cast<void*>(sstart),ss};
        if(process_vm_readv(pid,&l,1,&rv,1,0)!=(ssize_t)ss) continue;
        for(size_t off=ss-needed;off>0;off--){
            bool ok=true;for(size_t j=0;j<needed;j++)
                if(buf[off+j]!=0x00&&buf[off+j]!=0xCC&&buf[off+j]!=0x90){ok=false;break;}
            if(ok){out={sstart+off,sstart+off,r.start,needed};return true;}}}
    return false;
}

struct ThreadState{uintptr_t rip,rsp;};

static bool get_thread_state(pid_t pid, pid_t tid, ThreadState& out) {
    std::string path="/proc/"+std::to_string(pid)+"/task/"+std::to_string(tid)+"/syscall";
    std::ifstream f(path);
    if(!f){f.open("/proc/"+std::to_string(pid)+"/syscall");if(!f)return false;}
    std::string line;std::getline(f,line);
    if(line.empty()||line=="running") return false;
    std::vector<std::string> fields;std::istringstream iss(line);std::string field;
    while(iss>>field)fields.push_back(field);
    if(fields.size()<9) return false;
    out.rsp=std::stoull(fields[7],nullptr,16);
    out.rip=std::stoull(fields[8],nullptr,16);
    return out.rip!=0;
}

static pid_t pick_injectable_thread(pid_t pid) {
    std::string td="/proc/"+std::to_string(pid)+"/task";
    try{for(const auto& e:fs::directory_iterator(td)){
        std::string n=e.path().filename().string();
        if(!std::all_of(n.begin(),n.end(),::isdigit)) continue;
        pid_t tid=std::stoi(n);ThreadState ts;
        if(get_thread_state(pid,tid,ts)&&ts.rip!=0) return tid;}}catch(...){}
    return pid;
}

static uintptr_t find_data_region(const std::vector<MemoryRegion>& regions) {
    size_t best_size=0; uintptr_t best=0;
    for(const auto& r:regions){
        if(!r.writable()||!r.readable()||r.size()<8192) continue;
        if(r.path.find("[stack")!=std::string::npos||r.path.find("[vvar")!=std::string::npos||
           r.path.find("[vdso")!=std::string::npos||r.path.find("heap")!=std::string::npos) continue;
        if(!r.path.empty()&&r.path[0]=='/') continue;
        if(r.size()>best_size){best_size=r.size();best=r.start+r.size()-4096;}}
    if(best) return best;
    for(const auto& r:regions){
        if(!r.writable()||!r.readable()||r.size()<8192) continue;
        if(r.path.find("[stack")!=std::string::npos||r.path.find("[vvar")!=std::string::npos||
           r.path.find("[vdso")!=std::string::npos) continue;
        return r.start+((r.size()/2)&~(size_t)0xFFF);}
    return 0;
}

static bool install_jump_patch(uint8_t* patch, size_t& patch_len,
                               uintptr_t from, uintptr_t to, size_t steal) {
    int64_t disp=(int64_t)to-(int64_t)(from+5);
    if(disp>=INT32_MIN&&disp<=INT32_MAX&&steal>=5){
        patch[0]=0xE9;int32_t r32=(int32_t)disp;memcpy(patch+1,&r32,4);
        for(size_t i=5;i<steal;i++) patch[i]=0x90;
        patch_len=steal;return true;}
    if(steal>=14){
        patch[0]=0xFF;patch[1]=0x25;memset(patch+2,0,4);memcpy(patch+6,&to,8);
        patch_len=14;return true;}
    return false;
}

bool Injection::inject_via_inline_hook(pid_t pid, const std::string& lib_path,
                                        uintptr_t dlopen_addr, uint64_t dlopen_flags) {
    LOG_INFO("Attempting inline hook injection into PID {}...",pid);
    const char* candidates[]={"nanosleep","clock_nanosleep","poll","epoll_wait","usleep",
        "select","pselect","read","write","clock_gettime","gettimeofday"};
    uintptr_t hook_func_addr=0; const char* hooked_name=nullptr;
    uint8_t orig_prologue[16];
    int steal_size=0;

    for(const char* name:candidates){
        uintptr_t addr=find_remote_symbol(pid,"c",name); if(!addr) continue;
        if(!proc_mem_read(pid,addr,orig_prologue,sizeof(orig_prologue))) continue;
        int pos=0;
        while(pos<14){size_t il=dh_insn_len(orig_prologue+pos);if(il==0)break;
            if(orig_prologue[pos]==0xC3||orig_prologue[pos]==0xCC) break;
            pos+=(int)il;if(pos>=5)break;}
        if(pos>=5){hook_func_addr=addr;hooked_name=name;steal_size=pos;
            LOG_INFO("Targeting '{}' at 0x{:X} (steal={})",name,addr,pos);break;}}
    if(!hook_func_addr){error_="No hookable libc function found";return false;}

    auto regions=memory_.get_regions();
    uintptr_t data_addr=find_data_region(regions);
    if(!data_addr){error_="No writable data region";return false;}

    uint8_t orig_data[4096];
    if(!proc_mem_read(pid,data_addr,orig_data,sizeof(orig_data))){error_="Failed to save data region";return false;}

    uintptr_t path_addr=data_addr,result_addr=data_addr+512,guard_addr=data_addr+520,completion_addr=data_addr+528;
    static constexpr uint64_t GUARD_MAGIC=0x4F53534755415244ULL,COMPLETION_MAGIC=0x4F5353444F4E4521ULL;

    uint8_t path_buf[512]={};
    memcpy(path_buf,lib_path.c_str(),std::min(lib_path.size(),sizeof(path_buf)-1));
    if(!proc_mem_write(pid,path_addr,path_buf,lib_path.size()+1)){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));error_="Failed to write lib path";return false;}

    uint64_t zero=0,magic=GUARD_MAGIC;
    proc_mem_write(pid,result_addr,&zero,8);
    proc_mem_write(pid,guard_addr,&magic,8);
    proc_mem_write(pid,completion_addr,&zero,8);

    usleep(20000);
    uint64_t vg=0;proc_mem_read(pid,guard_addr,&vg,8);
    if(vg!=GUARD_MAGIC){
        proc_mem_write(pid,guard_addr,&magic,8);usleep(20000);
        proc_mem_read(pid,guard_addr,&vg,8);
        if(vg!=GUARD_MAGIC){proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));
            error_="Data region unstable";return false;}}

    std::vector<MemoryRegion> nearby;
    for(const auto& r:regions){
        int64_t d=(int64_t)r.start-(int64_t)hook_func_addr;
        if(d>INT32_MIN&&d<INT32_MAX) nearby.push_back(r);
        else{d=(int64_t)r.end-(int64_t)hook_func_addr;if(d>INT32_MIN&&d<INT32_MAX)nearby.push_back(r);}}

    ExeRegionInfo cave;
    if(!find_code_cave(pid,nearby,256,cave)){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));
        error_="No reachable code cave";return false;}

    uint8_t orig_cave[256];
    if(!proc_mem_read(pid,cave.padding_start,orig_cave,256)){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));error_="Failed to save cave";return false;}

    uint8_t sc[256]; memset(sc,0xCC,sizeof(sc)); int off=0;
    sc[off++]=0x9C;
    for(uint8_t r:{0x50,0x51,0x52,0x53,0x55,0x56,0x57}) sc[off++]=r;
    for(int r=0x50;r<=0x57;r++){sc[off++]=0x41;sc[off++]=(uint8_t)r;}
    sc[off++]=0x55;sc[off++]=0x48;sc[off++]=0x89;sc[off++]=0xE5;
    sc[off++]=0x48;sc[off++]=0x83;sc[off++]=0xE4;sc[off++]=0xF0;

    sc[off++]=0x48;sc[off++]=0xBA;memcpy(sc+off,&guard_addr,8);off+=8;
    sc[off++]=0x48;sc[off++]=0xB8;memcpy(sc+off,&magic,8);off+=8;
    sc[off++]=0xB9;sc[off++]=0x01;sc[off++]=0x00;sc[off++]=0x00;sc[off++]=0x00;
    sc[off++]=0xF0;sc[off++]=0x48;sc[off++]=0x0F;sc[off++]=0xB1;sc[off++]=0x0A;
    sc[off++]=0x0F;sc[off++]=0x85;int jnz_off=off;off+=4;

    sc[off++]=0x48;sc[off++]=0xBF;memcpy(sc+off,&path_addr,8);off+=8;
    sc[off++]=0x48;sc[off++]=0xBE;memcpy(sc+off,&dlopen_flags,8);off+=8;
    sc[off++]=0x48;sc[off++]=0xB8;memcpy(sc+off,&dlopen_addr,8);off+=8;
    sc[off++]=0xFF;sc[off++]=0xD0;

    sc[off++]=0x48;sc[off++]=0xBA;memcpy(sc+off,&result_addr,8);off+=8;
    sc[off++]=0x48;sc[off++]=0x89;sc[off++]=0x02;

    uint64_t comp=COMPLETION_MAGIC;
    sc[off++]=0x48;sc[off++]=0xBA;memcpy(sc+off,&completion_addr,8);off+=8;
    sc[off++]=0x48;sc[off++]=0xB8;memcpy(sc+off,&comp,8);off+=8;
    sc[off++]=0x48;sc[off++]=0x89;sc[off++]=0x02;

    int skip_target=off;
    int32_t jnz_rel=skip_target-(jnz_off+4);memcpy(sc+jnz_off,&jnz_rel,4);

    sc[off++]=0x48;sc[off++]=0x89;sc[off++]=0xEC;sc[off++]=0x5D;
    for(int r=0x5F;r>=0x58;r--){sc[off++]=0x41;sc[off++]=(uint8_t)r;}
    for(uint8_t r:{0x5F,0x5E,0x5D,0x5B,0x5A,0x59,0x58}) sc[off++]=r;
    sc[off++]=0x9D;

    memcpy(sc+off,orig_prologue,steal_size);off+=steal_size;

    uintptr_t jmp_to=hook_func_addr+steal_size;
    int64_t jmp_disp=(int64_t)jmp_to-(int64_t)(cave.padding_start+off+5);
    if(jmp_disp>=INT32_MIN&&jmp_disp<=INT32_MAX){
        sc[off++]=0xE9;int32_t r32=(int32_t)jmp_disp;memcpy(sc+off,&r32,4);off+=4;
    }else{sc[off++]=0xFF;sc[off++]=0x25;sc[off++]=0;sc[off++]=0;sc[off++]=0;sc[off++]=0;
        memcpy(sc+off,&jmp_to,8);off+=8;}

    if((size_t)off>256){error_="Shellcode too large";proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));return false;}
    if(!proc_mem_write(pid,cave.padding_start,sc,off)){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));error_="Failed to write shellcode";return false;}

    uint8_t hook_patch[16];size_t hook_size=0;
    if(!install_jump_patch(hook_patch,hook_size,hook_func_addr,cave.padding_start,steal_size)){
        proc_mem_write(pid,cave.padding_start,orig_cave,256);
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));error_="Cannot encode jump";return false;}

    if(!proc_mem_write(pid,hook_func_addr,hook_patch,hook_size)){
        proc_mem_write(pid,cave.padding_start,orig_cave,256);
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));error_="Failed to install hook";return false;}

    bool completed=false;uint64_t result=0;
    for(int i=0;i<100;i++){
        usleep(100000);if(kill(pid,0)!=0){error_="Process died";return false;}
        uint64_t c=0;proc_mem_read(pid,completion_addr,&c,8);
        if(c==COMPLETION_MAGIC){proc_mem_read(pid,result_addr,&result,8);completed=true;break;}}

    proc_mem_write(pid,hook_func_addr,orig_prologue,steal_size);
    usleep(50000);
    proc_mem_write(pid,cave.padding_start,orig_cave,256);
    proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));

    if(!completed){error_="Inline hook timed out";return false;}
    if(result==0){error_="dlopen returned NULL";return false;}

    bool lib_mapped=false;
    for(int retry=0;retry<10&&!lib_mapped;retry++){
        if(retry>0)usleep(100000);
        std::ifstream mc("/proc/"+std::to_string(pid)+"/maps");std::string ml;
        while(std::getline(mc,ml))
            if(ml.find("liboss_payload")!=std::string::npos){lib_mapped=true;break;}}

    if(!lib_mapped&&(proc_info_.via_flatpak||proc_info_.via_sober)){
        LOG_WARN("dlopen handle 0x{:X} — assuming success for containerized env",result);
        lib_mapped=true;}

    if(!lib_mapped){error_="Library not found in /proc/maps after dlopen";return false;}
    payload_loaded_=true;stop_elevated_helper();return true;
}

bool Injection::inject_via_procmem(pid_t pid, const std::string& lib_path,
                                    uintptr_t dlopen_addr, uint64_t dlopen_flags) {
    LOG_INFO("inject_via_procmem: PID {} lib={}",pid,lib_path);
    ProcessDetails pd=get_process_details(pid);
    pid_t tracer=pd.tracer_pid;bool tracer_frozen=false;
    if(tracer>0&&tracer!=getpid()){
        tracer_frozen=freeze_tracer(tracer);
        if(!tracer_frozen) return inject_via_inline_hook(pid,lib_path,dlopen_addr,dlopen_flags);}
    auto cleanup_tracer=[&](){if(tracer_frozen)thaw_tracer(tracer);};

    auto regions=memory_.get_regions();
    uintptr_t data_addr=find_data_region(regions);
    if(!data_addr){error_="No writable region";cleanup_tracer();return false;}

    uint8_t orig_data[4096];
    if(!proc_mem_read(pid,data_addr,orig_data,sizeof(orig_data))){error_="Failed to save data";cleanup_tracer();return false;}

    uintptr_t path_addr=data_addr,result_addr=data_addr+512,done_addr=data_addr+520;
    uint8_t path_buf[512]={};
    memcpy(path_buf,lib_path.c_str(),std::min(lib_path.size(),sizeof(path_buf)-1));
    if(!proc_mem_write(pid,data_addr,path_buf,lib_path.size()+1)){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));cleanup_tracer();error_="Failed to write path";return false;}
    uint64_t zero=0;
    proc_mem_write(pid,result_addr,&zero,8);proc_mem_write(pid,done_addr,&zero,8);

    ExeRegionInfo cave;
    if(!find_code_cave(pid,regions,256,cave)){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));cleanup_tracer();error_="No code cave";return false;}

    uint8_t orig_cave[256];
    if(!proc_mem_read(pid,cave.padding_start,orig_cave,256)){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));cleanup_tracer();error_="Failed to save cave";return false;}

    if(kill(pid,SIGSTOP)!=0){
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));cleanup_tracer();error_="SIGSTOP failed";return false;}

    bool stopped=false;
    for(int i=0;i<50;i++){usleep(10000);auto tpd=get_process_details(pid);
        if(tpd.state=='T'||tpd.state=='t'){stopped=true;break;}}
    if(!stopped){kill(pid,SIGCONT);proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));
        cleanup_tracer();return inject_via_inline_hook(pid,lib_path,dlopen_addr,dlopen_flags);}

    pid_t tid=pick_injectable_thread(pid);ThreadState ts;
    if(!get_thread_state(pid,tid,ts)){kill(pid,SIGCONT);
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));cleanup_tracer();
        error_="Cannot read thread state";return false;}

    uint8_t orig_rip_code[16];
    if(!proc_mem_read(pid,ts.rip,orig_rip_code,sizeof(orig_rip_code))){
        kill(pid,SIGCONT);proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));
        cleanup_tracer();error_="Failed to read code at RIP";return false;}

    uintptr_t return_addr=ts.rip;
    uint8_t sc[256];memset(sc,0,sizeof(sc));int off=0;
    sc[off++]=0x48;sc[off++]=0x81;sc[off++]=0xEC;sc[off++]=0x80;sc[off++]=0x00;sc[off++]=0x00;sc[off++]=0x00;
    sc[off++]=0x9C;
    for(uint8_t r:{0x50,0x51,0x52,0x53,0x55,0x56,0x57})sc[off++]=r;
    for(int r=0x50;r<=0x57;r++){sc[off++]=0x41;sc[off++]=(uint8_t)r;}
    sc[off++]=0x48;sc[off++]=0x89;sc[off++]=0xE5;sc[off++]=0x48;sc[off++]=0x83;sc[off++]=0xE4;sc[off++]=0xF0;

    sc[off++]=0x48;sc[off++]=0xBF;memcpy(sc+off,&path_addr,8);off+=8;
    sc[off++]=0x48;sc[off++]=0xBE;memcpy(sc+off,&dlopen_flags,8);off+=8;
    sc[off++]=0x48;sc[off++]=0xB8;memcpy(sc+off,&dlopen_addr,8);off+=8;
    sc[off++]=0xFF;sc[off++]=0xD0;

    sc[off++]=0x48;sc[off++]=0xB9;memcpy(sc+off,&result_addr,8);off+=8;
    sc[off++]=0x48;sc[off++]=0x89;sc[off++]=0x01;

    int spin_top=off;
    sc[off++]=0x48;sc[off++]=0xB9;memcpy(sc+off,&done_addr,8);off+=8;
    sc[off++]=0x48;sc[off++]=0x8B;sc[off++]=0x09;
    sc[off++]=0x48;sc[off++]=0x83;sc[off++]=0xF9;sc[off++]=0x01;
    sc[off++]=0x74;sc[off++]=0x04;sc[off++]=0xF3;sc[off++]=0x90;
    int8_t spin_disp=(int8_t)(spin_top-(off+2));
    sc[off++]=0xEB;sc[off++]=(uint8_t)spin_disp;

    sc[off++]=0x48;sc[off++]=0x89;sc[off++]=0xEC;
    for(int r=0x5F;r>=0x58;r--){sc[off++]=0x41;sc[off++]=(uint8_t)r;}
    for(uint8_t r:{0x5F,0x5E,0x5D,0x5B,0x5A,0x59,0x58})sc[off++]=r;
    sc[off++]=0x9D;
    sc[off++]=0x48;sc[off++]=0x81;sc[off++]=0xC4;sc[off++]=0x80;sc[off++]=0x00;sc[off++]=0x00;sc[off++]=0x00;
    sc[off++]=0xFF;sc[off++]=0x25;sc[off++]=0;sc[off++]=0;sc[off++]=0;sc[off++]=0;
    memcpy(sc+off,&return_addr,8);off+=8;

    if(!proc_mem_write(pid,cave.padding_start,sc,off)){
        kill(pid,SIGCONT);proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));
        cleanup_tracer();error_="Failed to write shellcode";return false;}

    uint8_t tramp[16];size_t toff=0;
    if(!install_jump_patch(tramp,toff,ts.rip,cave.padding_start,14)){
        kill(pid,SIGCONT);proc_mem_write(pid,cave.padding_start,orig_cave,256);
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));cleanup_tracer();
        error_="Failed to encode trampoline";return false;}

    if(!proc_mem_write(pid,ts.rip,tramp,toff)){
        kill(pid,SIGCONT);proc_mem_write(pid,cave.padding_start,orig_cave,256);
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));cleanup_tracer();
        error_="Failed to write trampoline";return false;}

    if(tracer_frozen){thaw_tracer(tracer);tracer_frozen=false;usleep(50000);}
    kill(pid,SIGCONT);
    for(int i=0;i<20;i++){usleep(25000);auto rpd=get_process_details(pid);
        if(rpd.state=='S'||rpd.state=='R'||rpd.state=='D')break;
        if(rpd.state=='T'||rpd.state=='t')kill(pid,SIGCONT);}

    bool completed=false;
    for(int i=0;i<100;i++){usleep(50000);uint64_t rv=0;
        if(proc_mem_read(pid,result_addr,&rv,8)&&rv!=0){completed=true;break;}
        if(kill(pid,0)!=0){error_="Process died";return false;}}

    if(!completed){
        if(tracer>0)tracer_frozen=freeze_tracer(tracer);
        kill(pid,SIGSTOP);usleep(50000);
        proc_mem_write(pid,ts.rip,orig_rip_code,sizeof(orig_rip_code));
        proc_mem_write(pid,cave.padding_start,orig_cave,256);
        proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));
        kill(pid,SIGCONT);if(tracer_frozen)thaw_tracer(tracer);
        return inject_via_inline_hook(pid,lib_path,dlopen_addr,dlopen_flags);}

    if(tracer>0)tracer_frozen=freeze_tracer(tracer);
    kill(pid,SIGSTOP);usleep(50000);
    proc_mem_write(pid,ts.rip,orig_rip_code,sizeof(orig_rip_code));
    uint64_t done_signal=1;proc_mem_write(pid,done_addr,&done_signal,8);
    if(tracer_frozen){thaw_tracer(tracer);tracer_frozen=false;usleep(50000);}
    kill(pid,SIGCONT);
    for(int i=0;i<20;i++){usleep(25000);auto rpd=get_process_details(pid);
        if(rpd.state=='S'||rpd.state=='R'||rpd.state=='D')break;
        if(rpd.state=='T'||rpd.state=='t')kill(pid,SIGCONT);}
    usleep(300000);
    proc_mem_write(pid,cave.padding_start,orig_cave,256);
    proc_mem_write(pid,data_addr,orig_data,sizeof(orig_data));

    if(!(proc_info_.via_flatpak||proc_info_.via_sober)){
        bool lib_mapped=false;
        std::ifstream mc("/proc/"+std::to_string(pid)+"/maps");std::string ml;
        while(std::getline(mc,ml))if(ml.find("liboss_payload")!=std::string::npos){lib_mapped=true;break;}
        if(!lib_mapped){error_="Library not in /proc/maps";stop_elevated_helper();return false;}}

    stop_elevated_helper();payload_loaded_=true;return true;
}

bool Injection::inject_shellcode_ptrace(pid_t pid, const std::string& lib_path,
                                         uintptr_t dlopen_addr, uint64_t dlopen_flags) {
    auto wait_for_trap=[](pid_t p)->bool{
        for(int i=0;i<200;i++){int st;int wr=waitpid(p,&st,0);if(wr==-1)return false;
            if(WIFSTOPPED(st)){int sig=WSTOPSIG(st);if(sig==SIGTRAP)return true;
                ptrace(PTRACE_CONT,p,nullptr,(void*)(uintptr_t)sig);continue;}
            if(WIFEXITED(st)||WIFSIGNALED(st))return false;}return false;};

    struct user_regs_struct orig_regs;
    if(ptrace(PTRACE_GETREGS,pid,nullptr,&orig_regs)!=0){
        ptrace(PTRACE_DETACH,pid,nullptr,nullptr);error_="Could not read registers";return false;}

    uintptr_t rip=orig_regs.rip;
    long orig_code[2];
    errno=0;orig_code[0]=ptrace(PTRACE_PEEKTEXT,pid,(void*)rip,nullptr);
    if(orig_code[0]==-1&&errno){ptrace(PTRACE_DETACH,pid,nullptr,nullptr);error_="PEEKTEXT failed";return false;}
    errno=0;orig_code[1]=ptrace(PTRACE_PEEKTEXT,pid,(void*)(rip+8),nullptr);
    if(orig_code[1]==-1&&errno){ptrace(PTRACE_DETACH,pid,nullptr,nullptr);error_="PEEKTEXT failed";return false;}

    auto restore_and_detach=[&](){
        ptrace(PTRACE_POKETEXT,pid,(void*)rip,(void*)orig_code[0]);
        ptrace(PTRACE_POKETEXT,pid,(void*)(rip+8),(void*)orig_code[1]);
        ptrace(PTRACE_SETREGS,pid,nullptr,&orig_regs);
        ptrace(PTRACE_DETACH,pid,nullptr,nullptr);};

    uint8_t sc_trap[]={0x0F,0x05,0xCC};
    long insn=orig_code[0];memcpy(&insn,sc_trap,3);
    ptrace(PTRACE_POKETEXT,pid,(void*)rip,(void*)insn);

    struct user_regs_struct mmap_regs=orig_regs;
    mmap_regs.rax=9;mmap_regs.rdi=0;mmap_regs.rsi=4096;
    mmap_regs.rdx=PROT_READ|PROT_WRITE|PROT_EXEC;
    mmap_regs.r10=MAP_PRIVATE|MAP_ANONYMOUS;mmap_regs.r8=(uintptr_t)-1;mmap_regs.r9=0;mmap_regs.rip=rip;
    ptrace(PTRACE_SETREGS,pid,nullptr,&mmap_regs);
    ptrace(PTRACE_CONT,pid,nullptr,nullptr);
    if(!wait_for_trap(pid)){restore_and_detach();error_="mmap did not complete";return false;}

    struct user_regs_struct result_regs;
    ptrace(PTRACE_GETREGS,pid,nullptr,&result_regs);
    uintptr_t mem_addr=result_regs.rax;
    if(mem_addr==0||(int64_t)mem_addr<0){restore_and_detach();error_="Remote mmap failed";return false;}

    size_t plen=lib_path.size()+1;
    for(size_t i=0;i<plen;i+=sizeof(long)){
        long word=0;memcpy(&word,lib_path.c_str()+i,std::min(sizeof(long),plen-i));
        ptrace(PTRACE_POKETEXT,pid,(void*)(mem_addr+256+i),(void*)word);}

    uint8_t shellcode[64]={};int so=0;
    uintptr_t sc_path=mem_addr+256;
    shellcode[so++]=0x48;shellcode[so++]=0xBF;memcpy(shellcode+so,&sc_path,8);so+=8;
    shellcode[so++]=0x48;shellcode[so++]=0xBE;memcpy(shellcode+so,&dlopen_flags,8);so+=8;
    shellcode[so++]=0x48;shellcode[so++]=0xB8;memcpy(shellcode+so,&dlopen_addr,8);so+=8;
    shellcode[so++]=0xFF;shellcode[so++]=0xD0;shellcode[so++]=0xCC;

    for(int i=0;i<so;i+=(int)sizeof(long)){
        long word=0;memcpy(&word,shellcode+i,std::min(sizeof(long),(size_t)(so-i)));
        ptrace(PTRACE_POKETEXT,pid,(void*)(mem_addr+(uintptr_t)i),(void*)word);}

    struct user_regs_struct sc_regs=orig_regs;
    sc_regs.rip=mem_addr;sc_regs.rsp=(sc_regs.rsp-256)&~0xFULL;
    ptrace(PTRACE_SETREGS,pid,nullptr,&sc_regs);
    ptrace(PTRACE_CONT,pid,nullptr,nullptr);
    if(!wait_for_trap(pid)){restore_and_detach();error_="Shellcode execution failed";return false;}

    ptrace(PTRACE_GETREGS,pid,nullptr,&result_regs);
    uintptr_t dlopen_result=result_regs.rax;

    struct user_regs_struct munmap_regs=orig_regs;
    munmap_regs.rax=11;munmap_regs.rdi=mem_addr;munmap_regs.rsi=4096;munmap_regs.rip=rip;
    ptrace(PTRACE_SETREGS,pid,nullptr,&munmap_regs);
    ptrace(PTRACE_CONT,pid,nullptr,nullptr);wait_for_trap(pid);
    restore_and_detach();

    if(dlopen_result==0){error_="dlopen returned NULL";return false;}
    payload_loaded_=true;return true;
}

bool Injection::inject_shellcode(pid_t pid, const std::string& lp, uintptr_t da, uint64_t df) {
    return inject_shellcode_ptrace(pid,lp,da,df);
}

bool Injection::inject_library(pid_t pid, const std::string& lib_path) {
    LOG_INFO("Injecting {} into PID {}",lib_path,pid);
    std::string target_path=prepare_payload_for_injection(pid,lib_path);
    uintptr_t dlopen_addr=0;bool libc_internal=false;
    uintptr_t libc_dlopen=find_libc_function(pid,"__libc_dlopen_mode");
    if(libc_dlopen){dlopen_addr=libc_dlopen;libc_internal=true;}
    if(!dlopen_addr)dlopen_addr=find_remote_symbol(pid,"dl","dlopen");
    if(!dlopen_addr)dlopen_addr=find_remote_symbol(pid,"c","dlopen");
    if(!dlopen_addr){error_="Cannot find dlopen";return false;}
    uint64_t flags=libc_internal?0x80000002ULL:0x00000002ULL;

    pid_t tracer=get_tracer_pid(pid);
    bool ptrace_ok=false;
    if(tracer<=0||tracer==getpid()){
        if(ptrace(PTRACE_ATTACH,pid,nullptr,nullptr)==0){ptrace_ok=true;
            int status;if(waitpid(pid,&status,0)==-1||!WIFSTOPPED(status)){
                ptrace(PTRACE_DETACH,pid,nullptr,nullptr);ptrace_ok=false;}}}

    if(ptrace_ok){
        if(inject_shellcode_ptrace(pid,target_path,dlopen_addr,flags)) return true;
        LOG_WARN("ptrace injection failed: {}",error_);}

    if(inject_via_procmem(pid,target_path,dlopen_addr,flags)) return true;
    if(error_.find("Inline hook")!=std::string::npos||error_.find("dlopen returned")!=std::string::npos) return false;
    return inject_via_inline_hook(pid,target_path,dlopen_addr,flags);
}

static bool extract_lock_internals(pid_t pid, uintptr_t lock_fn_addr,
                                    int32_t& global_offset_out,
                                    int32_t& mutex_offset_out,
                                    uintptr_t& pthread_lock_out) {
    uint8_t code[96];
    struct iovec li={code,sizeof(code)},ri={reinterpret_cast<void*>(lock_fn_addr),sizeof(code)};
    ssize_t rd=process_vm_readv(pid,&li,1,&ri,1,0);
    if(rd<20) return false;
    size_t code_len=(size_t)rd;

    size_t pos=0;
    if(pos+4<=code_len&&code[pos]==0xF3&&code[pos+1]==0x0F&&code[pos+2]==0x1E&&code[pos+3]==0xFA) pos+=4;
    if(pos<code_len&&code[pos]==0x55) pos++;
    if(pos+3<=code_len&&code[pos]==0x48&&code[pos+1]==0x89&&code[pos+2]==0xE5) pos+=3;
    while(pos<code_len&&(code[pos]==0x53||code[pos]==0x50||code[pos]==0x51||
          code[pos]==0x52||code[pos]==0x56||code[pos]==0x57)) pos++;
    if(pos+2<=code_len&&code[pos]==0x41&&code[pos+1]>=0x50&&code[pos+1]<=0x57) pos+=2;
    if(pos+4<=code_len&&code[pos]==0x48&&code[pos+1]==0x83&&code[pos+2]==0xEC) pos+=4;

    int gs_reg=7;int32_t gs_off=0,mx_off=0;
    bool found_global=false,found_mutex=false;uintptr_t call_target=0;

    for(int iter=0;iter<20&&pos+1<code_len;iter++){
        uint8_t b0=code[pos];bool has_rw=false;size_t rex_skip=0;
        if(b0>=0x48&&b0<=0x4F){has_rw=(b0&0x08)!=0;rex_skip=1;}

        if(!found_global&&has_rw&&pos+rex_skip+2<code_len){
            uint8_t op=code[pos+rex_skip],modrm=code[pos+rex_skip+1];
            uint8_t mod=(modrm>>6)&3,reg=(modrm>>3)&7,rm=modrm&7;
            if(op==0x8B&&rm==7&&mod!=3&&rm!=4){
                if(mod==1&&pos+rex_skip+3<=code_len){gs_off=(int8_t)code[pos+rex_skip+2];gs_reg=reg;if(b0&0x04)gs_reg+=8;found_global=true;pos+=rex_skip+3;continue;}
                if(mod==2&&pos+rex_skip+6<=code_len){memcpy(&gs_off,&code[pos+rex_skip+2],4);gs_reg=reg;if(b0&0x04)gs_reg+=8;found_global=true;pos+=rex_skip+6;continue;}
                if(mod==0){gs_off=0;gs_reg=reg;if(b0&0x04)gs_reg+=8;found_global=true;pos+=rex_skip+2;continue;}}}

        if(found_global&&!found_mutex&&has_rw&&pos+rex_skip+2<code_len){
            uint8_t op=code[pos+rex_skip],modrm=code[pos+rex_skip+1];
            uint8_t mod=(modrm>>6)&3,rm=modrm&7;int src_reg=rm;if(b0&0x01)src_reg+=8;
            if(op==0x8D&&src_reg==gs_reg&&mod!=3&&rm!=4){
                if(mod==1&&pos+rex_skip+3<=code_len){mx_off=(int8_t)code[pos+rex_skip+2];found_mutex=true;pos+=rex_skip+3;continue;}
                if(mod==2&&pos+rex_skip+6<=code_len){memcpy(&mx_off,&code[pos+rex_skip+2],4);found_mutex=true;pos+=rex_skip+6;continue;}}}

        if(found_global&&pos+5<=code_len&&(code[pos]==0xE8||code[pos]==0xE9)){
            int32_t disp;memcpy(&disp,&code[pos+1],4);
            call_target=lock_fn_addr+pos+5+(int64_t)disp;
            if(!found_mutex) mx_off=0;
            break;}

        size_t il=dh_insn_len(code+pos);if(il==0)break;pos+=il;
    }

    if(!found_global){
        pos=0;if(pos+4<=code_len&&code[pos]==0xF3&&code[pos+1]==0x0F&&code[pos+2]==0x1E&&code[pos+3]==0xFA)pos+=4;
        for(size_t scan=pos;scan+10<code_len;scan++){
            if(scan+4<=code_len&&code[scan]==0x48&&code[scan+1]==0x8B){
                uint8_t modrm=code[scan+2];uint8_t mod=(modrm>>6)&3,reg=(modrm>>3)&7,rm=modrm&7;
                if(rm!=7||rm==4||mod==3) continue;
                int32_t ov=0;size_t insn_len=0;
                if(mod==1&&scan+4<=code_len){ov=(int8_t)code[scan+3];insn_len=4;}
                else if(mod==2&&scan+7<=code_len){memcpy(&ov,&code[scan+3],4);insn_len=7;}
                else if(mod==0){ov=0;insn_len=3;}
                if(!insn_len) continue;
                size_t after=scan+insn_len;
                for(size_t j=after;j+5<=code_len&&j<after+30;j++){
                    if(code[j]==0xE8||code[j]==0xE9){
                        int32_t d;memcpy(&d,&code[j+1],4);
                        gs_off=ov;gs_reg=reg;found_global=true;mx_off=0;
                        call_target=lock_fn_addr+j+5+(int64_t)d;
                        for(size_t k=after;k<j;k++){
                            if(k+4<=code_len&&code[k]==0x48&&code[k+1]==0x83&&code[k+2]==0xC7)
                                {mx_off=(int8_t)code[k+3];found_mutex=true;}
                            else if(k+7<=code_len&&code[k]==0x48&&code[k+1]==0x81&&code[k+2]==0xC7)
                                {memcpy(&mx_off,&code[k+3],4);found_mutex=true;}}
                        goto done;}}}}}
done:
    if(found_global&&call_target){
        global_offset_out=gs_off;mutex_offset_out=mx_off;pthread_lock_out=call_target;return true;}
    return false;
}

bool Injection::find_remote_luau_functions(pid_t pid, DirectHookAddrs& out) {
    char exe_link[512];std::string exe_path;
    {std::string link="/proc/"+std::to_string(pid)+"/exe";
     ssize_t len=readlink(link.c_str(),exe_link,sizeof(exe_link)-1);
     if(len>0){exe_link[len]='\0';exe_path=exe_link;}}

    uintptr_t exe_base=0;
    {std::ifstream maps("/proc/"+std::to_string(pid)+"/maps");std::string line;
     while(std::getline(maps,line)){
         if(line.find(exe_path)==std::string::npos&&line.find("sober")==std::string::npos) continue;
         uintptr_t lo;unsigned long off;char perms[5]{};
         if(sscanf(line.c_str(),"%lx-%*x %4s %lx",&lo,perms,&off)==3&&off==0){exe_base=lo;break;}}}

    std::string real_path;
    {std::string ns="/proc/"+std::to_string(pid)+"/root"+exe_path;struct stat st;
     if(::stat(ns.c_str(),&st)==0)real_path=ns;
     else if(::stat(exe_path.c_str(),&st)==0)real_path=exe_path;}

    struct{const char* name;uintptr_t* dst;}syms[]={
        {"lua_resume",&out.resume},{"lua_newthread",&out.newthread},
        {"luau_load",&out.load},{"lua_settop",&out.settop},
        {"luaL_sandboxthread",&out.sandbox},{"luau_compile",&out.compile}};

    if(!real_path.empty()&&exe_base){
        uintptr_t first_vaddr=0;
        {FILE* f=fopen(real_path.c_str(),"rb");if(f){
            Elf64_Ehdr eh;if(fread(&eh,sizeof(eh),1,f)==1&&memcmp(eh.e_ident,ELFMAG,SELFMAG)==0)
                for(int i=0;i<eh.e_phnum;i++){Elf64_Phdr ph;
                    fseek(f,(long)(eh.e_phoff+i*eh.e_phentsize),SEEK_SET);
                    if(fread(&ph,sizeof(ph),1,f)!=1)break;
                    if(ph.p_type==PT_LOAD){first_vaddr=ph.p_vaddr;break;}}
            fclose(f);}}
        uintptr_t bias=exe_base-first_vaddr;
        for(auto& s:syms){uintptr_t a=find_elf_symbol_impl(real_path,s.name,bias,true);
            if(a){*s.dst=a;LOG_INFO("[direct-hook] ELF: {} at 0x{:X}",s.name,a);}}}

    for(auto& s:syms){if(*s.dst)continue;
        uintptr_t a=find_remote_symbol(pid,"c",s.name);
        if(!a)a=find_remote_symbol(pid,"dl",s.name);
        if(a){*s.dst=a;LOG_INFO("[direct-hook] dlsym: {} at 0x{:X}",s.name,a);}}

    if(out.resume&&out.load){int64_t d=(int64_t)out.resume-(int64_t)out.load;if(d<0)d=-d;
        if((uint64_t)d>0x2800000ULL){LOG_WARN("[direct-hook] luau_load too far from lua_resume, clearing");out.load=0;}}

    auto regions=memory_.get_regions();
    struct{const char* name;uintptr_t* dst;const char* strings[4];}fallbacks[]={
        {"lua_resume",&out.resume,{"cannot resume dead coroutine","cannot resume running coroutine",nullptr}},
        {"lua_newthread",&out.newthread,{"lua_newthread","too many C calls",nullptr}},
        {"luau_load",&out.load,{"bytecode version mismatch","truncated",nullptr}},
        {"lua_settop",&out.settop,{"stack overflow",nullptr}},
        {"luau_compile",&out.compile,{"CompileError","broken string",nullptr}}};

    for(auto& fb:fallbacks){if(*fb.dst)continue;
        std::vector<uintptr_t> excl;
        if(out.resume) excl.push_back(out.resume);
        if(out.settop) excl.push_back(out.settop);
                if(out.newthread) excl.push_back(out.newthread);
                if(out.load) excl.push_back(out.load);
        uintptr_t anchor=out.resume?out.resume:(out.settop?out.settop:0);
        uintptr_t found=find_func_by_stringref(pid,memory_,regions,fb.strings,anchor,excl);
        if(found){*fb.dst=found;LOG_INFO("[direct-hook] string-ref: {} at 0x{:X}",fb.name,found);}}

    if(!out.newthread){
        std::vector<uintptr_t> anchors;
        if(out.settop)anchors.push_back(out.settop);
        if(out.resume)anchors.push_back(out.resume);
        if(out.load)anchors.push_back(out.load);
        std::vector<uintptr_t> excl={out.resume,out.settop,out.load,out.sandbox};
        for(uintptr_t anchor:anchors){
            if(out.newthread) break;
            auto result=scan_funcs_near(pid,regions,anchor,0x80000000LL,excl,
                [&](pid_t p,uintptr_t addr,const uint8_t* code,size_t off,size_t scan_sz,uintptr_t)->int{
                    auto sig=analyze_func_sig(code,off,scan_sz,250,30);
                    if(sig.func_size<40||sig.func_size>200||sig.leas>0||sig.calls<2||sig.calls>6) return -1;
                    bool uses_rsi=false;
                    for(size_t bi=0;bi<20&&off+bi+3<scan_sz;bi++){
                        uint8_t b=code[off+bi];
                        if(b==0x89&&(code[off+bi+1]&0x38)==0x30)uses_rsi=true;
                        if((b==0x48||b==0x49)&&code[off+bi+1]==0x89&&(code[off+bi+2]&0x38)==0x30)uses_rsi=true;}
                    if(uses_rsi) return -1;
                    const uint8_t pro9[]={0x55,0x48,0x89,0xE5,0x53,0x50,0x48,0x89,0xFB};
                    size_t pp=off;if(pp+4<=scan_sz&&code[pp]==0xF3)pp+=4;
                    bool has_pro9=(pp+sizeof(pro9)<=scan_sz&&memcmp(&code[pp],pro9,sizeof(pro9))==0);
                    int score=0;
                    if(has_pro9) score+=20;
                    if(sig.has_tt9) score+=10;
                    if(sig.calls>=2&&sig.calls<=4)score+=3;
                    if(out.resume&&score>=5){int sh=shared_call_count(p,addr,out.resume,sig.func_size);if(sh>0)score+=5;}
                    return score;},20);
            if(result.addr&&result.score>=8){
                out.newthread=result.addr;
                LOG_INFO("[direct-hook] proximity: lua_newthread=0x{:X} (score={})",result.addr,result.score);}}}

    if(out.newthread&&!out.lock_fn){
        uint8_t ntb[128];struct iovec nl={ntb,sizeof(ntb)},nr={reinterpret_cast<void*>(out.newthread),sizeof(ntb)};
        ssize_t nrd=process_vm_readv(pid,&nl,1,&nr,1,0);
        if(nrd>=20){size_t fend=find_func_end(ntb,(size_t)nrd,25);if(!fend)fend=(size_t)nrd;
            for(size_t i=0;i<std::min(fend,(size_t)80);i++)
                if(ntb[i]==0xE8){int32_t d;memcpy(&d,&ntb[i+1],4);
                    out.lock_fn=out.newthread+i+5+(int64_t)d;
                    LOG_INFO("[direct-hook] lua_lock at 0x{:X}",out.lock_fn);break;}}}

    if(!out.free_fn){out.free_fn=find_remote_symbol(pid,"c","free");}

    if(out.settop){
        uint8_t stb[128];struct iovec sl={stb,sizeof(stb)},sr={reinterpret_cast<void*>(out.settop),sizeof(stb)};
        if(process_vm_readv(pid,&sl,1,&sr,1,0)>=24){
            auto sig=analyze_func_sig(stb,0,128,128,10);
            if(sig.saves_rdx&&!sig.saves_rsi){LOG_WARN("[direct-hook] lua_settop wrong sig, clearing");out.settop=0;}
            else if(!sig.saves_rsi){LOG_WARN("[direct-hook] lua_settop no rsi, clearing");out.settop=0;}}}

    if(!out.settop&&out.resume){
        std::vector<uintptr_t> excl={out.resume,out.newthread,out.load};
        auto result=scan_funcs_near(pid,regions,out.resume,0x80000000LL,excl,
            [&](pid_t p,uintptr_t addr,const uint8_t* code,size_t off,size_t scan_sz,uintptr_t)->int{
                auto sig=analyze_func_sig(code,off,scan_sz,250,20);
                if(!sig.saves_rdi||!sig.saves_rsi||sig.saves_rdx) return -1;
                if(sig.func_size<30||sig.func_size>250||sig.calls<1||sig.calls>8) return -1;
                int score=5;if(sig.calls<=4)score+=2;if(sig.leas==0)score+=1;
                if(out.resume){int sh=shared_call_count(p,addr,out.resume,sig.func_size);if(sh>0)score+=10;}
                return score;},15);
        if(result.addr&&result.score>=15){out.settop=result.addr;
            LOG_INFO("[direct-hook] proximity: lua_settop=0x{:X} (score={})",result.addr,result.score);}}

    if(!out.load&&out.resume){
        const char* load_needles[]={"bytecode version mismatch","truncated",nullptr};
        std::vector<uintptr_t> excl={out.resume,out.settop,out.newthread};
        uintptr_t found=find_func_by_stringref(pid,memory_,regions,load_needles,out.resume,excl);
        if(found){out.load=found;LOG_INFO("[direct-hook] proximity string-ref: luau_load at 0x{:X}",found);}

        if(!out.load){
            auto result=scan_funcs_near(pid,regions,out.resume,0x80000000LL,excl,
                [&](pid_t p,uintptr_t addr,const uint8_t* code,size_t off,size_t scan_sz,uintptr_t)->int{
                    auto sig=analyze_func_sig(code,off,scan_sz,2000,200);
                    if(!sig.saves_rdi||!sig.saves_rsi||!sig.saves_rdx) return -1;
                    if(sig.func_size<200||sig.calls<5) return -1;
                    int sh=shared_call_count(p,addr,out.resume,sig.func_size);
                    if(sh<2) return -1;
                    return sh*5+(sig.func_size>=500?3:0)+(sig.calls>=8?2:0);},12);
            if(result.addr&&result.score>=12){out.load=result.addr;
                LOG_INFO("[direct-hook] proximity sig: luau_load=0x{:X} (score={})",result.addr,result.score);}}}

    if(!out.lock_fn&&out.settop){
        uint8_t stb[128];struct iovec sl={stb,sizeof(stb)},sr={reinterpret_cast<void*>(out.settop),sizeof(stb)};
        if(process_vm_readv(pid,&sl,1,&sr,1,0)>=20){
            size_t fend=find_func_end(stb,128,20);if(!fend)fend=80;
            for(size_t i=0;i<std::min(fend,(size_t)80);i++)
                if(stb[i]==0xE8){int32_t d;memcpy(&d,&stb[i+1],4);
                    out.lock_fn=out.settop+i+5+(int64_t)d;
                    LOG_INFO("[direct-hook] lua_lock from settop at 0x{:X}",out.lock_fn);break;}}}

    uintptr_t active_lock=out.lock_fn;

    if(active_lock&&out.newthread){
        uint8_t nt_pre[128];struct iovec sp_l={nt_pre,sizeof(nt_pre)},sp_r={reinterpret_cast<void*>(out.newthread),sizeof(nt_pre)};
        ssize_t sp_rd=process_vm_readv(pid,&sp_l,1,&sp_r,1,0);
        if(sp_rd>=40){
            size_t lock_pos=0;
            for(size_t i=0;i+5<=(size_t)sp_rd;i++)
                if(nt_pre[i]==0xE8){int32_t d;memcpy(&d,&nt_pre[i+1],4);
                    if(out.newthread+i+5+(int64_t)d==active_lock){lock_pos=i;break;}}
            if(lock_pos>5){
                for(size_t s=lock_pos;s>=3;s--){
                    if(nt_pre[s]!=0x48) {if(s==0)break; continue;}
                    if(nt_pre[s+1]==0x89&&nt_pre[s+2]==0xDF){out.lua_state_to_lock_arg=-1;break;}
                    if(nt_pre[s+1]==0x8B&&nt_pre[s+2]==0x3B){out.lua_state_to_lock_arg=0;break;}
                    if(nt_pre[s+1]==0x8B&&nt_pre[s+2]==0x7B&&s+4<=lock_pos)
                        {out.lua_state_to_lock_arg=(int8_t)nt_pre[s+3];break;}
                    if(nt_pre[s+1]==0x8B&&nt_pre[s+2]==0xBB&&s+7<=lock_pos)
                        {memcpy(&out.lua_state_to_lock_arg,&nt_pre[s+3],4);break;}
                    if(nt_pre[s+1]==0x8B&&nt_pre[s+2]==0x3F){out.lua_state_to_lock_arg=0;break;}
                    if(nt_pre[s+1]==0x8B&&nt_pre[s+2]==0x7F&&s+4<=lock_pos)
                        {out.lua_state_to_lock_arg=(int8_t)nt_pre[s+3];break;}
                    if(nt_pre[s+1]==0x8B&&nt_pre[s+2]==0xBF&&s+7<=lock_pos)
                        {memcpy(&out.lua_state_to_lock_arg,&nt_pre[s+3],4);break;}
                    if(s==0) break;}}}}

    if(active_lock&&!out.unlock_fn){
        uint8_t al_body[32];struct iovec ab_l={al_body,sizeof(al_body)},ab_r={reinterpret_cast<void*>(active_lock),sizeof(al_body)};
        ssize_t ab_rd=process_vm_readv(pid,&ab_l,1,&ab_r,1,0);
        uintptr_t inner_lock=0;
        if(ab_rd>=15){for(size_t i=0;i+5<=(size_t)ab_rd;i++)
            if(al_body[i]==0xE8||al_body[i]==0xE9){int32_t d;memcpy(&d,&al_body[i+1],4);
                inner_lock=active_lock+i+5+(int64_t)d;break;}}
        if(inner_lock){
            uintptr_t scan_lo=(active_lock>0x1000)?active_lock-0x1000:0,scan_hi=active_lock+0x1000;
            size_t scan_sz=scan_hi-scan_lo;
            std::vector<uint8_t> rbuf(scan_sz);
            struct iovec rl={rbuf.data(),scan_sz},rr={reinterpret_cast<void*>(scan_lo),scan_sz};
            if(process_vm_readv(pid,&rl,1,&rr,1,0)==(ssize_t)scan_sz){
                int64_t best_dist=INT64_MAX;uintptr_t best_ul=0;
                for(size_t off=1;off+20<scan_sz;off++){
                    uintptr_t cand=scan_lo+off;if(cand==active_lock||!at_func_boundary(rbuf[off-1]))continue;
                    for(size_t j=0;j<20&&off+j+5<scan_sz;j++){
                        if(rbuf[off+j]!=0xE8&&rbuf[off+j]!=0xE9)continue;
                        int32_t d;memcpy(&d,&rbuf[off+j+1],4);
                        uintptr_t target=scan_lo+off+j+5+(int64_t)d;
                        if(target==inner_lock)break;
                        int64_t td=(int64_t)target-(int64_t)inner_lock;if(td<0)td=-td;
                        if(td>0x100000)break;
                        int64_t cd=(int64_t)cand-(int64_t)active_lock;if(cd<0)cd=-cd;
                        if(cd<best_dist){best_dist=cd;best_ul=cand;}break;}}
                if(best_ul){out.unlock_fn=best_ul;LOG_INFO("[direct-hook] active_unlock at 0x{:X}",best_ul);}}}}

    if(active_lock&&!out.unlock_fn){
        int32_t gs_off=0,mx_off=0;uintptr_t pml_addr=0;
        bool internals_ok=extract_lock_internals(pid,active_lock,gs_off,mx_off,pml_addr);

        if(!internals_ok){
            uint8_t lk[48];struct iovec lkl={lk,sizeof(lk)},lkr={reinterpret_cast<void*>(active_lock),sizeof(lk)};
            ssize_t lkrd=process_vm_readv(pid,&lkl,1,&lkr,1,0);
            if(lkrd>=20){for(size_t i=0;i+7<(size_t)lkrd;i++){
                if(lk[i]!=0x48&&lk[i]!=0x4C)continue;
                if(lk[i+1]!=0x8B) continue;
                uint8_t modrm=lk[i+2];
                uint8_t mod=(modrm>>6)&3,rm=modrm&7;
                if(rm!=7||mod==3||rm==4)continue;
                int32_t dv=0;size_t ie=0;
                if(mod==1&&i+4<=(size_t)lkrd){dv=(int8_t)lk[i+3];ie=i+4;}
                else if(mod==2&&i+7<=(size_t)lkrd){memcpy(&dv,&lk[i+3],4);ie=i+7;}
                else if(mod==0){dv=0;ie=i+3;}
                if(!ie)continue;
                for(size_t j=ie;j+5<=(size_t)lkrd&&j<ie+25;j++){
                    if(lk[j]==0xE8||lk[j]==0xE9){int32_t cd;memcpy(&cd,&lk[j+1],4);
                        gs_off=dv;mx_off=0;pml_addr=active_lock+j+5+(int64_t)cd;internals_ok=true;goto brute_done;}}}}
            brute_done:;}

        if(internals_ok){
            out.lock_global_state_offset=gs_off;out.lock_mutex_offset=mx_off;
            out.pthread_mutex_lock_addr=pml_addr;

            uintptr_t pmu=0;
            uintptr_t pml_sym=find_remote_symbol(pid,"c","pthread_mutex_lock");
            uintptr_t pmu_sym=find_remote_symbol(pid,"c","pthread_mutex_unlock");
            if(pml_sym&&pmu_sym&&pml_addr){
                int64_t delta=(int64_t)pml_addr-(int64_t)pml_sym;
                if(delta>=-0x100000LL&&delta<=0x100000LL) pmu=pmu_sym+delta;}
            if(!pmu&&pmu_sym) pmu=pmu_sym;

            if(!pmu&&pml_addr){
                for(int64_t try_off:{0x10,0x20,0x30,0x40,0x50,0x60,0x80,0xA0,0xC0,0x100,0x200,0x400,
                    -0x10,-0x20,-0x30,-0x40,-0x60,-0x80,-0xC0,-0x100,-0x200}){
                    uint8_t ch[4];struct iovec cl={ch,4},cr={reinterpret_cast<void*>(pml_addr+try_off),4};
                    if(process_vm_readv(pid,&cl,1,&cr,1,0)!=4)continue;
                    if(ch[0]==0xF3||(ch[0]==0x55)||(ch[0]==0x48&&ch[1]==0x83)||ch[0]==0x31||ch[0]==0xB8)
                        {pmu=pml_addr+try_off;break;}}}

            if(pmu){out.pthread_mutex_unlock_addr=pmu;out.lock_internals_valid=true;
                LOG_INFO("[direct-hook] pthread_mutex_unlock=0x{:X}",pmu);}}}

    if(out.settop&&active_lock&&!out.unlock_fn){
        uint8_t stbuf[256];struct iovec ul_l={stbuf,sizeof(stbuf)},ul_r={reinterpret_cast<void*>(out.settop),sizeof(stbuf)};
        ssize_t ul_rd=process_vm_readv(pid,&ul_l,1,&ul_r,1,0);
        if(ul_rd>=40){size_t fend=find_func_end(stbuf,(size_t)ul_rd);
            if(fend>10){uintptr_t last=last_call_in_func(stbuf,fend,out.settop,active_lock);
                if(last){out.unlock_fn=last;LOG_INFO("[direct-hook] lua_unlock at 0x{:X}",last);}}}}

    if(!out.resume||!out.load||!out.settop){
        LOG_ERROR("[direct-hook] missing required: resume={:#x} load={:#x} settop={:#x}",out.resume,out.load,out.settop);
        return false;}
    if(!out.newthread){LOG_ERROR("[direct-hook] lua_newthread not found");return false;}
    return true;
}

template<typename AddrsType>
static std::vector<uint8_t> gen_entry_trampoline(
    const AddrsType& a, uintptr_t mailbox_addr, uintptr_t cave_addr,
    uintptr_t hook_target, const uint8_t* stolen, size_t stolen_len,
    bool capture_rdi_to_mailbox, bool hook_held_lock, bool hook_target_is_settop)
{
    std::vector<uint8_t> c; c.reserve(640);
    auto e=[&](std::initializer_list<uint8_t> b){c.insert(c.end(),b);};
    auto e8=[&](uint8_t v){c.push_back(v);};
    auto e32=[&](uint32_t v){for(int i=0;i<4;i++)c.push_back((v>>(i*8))&0xFF);};
    auto e64=[&](uint64_t v){for(int i=0;i<8;i++)c.push_back((v>>(i*8))&0xFF);};

    auto emit_unlock=[&](){
        if(a.unlock_fn&&a.lua_state_to_lock_arg>=0){
            e({0x4C,0x89,0xFF});
            if(a.lua_state_to_lock_arg==0){e({0x48,0x8B,0x3F});}
            else if(a.lua_state_to_lock_arg>=-128&&a.lua_state_to_lock_arg<128)
                {e({0x48,0x8B,0x7F});e8((uint8_t)(int8_t)a.lua_state_to_lock_arg);}
            else{e({0x48,0x8B,0xBF});e32((uint32_t)a.lua_state_to_lock_arg);}
            e({0x48,0xB8});e64(a.unlock_fn);e({0xFF,0xD0});
        }else if(a.unlock_fn){e({0x4C,0x89,0xFF});e({0x48,0xB8});e64(a.unlock_fn);e({0xFF,0xD0});}
        else if(a.lock_internals_valid&&a.pthread_mutex_unlock_addr){
            e({0x4C,0x89,0xFF});
            if(a.lua_state_to_lock_arg>=0){
                if(a.lua_state_to_lock_arg==0){e({0x48,0x8B,0x3F});}
                else if(a.lua_state_to_lock_arg>=-128&&a.lua_state_to_lock_arg<128)
                    {e({0x48,0x8B,0x7F});e8((uint8_t)(int8_t)a.lua_state_to_lock_arg);}
                else{e({0x48,0x8B,0xBF});e32((uint32_t)a.lua_state_to_lock_arg);}}
            if(a.lock_global_state_offset!=0){
                if(a.lock_global_state_offset>=-128&&a.lock_global_state_offset<128)
                    {e({0x48,0x8B,0x7F});e8((uint8_t)(int8_t)a.lock_global_state_offset);}
                else{e({0x48,0x8B,0xBF});e32((uint32_t)a.lock_global_state_offset);}}
            if(a.lock_mutex_offset!=0){
                if(a.lock_mutex_offset>=-128&&a.lock_mutex_offset<128)
                    {e({0x48,0x83,0xC7});e8((uint8_t)(int8_t)a.lock_mutex_offset);}
                else{e({0x48,0x81,0xC7});e32((uint32_t)a.lock_mutex_offset);}}
            e({0x48,0xB8});e64(a.pthread_mutex_unlock_addr);e({0xFF,0xD0});}};

    auto emit_lock=[&](){
        if(a.lock_fn&&a.lua_state_to_lock_arg>=0){
            e({0x4C,0x89,0xFF});
            if(a.lua_state_to_lock_arg==0){e({0x48,0x8B,0x3F});}
            else if(a.lua_state_to_lock_arg>=-128&&a.lua_state_to_lock_arg<128)
                {e({0x48,0x8B,0x7F});e8((uint8_t)(int8_t)a.lua_state_to_lock_arg);}
            else{e({0x48,0x8B,0xBF});e32((uint32_t)a.lua_state_to_lock_arg);}
            e({0x48,0xB8});e64(a.lock_fn);e({0xFF,0xD0});
        }else if(a.lock_fn){e({0x4C,0x89,0xFF});e({0x48,0xB8});e64(a.lock_fn);e({0xFF,0xD0});}};

    e8(0x9C);e8(0x50);e8(0x51);e8(0x52);e8(0x56);e8(0x57);
    e({0x41,0x50});e({0x41,0x51});e({0x41,0x52});e({0x41,0x53});
    e8(0x53);e({0x41,0x56});e({0x41,0x57});e8(0x55);
    e({0x48,0x89,0xE5});e({0x48,0x83,0xE4,0xF0});

    e({0x48,0xBB});e64(mailbox_addr);
    if(capture_rdi_to_mailbox) e({0x48,0x89,0x7B,0x30});
    e({0x66,0xFF,0x43,0x2A});

    e({0x80,0x7B,0x28,0x00});
    size_t j_guard=c.size(); e({0x0F,0x85});e32(0);
    e({0x48,0x8B,0x43,0x10});e({0x48,0x3B,0x43,0x18});
    size_t j_seq=c.size(); e({0x0F,0x86});e32(0);
    e({0xC6,0x43,0x28,0x01});
    e({0x49,0x89,0xFF});

    if(hook_held_lock) emit_unlock();

    size_t j_nt_fail=SIZE_MAX;
    if(a.newthread){
        e({0xC7,0x43,0x2C,0x01,0x00,0x00,0x00});
        e({0x4C,0x89,0xFF});e({0x48,0xB8});e64(a.newthread);e({0xFF,0xD0});
        e({0x49,0x89,0xC6});e({0x4D,0x85,0xF6});
        j_nt_fail=c.size();e({0x0F,0x84});e32(0);
    }else{e({0xC7,0x43,0x2C,0x01,0x00,0x00,0x00});e({0x4D,0x89,0xFE});}

    e({0xC7,0x43,0x2C,0x02,0x00,0x00,0x00});
    e({0x4C,0x89,0xF7});
    size_t chunk_movabs=c.size();e({0x48,0xBE});e64(0);
    e({0x48,0x8D,0x53,0x40});e({0x8B,0x4B,0x20});e({0x45,0x31,0xC0});
    e({0x48,0xB8});e64(a.load);e({0xFF,0xD0});
    e({0x85,0xC0});
    size_t j_load_fail=c.size();e({0x0F,0x85});e32(0);

    e({0xC7,0x43,0x2C,0x03,0x00,0x00,0x00});
    e({0x4C,0x89,0xF7});e({0x31,0xF6});e({0x31,0xD2});
    e({0x48,0xB8});e64(a.resume);e({0xFF,0xD0});
    e({0x89,0x43,0x38});

    size_t settop_label=c.size();

    if(hook_held_lock) emit_lock();

    size_t ack_label=c.size();
    e({0x48,0x8B,0x43,0x10});e({0x48,0x89,0x43,0x18});
    e({0xC7,0x43,0x2C,0x05,0x00,0x00,0x00});
    e({0xC6,0x43,0x28,0x00});

    size_t skip_label=c.size();
    auto patch_j=[&](size_t off,size_t target){int32_t r=(int32_t)(target-(off+4));memcpy(&c[off],&r,4);};
    patch_j(j_guard+2,skip_label);
    patch_j(j_seq+2,skip_label);
    if(j_nt_fail!=SIZE_MAX) patch_j(j_nt_fail+2,ack_label);
    patch_j(j_load_fail+2,settop_label);

    e({0x48,0x89,0xEC});e8(0x5D);
    e({0x41,0x5F});e({0x41,0x5E});e8(0x5B);
    e({0x41,0x5B});e({0x41,0x5A});e({0x41,0x59});e({0x41,0x58});
    e8(0x5F);e8(0x5E);e8(0x5A);e8(0x59);e8(0x58);e8(0x9D);

    for(size_t i=0;i<stolen_len;i++) e8(stolen[i]);

    uintptr_t cont=hook_target+stolen_len;
    int64_t jd=(int64_t)cont-(int64_t)(cave_addr+c.size()+5);
    if(jd>=INT32_MIN&&jd<=INT32_MAX){e8(0xE9);e32((uint32_t)(int32_t)jd);}
    else{e({0xFF,0x25,0x00,0x00,0x00,0x00});e64(cont);}

    size_t chunk_label=c.size();
    e({0x3D,0x6F,0x73,0x73,0x00});
    uintptr_t chunk_abs=cave_addr+chunk_label;
    memcpy(&c[chunk_movabs+2],&chunk_abs,8);

    e8(0xC3);

    (void)hook_target_is_settop;
    return c;
}

static bool do_dryrun(pid_t pid, uintptr_t mb_addr, int timeout_iters=100) {
    size_t bc_len=0;char* bc=luau_compile("return",6,nullptr,&bc_len);
    if(!bc||bc_len==0||(uint8_t)bc[0]==0||bc_len>16320){free(bc);return true;}
    uint64_t seq=0,ack=0;
    struct iovec sl,sr;
    sl={&seq,8};sr={reinterpret_cast<void*>(mb_addr+16),8};process_vm_readv(pid,&sl,1,&sr,1,0);
    sl={&ack,8};sr={reinterpret_cast<void*>(mb_addr+24),8};process_vm_readv(pid,&sl,1,&sr,1,0);
    if(seq>ack){free(bc);return true;}
    std::string path="/proc/"+std::to_string(pid)+"/mem";
    int fd=open(path.c_str(),O_RDWR);
    auto pw=[&](uintptr_t a,const void* d,size_t l){
        if(fd>=0){(void)!pwrite(fd,d,l,(off_t)a);return;}
        struct iovec wl={const_cast<void*>(d),l},wr={reinterpret_cast<void*>(a),l};
        process_vm_writev(pid,&wl,1,&wr,1,0);};
    pw(mb_addr+64,bc,bc_len);
    uint32_t tsz=(uint32_t)bc_len,tfl=1,z32=0;uint8_t z8=0;uint16_t z16=0;
    pw(mb_addr+32,&tsz,4);pw(mb_addr+36,&tfl,4);
    pw(mb_addr+44,&z32,4);pw(mb_addr+40,&z8,1);pw(mb_addr+42,&z16,2);
    uint64_t arm=seq+1;pw(mb_addr+16,&arm,8);
    free(bc);
    bool pass=false;
    for(int i=0;i<timeout_iters;i++){
        usleep(50000);if(kill(pid,0)!=0)break;
        uint64_t da=0;
        struct iovec al={&da,8},ar={reinterpret_cast<void*>(mb_addr+24),8};
        process_vm_readv(pid,&al,1,&ar,1,0);
        if(da>=arm){pass=true;break;}
        if(i>=39){uint32_t ds=0;uint8_t dg=0;
            struct iovec dsl={&ds,4},dsr={reinterpret_cast<void*>(mb_addr+44),4};
            process_vm_readv(pid,&dsl,1,&dsr,1,0);
            struct iovec dgl={&dg,1},dgr={reinterpret_cast<void*>(mb_addr+40),1};
            process_vm_readv(pid,&dgl,1,&dgr,1,0);
            if(ds<=1&&dg==1){LOG_ERROR("[direct-hook] dry-run deadlock at step {}",ds);break;}}}
    if(fd>=0) close(fd);
    return pass;
}

bool Injection::inject_via_direct_hook(pid_t pid) {
    if(dhook_.active) return true;
    LOG_INFO("[direct-hook] starting for PID {}",pid);

    DirectHookAddrs addrs;
    if(!find_remote_luau_functions(pid,addrs)){LOG_ERROR("[direct-hook] failed to find Luau functions");return false;}

    auto regions=memory_.get_regions();

    uintptr_t mb_addr=0;
    {constexpr size_t MB_SIZE=16384;
     for(auto it=regions.rbegin();it!=regions.rend();++it){
         auto& r=*it;if(!r.writable()||!r.readable()||r.size()<MB_SIZE+4096) continue;
         if(r.path.find("[stack")!=std::string::npos||r.path.find("[vvar")!=std::string::npos||
            r.path.find("[vdso")!=std::string::npos||r.path.find("heap")!=std::string::npos) continue;
         if(!r.path.empty()&&r.path[0]=='/') continue;
         uintptr_t cs=r.end-MB_SIZE-4096;cs&=~(uintptr_t)0xFFF;if(cs<r.start)continue;
         std::vector<uint8_t> probe(MB_SIZE);
         if(!proc_mem_read(pid,cs,probe.data(),MB_SIZE))continue;
         bool ok=true;for(auto b:probe)if(b!=0){ok=false;break;}
         if(ok){mb_addr=cs;break;}}}
    if(!mb_addr){LOG_ERROR("[direct-hook] no mailbox memory");return false;}

    DirectMailbox mb{};memcpy(mb.magic,"OSS_DMBOX_V3\0\0\0\0",16);
    if(!proc_mem_write(pid,mb_addr,&mb,sizeof(mb))){LOG_ERROR("[direct-hook] mailbox write failed");return false;}

    if(!addrs.settop){LOG_ERROR("[direct-hook] lua_settop not found");return false;}

    uint8_t prologue[32];
    if(!proc_mem_read(pid,addrs.settop,prologue,sizeof(prologue))){LOG_ERROR("[direct-hook] cannot read prologue");return false;}
    size_t steal=0;
    while(steal<5){size_t il=dh_insn_len(prologue+steal);if(il==0||steal+il>sizeof(prologue)){
        LOG_ERROR("[direct-hook] decode failed");return false;}steal+=il;}

    std::vector<MemoryRegion> nearby;
    for(const auto& r:regions){int64_t d=(int64_t)r.start-(int64_t)addrs.settop;
        if(d>INT32_MIN&&d<INT32_MAX){nearby.push_back(r);continue;}
        d=(int64_t)r.end-(int64_t)addrs.settop;if(d>INT32_MIN&&d<INT32_MAX)nearby.push_back(r);}

    constexpr size_t CAVE_SIZE=640;
    ExeRegionInfo cave;
    if(!find_code_cave(pid,nearby,CAVE_SIZE,cave)){LOG_ERROR("[direct-hook] no code cave");return false;}

    uintptr_t hook_addr=addrs.settop;
    bool hook_needs_unlock=false;
    uint8_t patch[16]={};size_t patch_len=0;

    auto try_hook=[&](uintptr_t target,const char* name,uint8_t* pro,size_t st,bool held_lock)->bool{
        auto t=gen_entry_trampoline(addrs,mb_addr,cave.padding_start,target,pro,st,true,held_lock,target!=addrs.resume);
        if(t.size()>CAVE_SIZE||!proc_mem_write(pid,cave.padding_start,t.data(),t.size())) return false;
        uint8_t p[16];size_t pl;
        if(!install_jump_patch(p,pl,target,cave.padding_start,st)) return false;
        if(!proc_mem_write(pid,target,p,pl)) return false;
        uint8_t vf[16]={};proc_mem_read(pid,target,vf,pl);
        if(memcmp(vf,p,pl)!=0){LOG_ERROR("[direct-hook] patch didn't persist");return false;}
        uint16_t zh=0;proc_mem_write(pid,mb_addr+42,&zh,2);
        usleep(1000000);uint16_t hits=0;proc_mem_read(pid,mb_addr+42,&hits,2);
        if(hits<10){LOG_WARN("[direct-hook] {} only {} hits — dead",name,hits);
            proc_mem_write(pid,target,pro,st);return false;}
        LOG_INFO("[direct-hook] {} probe: {} hits — LIVE!",name,hits);
        memcpy(patch,p,pl);patch_len=pl;return true;};

    if(!try_hook(addrs.settop,"lua_settop",prologue,steal,false)){
        LOG_WARN("[direct-hook] lua_settop dead, searching for live variant...");
        uintptr_t dead_settop=addrs.settop;
        bool found_live=false;int total_probes=0;constexpr int MAX_PROBES=15;

        for(const auto& r:regions){
            if(found_live||total_probes>=MAX_PROBES) break;
            if(!r.readable()||!r.executable()||r.size()<256) continue;
            int64_t rd=(int64_t)r.start-(int64_t)addrs.resume;
            if(rd<-0x800000LL||rd>0x800000LL) continue;
            size_t scan_sz=std::min(r.size(),(size_t)0x800000);
            std::vector<uint8_t> code(scan_sz);
            struct iovec sli={code.data(),scan_sz},sri={reinterpret_cast<void*>(r.start),scan_sz};
            if(process_vm_readv(pid,&sli,1,&sri,1,0)!=(ssize_t)scan_sz) continue;

            for(size_t off=1;off+260<scan_sz&&!found_live;off++){
                if(!at_func_boundary(code[off-1])) continue;
                uintptr_t cand=r.start+off;
                if(cand==addrs.resume||cand==addrs.newthread||cand==addrs.load||
                   cand==addrs.lock_fn||cand==dead_settop) continue;
                int64_t dd=(int64_t)cand-(int64_t)dead_settop;
                if(dd>-0x1000LL&&dd<0x1000LL) continue;
                if(!has_prologue(code.data()+off,scan_sz-off)) continue;

                auto sig=analyze_func_sig(code.data(),off,scan_sz,250,20);
                if(!sig.saves_rdi||!sig.saves_rsi||sig.saves_rdx) continue;
                if(sig.func_size<30||sig.func_size>250||sig.calls<1||sig.calls>8) continue;

                bool has_alock=false;
                for(size_t fi=0;fi<60&&off+fi+5<=scan_sz;fi++){
                    if(code[off+fi]!=0xE8) continue;
                    int32_t cd; memcpy(&cd,&code[off+fi+1],4);
                    uintptr_t ct=r.start+off+fi+5+(int64_t)cd;
                    if(ct==addrs.lock_fn){has_alock=true;break;}
                    if(first_call_reaches(pid,ct,addrs.lock_fn,20)){has_alock=true;break;}break;}
                if(!has_alock) continue;

                total_probes++;
                uint8_t cand_pro[32];
                if(!proc_mem_read(pid,cand,cand_pro,sizeof(cand_pro))) continue;
                size_t cand_steal=0;
                while(cand_steal<5){size_t il=dh_insn_len(cand_pro+cand_steal);
                    if(il==0||cand_steal+il>sizeof(cand_pro)) break;
                    cand_steal+=il;}
                if(cand_steal<5) continue;

                if(!addrs.unlock_fn){
                    uint8_t ls_buf[256];struct iovec ls_l={ls_buf,sizeof(ls_buf)},
                        ls_r={reinterpret_cast<void*>(cand),sizeof(ls_buf)};
                    ssize_t ls_rd=process_vm_readv(pid,&ls_l,1,&ls_r,1,0);
                    if(ls_rd>=30){size_t fend=find_func_end(ls_buf,(size_t)ls_rd);
                        if(fend>10){uintptr_t ul=last_call_in_func(ls_buf,fend,cand,addrs.lock_fn);
                            if(ul)addrs.unlock_fn=ul;}}}

                hook_needs_unlock=true;
                memcpy(prologue,cand_pro,cand_steal);steal=cand_steal;
                hook_addr=cand;

                if(try_hook(cand,"live_settop",cand_pro,cand_steal,true)){found_live=true;break;}
                else{hook_addr=addrs.settop;memcpy(prologue,cand_pro,steal);}
            }}

        if(!found_live&&addrs.resume){
            LOG_INFO("[direct-hook] trying lua_resume as fallback hook target");
            uint8_t rpro[32];
            if(proc_mem_read(pid,addrs.resume,rpro,sizeof(rpro))){
                size_t rsteal=0;while(rsteal<5){size_t il=dh_insn_len(rpro+rsteal);
                    if(il==0||rsteal+il>sizeof(rpro)) break;
                    rsteal+=il;}
                if(rsteal>=5&&try_hook(addrs.resume,"lua_resume",rpro,rsteal,true)){
                    hook_addr=addrs.resume;memcpy(prologue,rpro,rsteal);steal=rsteal;
                    hook_needs_unlock=true;found_live=true;}}}

        if(!found_live){LOG_ERROR("[direct-hook] all hook targets exhausted");return false;}
    }

    if(hook_needs_unlock&&!addrs.unlock_fn&&addrs.lock_internals_valid&&addrs.pthread_mutex_unlock_addr){
        if(addrs.pthread_mutex_lock_addr){
            int64_t lu=(int64_t)addrs.pthread_mutex_lock_addr-(int64_t)addrs.pthread_mutex_unlock_addr;
            if(lu<0) lu=-lu;
            if((uint64_t)lu>0x100000ULL){
                LOG_WARN("[direct-hook] lock/unlock incompatible, disabling bracket");hook_needs_unlock=false;}}}

    bool effective_held_lock=hook_needs_unlock;
    {auto t_final=gen_entry_trampoline(addrs,mb_addr,cave.padding_start,hook_addr,prologue,steal,
                                        false,effective_held_lock,hook_addr!=addrs.resume);
     if(!proc_mem_write(pid,cave.padding_start,t_final.data(),t_final.size())){
         proc_mem_write(pid,hook_addr,prologue,steal);return false;}}

    dhook_.cave_addr=cave.padding_start;dhook_.mailbox_addr=mb_addr;dhook_.cave_size=CAVE_SIZE;
    dhook_.stolen_len=steal;dhook_.resume_addr=addrs.resume;dhook_.newthread_addr=addrs.newthread;
    dhook_.load_addr=addrs.load;dhook_.settop_addr=hook_addr;
    memcpy(dhook_.stolen_bytes,prologue,steal);memcpy(dhook_.orig_patch,prologue,patch_len);
    dhook_.patch_len=patch_len;dhook_.active=true;dhook_.has_compile=(addrs.compile!=0);
    {auto tm=gen_entry_trampoline(addrs,mb_addr,cave.padding_start,hook_addr,prologue,steal,false,effective_held_lock,hook_addr!=addrs.resume);
     dhook_.nop_stub_addr=cave.padding_start+tm.size()-1;}

    LOG_INFO("[direct-hook] HOOK ARMED at 0x{:X}, cave=0x{:X}, mailbox=0x{:X}",hook_addr,cave.padding_start,mb_addr);

    if(!do_dryrun(pid,mb_addr)){
        proc_mem_write(pid,hook_addr,prologue,steal);
        DirectMailbox empty{};proc_mem_write(pid,mb_addr,&empty,sizeof(empty));
        dhook_={};

        if(hook_addr!=addrs.resume&&addrs.resume){
            LOG_INFO("[direct-hook] retrying with lua_resume...");
            uint8_t rpro[32];
            if(proc_mem_read(pid,addrs.resume,rpro,sizeof(rpro))){
                size_t rs=0;while(rs<5){size_t il=dh_insn_len(rpro+rs);if(il==0||rs+il>sizeof(rpro))break;rs+=il;}
                if(rs>=5){
                    DirectMailbox mb2{};memcpy(mb2.magic,"OSS_DMBOX_V3\0\0\0\0",16);
                    proc_mem_write(pid,mb_addr,&mb2,sizeof(mb2));
                    auto rt=gen_entry_trampoline(addrs,mb_addr,cave.padding_start,addrs.resume,rpro,rs,false,true,false);
                    if(rt.size()<=CAVE_SIZE&&proc_mem_write(pid,cave.padding_start,rt.data(),rt.size())){
                        uint8_t rp[16];size_t rpl=0;
                        if(install_jump_patch(rp,rpl,addrs.resume,cave.padding_start,rs)&&
                           proc_mem_write(pid,addrs.resume,rp,rpl)){
                            if(do_dryrun(pid,mb_addr,100)){
                                dhook_.cave_addr=cave.padding_start;dhook_.mailbox_addr=mb_addr;
                                dhook_.cave_size=CAVE_SIZE;dhook_.stolen_len=rs;
                                dhook_.resume_addr=addrs.resume;dhook_.newthread_addr=addrs.newthread;
                                dhook_.load_addr=addrs.load;dhook_.settop_addr=addrs.resume;
                                memcpy(dhook_.stolen_bytes,rpro,rs);memcpy(dhook_.orig_patch,rpro,rpl);
                                dhook_.patch_len=rpl;dhook_.active=true;
                                dhook_.nop_stub_addr=cave.padding_start+rt.size()-1;
                                set_state(InjectionState::Ready,"Direct hook active \u2014 ready for scripts");
                                return true;
                            }
                            proc_mem_write(pid,addrs.resume,rpro,rs);
                        }
                    }
                }
            }
        }
        error_="Direct hook dry-run failed";set_state(InjectionState::Failed,error_);return false;
    }

    set_state(InjectionState::Ready,"Direct hook active \u2014 ready for scripts");return true;
}

void Injection::cleanup_direct_hook() {
    if(!dhook_.active) return;
    pid_t pid=memory_.get_pid();
    if(pid>0&&kill(pid,0)==0){
        uintptr_t ha=dhook_.settop_addr;
        if(!ha){if(dhook_.hook_is_lock_fn&&dhook_.active_lock_addr)ha=dhook_.active_lock_addr;
                else if(dhook_.resume_addr)ha=dhook_.resume_addr;}
        if(ha&&dhook_.stolen_len>0) proc_mem_write(pid,ha,dhook_.stolen_bytes,dhook_.stolen_len);
        DirectMailbox mb{};proc_mem_write(pid,dhook_.mailbox_addr,&mb,sizeof(mb));
        if(dhook_.cave_addr&&dhook_.cave_size>0){
            std::vector<uint8_t> zeros(dhook_.cave_size,0xCC);
            proc_mem_write(pid,dhook_.cave_addr,zeros.data(),zeros.size());}}
    dhook_={};LOG_INFO("[direct-hook] cleaned up");
}

uint64_t Injection::send_via_mailbox(const void* data, size_t len, uint32_t flags) {
    if(!dhook_.active||!dhook_.mailbox_addr||len>16320) return 0;
    pid_t pid=memory_.get_pid();if(pid<=0)return 0;
    uint64_t seq=0,ack=0;
    proc_mem_read(pid,dhook_.mailbox_addr+16,&seq,8);proc_mem_read(pid,dhook_.mailbox_addr+24,&ack,8);
    for(int i=0;i<200&&seq>ack;i++){usleep(10000);proc_mem_read(pid,dhook_.mailbox_addr+24,&ack,8);}
    if(seq>ack) return 0;
    if(!proc_mem_write(pid,dhook_.mailbox_addr+64,data,len)) return 0;
    uint32_t sz=(uint32_t)len,z32=0;uint8_t z8=0;uint16_t z16=0;
    proc_mem_write(pid,dhook_.mailbox_addr+32,&sz,4);
    proc_mem_write(pid,dhook_.mailbox_addr+36,&flags,4);
    proc_mem_write(pid,dhook_.mailbox_addr+44,&z32,4);
    proc_mem_write(pid,dhook_.mailbox_addr+40,&z8,1);
    proc_mem_write(pid,dhook_.mailbox_addr+42,&z16,2);
    uint64_t ns=seq+1;proc_mem_write(pid,dhook_.mailbox_addr+16,&ns,8);
    return ns;
}

bool Injection::wait_for_mailbox_ack(uint64_t armed_seq, size_t bc_len, uint8_t bc_ver) {
    if(!dhook_.active||!dhook_.mailbox_addr||armed_seq==0) return false;
    pid_t mpid=memory_.get_pid();if(mpid<=0)return false;
    for(int i=0;i<100;i++){
        usleep(50000);if(kill(mpid,0)!=0)return false;
        uint64_t ca=0;proc_mem_read(mpid,dhook_.mailbox_addr+24,&ca,8);
        if(ca>=armed_seq){LOG_INFO("[direct-hook] ack confirmed in {}ms",(i+1)*50);return true;}
        if(i%20==19){uint32_t step=0;uint8_t guard=0;uint16_t hits=0;
            proc_mem_read(mpid,dhook_.mailbox_addr+44,&step,4);
            proc_mem_read(mpid,dhook_.mailbox_addr+40,&guard,1);
            proc_mem_read(mpid,dhook_.mailbox_addr+42,&hits,2);
            LOG_DEBUG("[direct-hook] wait[{}]: step={} guard={} hits={}",i,step,guard,hits);}}
    LOG_ERROR("[direct-hook] execution timeout");return false;
}

bool Injection::attach() {
    if(memory_.is_valid()&&process_alive()){auto r=memory_.get_regions();if(!r.empty())return true;}
    if(!scan_for_roblox()) return false;
    set_state(InjectionState::Attaching,"Attaching to PID "+std::to_string(memory_.get_pid())+"...");
    auto regions=memory_.get_regions();
    if(regions.empty()){set_state(InjectionState::Failed,"Cannot read process memory");return false;}
    set_state(InjectionState::Ready,"Attached to process");return true;
}

bool Injection::detach() {
    cleanup_direct_hook();stop_elevated_helper();
    if(state_!=InjectionState::Detached){try{set_state(InjectionState::Detached,"Detached");}catch(...){}}
    state_=InjectionState::Detached;memory_.set_pid(0);
    mode_=InjectionMode::None;vm_marker_addr_=0;vm_scan_={};proc_info_={};
    payload_loaded_=false;
    {std::lock_guard<std::mutex> lk(mtx_);status_cb_=nullptr;}
    return true;
}

bool Injection::inject() {
    if(!attach()) return false;
    if(dhook_.active&&payload_loaded_&&process_alive()) return true;
    if(!process_alive()){cleanup_direct_hook();set_state(InjectionState::Failed,"Process died");memory_.set_pid(0);return false;}

    std::string payload=find_payload_path();
    if(!payload.empty()){
        {std::ifstream sf("/proc/sys/kernel/yama/ptrace_scope");int scope=-1;
         if(sf){sf>>scope;sf.close();
         if(scope>0){
             {std::ofstream fix("/proc/sys/kernel/yama/ptrace_scope",std::ios::trunc);if(fix)fix<<"0";}
             {std::ifstream rc("/proc/sys/kernel/yama/ptrace_scope");int v=-1;if(rc)rc>>v;
              if(v!=0){pid_t pk=fork();
                  if(pk==0){execlp("pkexec","pkexec","sh","-c","echo 0 > /proc/sys/kernel/yama/ptrace_scope",nullptr);_exit(127);}
                  if(pk>0){int st;waitpid(pk,&st,0);}}}}}}

        set_state(InjectionState::Injecting,"Injecting payload...");
        if(inject_library(memory_.get_pid(),payload)){
            set_state(InjectionState::Initializing,"Payload loaded \u2014 waiting for init...");
            auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
            bool handshake=false;
            while(std::chrono::steady_clock::now()<deadline){
                if(verify_payload_alive()){handshake=true;break;}
                std::this_thread::sleep_for(std::chrono::milliseconds(100));}
            if(handshake) payload_loaded_=true;
            else{payload_loaded_=false;
                set_state(InjectionState::Injecting,"Trying direct hook...");
                if(inject_via_direct_hook(memory_.get_pid())) payload_loaded_=true;}
        }else{
            LOG_WARN("Library injection failed ({}), trying direct hook",error_);
            set_state(InjectionState::Injecting,"Trying direct hook...");
            if(inject_via_direct_hook(memory_.get_pid())) payload_loaded_=true;}
    }else{
        set_state(InjectionState::Injecting,"Direct hook (no payload library)...");
        if(inject_via_direct_hook(memory_.get_pid())) payload_loaded_=true;}

    bool found=locate_luau_vm();
    mode_=payload_loaded_?InjectionMode::Full:InjectionMode::LocalOnly;
    if(payload_loaded_){
        if(dhook_.active) set_state(InjectionState::Ready,"Direct hook active \u2014 ready for scripts");
        else if(found) set_state(InjectionState::Ready,"Injection complete");
        else set_state(InjectionState::Ready,"Payload injected");
    }else{
        set_state(InjectionState::Ready,found?"Attached \u2014 VM located":"Attached \u2014 local execution mode");}
    return true;
}

bool Injection::verify_payload_alive() {
    if(!payload_loaded_||!process_alive()) return false;
    bool mapped=false;auto regions=memory_.get_regions();
    for(const auto& r:regions){
        if(r.path.find("liboss_payload")!=std::string::npos||r.path.find("oss_payload")!=std::string::npos)
            {mapped=true;break;}
        if(!payload_mapped_name_.empty()&&r.path.find(payload_mapped_name_)!=std::string::npos){mapped=true;break;}}
    if(!mapped&&(proc_info_.via_flatpak||proc_info_.via_sober)) mapped=true;
    if(!mapped) return false;

    std::string prefix;pid_t pid=memory_.get_pid();
    if((proc_info_.via_flatpak||proc_info_.via_sober)&&pid>0)
        prefix="/proc/"+std::to_string(pid)+"/root";

    struct stat st;
    if(::stat((prefix+"/tmp/oss_payload_ready").c_str(),&st)==0) return true;

    int afd=::socket(AF_UNIX,SOCK_STREAM,0);
    if(afd>=0){struct sockaddr_un aa{};aa.sun_family=AF_UNIX;aa.sun_path[0]='\0';
        static constexpr char AS[]="oss_executor_v2";memcpy(aa.sun_path+1,AS,sizeof(AS)-1);
        socklen_t al=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+sizeof(AS)-1);
        struct timeval tv{};tv.tv_usec=500000;setsockopt(afd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        bool ok=(::connect(afd,(struct sockaddr*)&aa,al)==0);::close(afd);if(ok)return true;}

    std::string sp=prefix+PAYLOAD_SOCK;int fd=::socket(AF_UNIX,SOCK_STREAM,0);
    if(fd>=0){struct sockaddr_un addr{};addr.sun_family=AF_UNIX;
        strncpy(addr.sun_path,sp.c_str(),sizeof(addr.sun_path)-1);
        struct timeval tv{};tv.tv_usec=500000;setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        bool ok=(::connect(fd,(struct sockaddr*)&addr,sizeof(addr))==0);::close(fd);if(ok)return true;}

    if(::stat((prefix+"/tmp/oss_payload_cmd").c_str(),&st)==0) return true;
    return false;
}

bool Injection::execute_script(const std::string& source) {
    if(state_!=InjectionState::Ready) return false;
    if(!process_alive()){set_state(InjectionState::Failed,"Target process exited");payload_loaded_=false;memory_.set_pid(0);return false;}
    if(source.empty()) return true;
    if(!payload_loaded_){set_state(InjectionState::Ready,"No payload");return false;}

    set_state(InjectionState::Executing,"Executing ("+std::to_string(source.size())+" bytes)...");

    if(dhook_.active){
        size_t bc_len=0;char* bc=luau_compile(source.c_str(),source.size(),nullptr,&bc_len);
        if(!bc||bc_len==0||(uint8_t)bc[0]==0){
            std::string ce=(bc&&bc_len>1)?std::string(bc+1,bc_len-1):"unknown";
            free(bc);set_state(InjectionState::Ready,"Compile error: "+ce);return false;}
        uint8_t bc_ver=(uint8_t)bc[0];
        if(bc_ver<3||bc_ver>6){free(bc);set_state(InjectionState::Ready,"Bad bytecode version");return false;}
        if(bc_len>16320){free(bc);set_state(InjectionState::Ready,"Bytecode too large");return false;}
        uint64_t armed=send_via_mailbox(bc,bc_len,1);
        size_t slen=bc_len;free(bc);
        if(armed>0&&wait_for_mailbox_ack(armed,slen,bc_ver)){
            set_state(InjectionState::Ready,"Script executed in Roblox");return true;}
        if(armed>0){set_state(InjectionState::Ready,"Script dispatch timeout");return false;}
        LOG_WARN("Mailbox send failed, trying IPC fallback");}

    {size_t bc_len=0;char* bc=luau_compile(source.c_str(),source.size(),nullptr,&bc_len);
     if(!bc||bc_len==0||(uint8_t)bc[0]==0){
         std::string ce=(bc&&bc_len>1)?std::string(bc+1,bc_len-1):"unknown";
         free(bc);set_state(InjectionState::Ready,"Compile error: "+ce);return false;}
     free(bc);}

    auto try_send=[&](int fd)->bool{
        const char* d=source.data();size_t rem=source.size();
        while(rem>0){ssize_t n=::write(fd,d,rem);if(n<=0)return false;d+=n;rem-=(size_t)n;}
        ::shutdown(fd,SHUT_WR);return true;};

    {int afd=::socket(AF_UNIX,SOCK_STREAM,0);
     if(afd>=0){struct sockaddr_un aa{};aa.sun_family=AF_UNIX;aa.sun_path[0]='\0';
         static constexpr char AS[]="oss_executor_v2";memcpy(aa.sun_path+1,AS,sizeof(AS)-1);
         socklen_t al=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+sizeof(AS)-1);
         struct timeval tv{};tv.tv_sec=2;setsockopt(afd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
         if(::connect(afd,(struct sockaddr*)&aa,al)==0&&try_send(afd)){
             ::close(afd);set_state(InjectionState::Ready,"Script dispatched");return true;}
         ::close(afd);}}

    std::string sock_path=PAYLOAD_SOCK;
    if(proc_info_.via_flatpak||proc_info_.via_sober){pid_t p=memory_.get_pid();
        if(p>0)sock_path="/proc/"+std::to_string(p)+"/root"+PAYLOAD_SOCK;}
    {int fd=::socket(AF_UNIX,SOCK_STREAM,0);
     if(fd>=0){struct sockaddr_un addr{};addr.sun_family=AF_UNIX;
         strncpy(addr.sun_path,sock_path.c_str(),sizeof(addr.sun_path)-1);
         struct timeval tv{};tv.tv_sec=2;setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
         if(::connect(fd,(struct sockaddr*)&addr,sizeof(addr))==0&&try_send(fd)){
             ::close(fd);set_state(InjectionState::Ready,"Script dispatched");return true;}
         ::close(fd);}}

    {std::string cmd_path="/tmp/oss_payload_cmd";
     if(proc_info_.via_flatpak||proc_info_.via_sober){pid_t p=memory_.get_pid();
         if(p>0)cmd_path="/proc/"+std::to_string(p)+"/root/tmp/oss_payload_cmd";}
     std::string tmp=cmd_path+".tmp";
     int cfd=::open(tmp.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0644);
     if(cfd>=0){const char* d=source.data();size_t rem=source.size();bool ok=true;
         while(rem>0){ssize_t n=::write(cfd,d,rem);if(n<=0){ok=false;break;}d+=n;rem-=(size_t)n;}
         ::fsync(cfd);::close(cfd);
         if(ok&&::rename(tmp.c_str(),cmd_path.c_str())==0){
             for(int i=0;i<40;i++){usleep(50000);struct stat st;
                 if(::stat(cmd_path.c_str(),&st)!=0){
                     set_state(InjectionState::Ready,"Script executed via file IPC");return true;}}
             ::unlink(cmd_path.c_str());}
         ::unlink(tmp.c_str());}}

    set_state(InjectionState::Ready,"All IPC channels failed");return false;
}

void Injection::start_auto_scan() {
    bool expected=false;if(!scanning_.compare_exchange_strong(expected,true))return;
    scan_thread_=std::thread([this](){
        while(scanning_.load()){
            if(memory_.is_valid()&&!process_alive()){
                cleanup_direct_hook();mode_=InjectionMode::None;vm_marker_addr_=0;
                vm_scan_={};proc_info_={};payload_loaded_=false;payload_mapped_name_.clear();
                memory_.set_pid(0);set_state(InjectionState::Idle,"Process exited \u2014 rescanning...");}
            if(!memory_.is_valid()) scan_for_roblox();
            for(int i=0;i<AUTOSCAN_TICKS&&scanning_.load();i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(TICK_MS));}});
}

void Injection::stop_auto_scan() { scanning_.store(false); if(scan_thread_.joinable()) scan_thread_.join(); }

} // namespace oss
