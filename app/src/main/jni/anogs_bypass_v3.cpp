// ============================================================================
// anogs_bypass_v3.cpp — ANOGS/ACE bypass ติดตั้งตอนเริ่มเกม ครอบคลุมทุกชั้น
// Target: libanogs.so (Tencent ACE / ANOGS)
// Trigger: intercept dlopen("libanogs.so") → patch ก่อน ACE init
// ABI: arm64-v8a (armeabi-v7a ใช้ hook ต่างกัน — ดูหมายเหตุ)
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <android/log.h>

#define LOG_TAG "anogsbypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace anogs {

// ============================================================================
// SECTION 1 — module discovery
// ============================================================================

struct ModuleInfo {
    uintptr_t   base = 0;
    size_t      size = 0;
    std::string path;
    bool valid() const { return base != 0 && size != 0; }
};

static bool read_maps(std::string& out) {
    int fd = ::open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0)
        out.append(buf, (size_t)n);
    ::close(fd);
    return !out.empty();
}

static ModuleInfo find_module(const char* soname) {
    ModuleInfo m;
    std::string maps;
    if (!read_maps(maps)) return m;
    size_t pos = 0;
    while (pos < maps.size()) {
        size_t eol = maps.find('\n', pos);
        if (eol == std::string::npos) eol = maps.size();
        std::string line = maps.substr(pos, eol - pos);
        pos = eol + 1;
        if (line.find(soname) == std::string::npos) continue;
        uintptr_t lo = 0, hi = 0;
        char perms[8] = {0};
        if (std::sscanf(line.c_str(), "%lx-%lx %7s", &lo, &hi, perms) != 3)
            continue;
        if (m.base == 0 || lo < m.base) m.base = lo;
        if (hi > m.base + m.size) m.size = hi - m.base;
        size_t sp = line.find('/');
        if (sp != std::string::npos && m.path.empty())
            m.path = line.substr(sp);
    }
    return m;
}

// ============================================================================
// SECTION 2 — patch primitives
// ============================================================================

static long page_size() {
    static long ps = ::sysconf(_SC_PAGESIZE);
    return ps > 0 ? ps : 4096;
}

static bool make_writable(void* addr, size_t len) {
    uintptr_t a = (uintptr_t)addr & ~(uintptr_t)(page_size() - 1);
    size_t    l = ((uintptr_t)addr + len) - a;
    return ::mprotect((void*)a, l, PROT_READ | PROT_WRITE) == 0;
}

static bool patch_bytes(void* addr, const void* data, size_t len) {
    if (!addr || !data || !len) return false;
    if (!make_writable(addr, len)) return false;
    std::memcpy(addr, data, len);
    __builtin___clear_cache((char*)addr, (char*)addr + len);
    return true;
}

// ============================================================================
// SECTION 3 — ARM64 patch encodings
// ============================================================================

static constexpr uint32_t INSN_MOV_X0_0  = 0xD2800000u;
static constexpr uint32_t INSN_MOV_X0_N1 = 0x92800000u;
static constexpr uint32_t INSN_RET        = 0xD65F03C0u;

static bool ret0(uintptr_t addr) {
    uint32_t code[2] = { INSN_MOV_X0_0, INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}
static bool ret_n1(uintptr_t addr) {
    uint32_t code[2] = { INSN_MOV_X0_N1, INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}
static bool ret_void(uintptr_t addr) {
    uint32_t code[1] = { INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}

// ============================================================================
// SECTION 4 — offsets จาก libanogs.so.c
// ============================================================================

namespace offsets {

constexpr uintptr_t kInteg_1F89AC       = 0x1F89AC;
constexpr uintptr_t kInteg_1F89D8       = 0x1F89D8;
constexpr uintptr_t kInteg_1F8AB8       = 0x1F8AB8;

constexpr uintptr_t kInit_1C36CC        = 0x1C36CC;
constexpr uintptr_t kInit_1C3740        = 0x1C3740;
constexpr uintptr_t kInit_1C3658        = 0x1C3658;

constexpr uintptr_t kDet_1B40A0         = 0x1B40A0;
constexpr uintptr_t kDet_1B4984         = 0x1B4984;
constexpr uintptr_t kDet_1B5148         = 0x1B5148;
constexpr uintptr_t kDet_1B6CCC         = 0x1B6CCC;
constexpr uintptr_t kDet_1B767C         = 0x1B767C;
constexpr uintptr_t kDet_1B7780         = 0x1B7780;
constexpr uintptr_t kDet_1B7884         = 0x1B7884;
constexpr uintptr_t kDet_1BA124         = 0x1BA124;
constexpr uintptr_t kDet_1BA72C         = 0x1BA72C;
constexpr uintptr_t kDet_1BAE8C         = 0x1BAE8C;
constexpr uintptr_t kDet_1BB1DC         = 0x1BB1DC;
constexpr uintptr_t kDet_1BBB44         = 0x1BBB44;

constexpr uintptr_t kEnv_1B2864         = 0x1B2864;
constexpr uintptr_t kEnv_1B2B80         = 0x1B2B80;
constexpr uintptr_t kEnv_1B2F00         = 0x1B2F00;
constexpr uintptr_t kEnv_1B3280         = 0x1B3280;
constexpr uintptr_t kEnv_1B3578         = 0x1B3578;

constexpr uintptr_t kThread_4C0968      = 0x4C0968;
constexpr uintptr_t kThread_377144      = 0x377144;

constexpr uintptr_t kKill_2D4F08        = 0x2D4F08;
constexpr uintptr_t kKill_2D5158        = 0x2D5158;
constexpr uintptr_t kKill_30CA70        = 0x30CA70;
constexpr uintptr_t kKill_30CACC        = 0x30CACC;

constexpr uintptr_t kReport_1CC130      = 0x1CC130;
constexpr uintptr_t kReport_1CC1DC      = 0x1CC1DC;
constexpr uintptr_t kReport_1CC278      = 0x1CC278;

constexpr uintptr_t kSys_3ED518         = 0x3ED518;
constexpr uintptr_t kSys_3ED61C         = 0x3ED61C;
constexpr uintptr_t kSys_3ED720         = 0x3ED720;
constexpr uintptr_t kSys_3ED760         = 0x3ED760;

constexpr uintptr_t kSysRange_4E0xxx_start = 0x4E0140;
constexpr uintptr_t kSysRange_4E0xxx_end   = 0x4E0F00;

constexpr uintptr_t kTime_39FF04        = 0x39FF04;
constexpr uintptr_t kTime_39FF30        = 0x39FF30;

} // namespace offsets

// ============================================================================
// SECTION 5 — syscall wrapper patcher
// ============================================================================

static int patch_syscall_wrappers(uintptr_t base, size_t /*size*/) {
    int patched = 0;

    uintptr_t fixed[] = {
        offsets::kSys_3ED518,
        offsets::kSys_3ED61C,
        offsets::kSys_3ED720,
        offsets::kSys_3ED760,
    };
    for (auto off : fixed) {
        if (ret0(base + off)) patched++;
    }

    for (uintptr_t off = offsets::kSysRange_4E0xxx_start;
         off < offsets::kSysRange_4E0xxx_end; off += 4) {
        uint32_t insn = *(uint32_t*)(base + off);
        if (insn == 0xD4000001u) {
            uint32_t patch[1] = { INSN_MOV_X0_0 };
            if (patch_bytes((void*)(base + off), patch, 4)) patched++;
        }
    }
    return patched;
}

// ============================================================================
// SECTION 6 — hook engine
// ============================================================================

namespace hook {

#if defined(__aarch64__)
struct Arm64Patch { uint32_t code[2]; uint64_t addr; };

static bool inline_hook(void* target, void* replace, void** original_out) {
    if (!target || !replace) return false;
    void* saved = ::malloc(16);
    if (!saved) return false;
    std::memcpy(saved, target, 16);
    if (original_out) *original_out = saved;

    Arm64Patch p;
    p.code[0] = 0x58000050u;
    p.code[1] = 0xD61F0200u;
    p.addr    = (uint64_t)replace;

    if (!make_writable(target, 16)) return false;
    std::memcpy(target, p.code, 8);
    std::memcpy((char*)target + 8, &p.addr, 8);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    return true;
}
#endif

} // namespace hook

// ============================================================================
// SECTION 7 — dlopen interception
// ============================================================================

static void* (*real_android_dlopen_ext)(const char*, int, const void*) = nullptr;

static void apply_full_bypass(uintptr_t base, size_t size);

static void* hook_android_dlopen_ext(const char* filename, int flags,
                                      const void* extinfo) {
    void* h = real_android_dlopen_ext
        ? real_android_dlopen_ext(filename, flags, extinfo)
        : nullptr;

    if (filename && std::strstr(filename, "libanogs.so")) {
        LOGI("libanogs.so loaded via dlopen — applying bypass");
        ModuleInfo m = find_module("libanogs.so");
        if (m.valid()) {
            apply_full_bypass(m.base, m.size);
        }
    }
    return h;
}

// ============================================================================
// SECTION 8 — apply_full_bypass
// ============================================================================

static void apply_full_bypass(uintptr_t base, size_t size) {
    LOGI("applying bypass: base=0x%lx size=0x%zx",
         (unsigned long)base, size);

    ret0(base + offsets::kInteg_1F89AC);
    ret0(base + offsets::kInteg_1F89D8);
    ret0(base + offsets::kInteg_1F8AB8);
    LOGI("Stage 0: integrity checker neutralised");

    int sys_patched = patch_syscall_wrappers(base, size);
    LOGI("Stage 1: syscall wrappers patched = %d", sys_patched);

    ret_n1(base + offsets::kThread_4C0968);
    ret_n1(base + offsets::kThread_377144);
    LOGI("Stage 2: watchdog blocked");

    ret0(base + offsets::kDet_1B40A0);
    ret0(base + offsets::kDet_1B4984);
    ret_void(base + offsets::kDet_1B5148);
    ret0(base + offsets::kDet_1B6CCC);
    ret0(base + offsets::kDet_1B767C);
    ret0(base + offsets::kDet_1B7780);
    ret0(base + offsets::kDet_1B7884);
    ret0(base + offsets::kDet_1BA124);
    ret0(base + offsets::kDet_1BA72C);
    ret0(base + offsets::kDet_1BAE8C);
    ret0(base + offsets::kDet_1BB1DC);
    ret0(base + offsets::kDet_1BBB44);

    ret_void(base + offsets::kEnv_1B2864);
    ret0(base + offsets::kEnv_1B2B80);
    ret0(base + offsets::kEnv_1B2F00);
    ret_void(base + offsets::kEnv_1B3280);
    ret_void(base + offsets::kEnv_1B3578);
    LOGI("Stage 3: detection chain neutralised");

    ret0(base + offsets::kTime_39FF04);
    ret0(base + offsets::kTime_39FF30);
    LOGI("Stage 4: timing check neutralised");

    ret_void(base + offsets::kKill_2D4F08);
    ret_void(base + offsets::kKill_2D5158);
    ret_void(base + offsets::kKill_30CA70);
    ret_void(base + offsets::kKill_30CACC);
    LOGI("Stage 5: kill suppressed");

    ret0(base + offsets::kReport_1CC130);
    ret0(base + offsets::kReport_1CC1DC);
    ret0(base + offsets::kReport_1CC278);
    LOGI("Stage 6: report packers stubbed");

    LOGI("bypass fully applied");
}

// ============================================================================
// SECTION 9 — constructor
// ============================================================================

__attribute__((constructor))
static void anogs_bypass_ctor() {
    LOGI("anogs_bypass ctor: installing dlopen hook");

    void* sym = ::dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (sym) {
        real_android_dlopen_ext = (void* (*)(const char*, int, const void*))sym;
        hook::inline_hook(sym, (void*)hook_android_dlopen_ext,
                          (void**)&real_android_dlopen_ext);
        LOGI("android_dlopen_ext hooked");
    } else {
        LOGW("android_dlopen_ext not found — fallback to polling");
    }

    ModuleInfo m = find_module("libanogs.so");
    if (m.valid()) {
        LOGI("libanogs.so already mapped — applying now");
        apply_full_bypass(m.base, m.size);
    } else {
        pthread_t t;
        pthread_create(&t, nullptr, [](void*) -> void* {
            for (int i = 0; i < 3000; ++i) {
                ModuleInfo mm = find_module("libanogs.so");
                if (mm.valid()) {
                    LOGI("libanogs.so appeared via polling");
                    apply_full_bypass(mm.base, mm.size);
                    return nullptr;
                }
                ::usleep(10 * 1000);
            }
            LOGW("timeout waiting for libanogs.so");
            return nullptr;
        }, nullptr);
        pthread_detach(t);
    }
}

} // namespace anogs

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* /*vm*/, void* /*reserved*/) {
    return JNI_VERSION_1_6;
}
