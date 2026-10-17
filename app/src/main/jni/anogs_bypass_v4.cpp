// ============================================================================
// anogs_bypass_v4.cpp — ANOGS/ACE native bypass (single-file, hardened)
// Target: libanogs.so (Tencent ACE / ANOGS)
// ABI: arm64-v8a (armeabi-v7a ใช้ branch __arm__ ที่เตรียมไว้)
//
// Fixes over v3:
//   [1] ret0/ret_n1: prologue validation + float/double return variants
//   [2] find_module: dl_iterate_phdr (correct load bias, not first mapping)
//   [3] inline_hook: real trampoline in executable mmap (callable)
//   [4] dlopen hook: REMOVED — polling thread (safe, no crash surface)
//   [5] offsets: FNV-1a fingerprint gate before any patch
//   [6] patch_bytes: preserve and restore original page protection
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <atomic>

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#include <jni.h>
#include <android/log.h>

#define LOG_TAG "anogsbypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace anogs {

// ============================================================================
// SECTION 1 — module discovery (FIX #2: dl_iterate_phdr)
// ============================================================================

struct ModuleInfo {
    uintptr_t   base = 0;   // load bias (dlpi_addr)
    size_t      size = 0;   // span of PT_LOAD segments
    std::string path;
    bool valid() const { return base != 0 && size != 0; }
};

struct PhdrCtx {
    const char* soname;
    uintptr_t   base;
    size_t      size;
    std::string path;
    bool        found;
};

static int phdr_cb(struct dl_phdr_info* info, size_t /*sz*/, void* data) {
    auto* ctx = (PhdrCtx*)data;
    if (!info->dlpi_name || !std::strstr(info->dlpi_name, ctx->soname))
        return 0;

    ctx->base = (uintptr_t)info->dlpi_addr;   // TRUE load bias
    ctx->size = 0;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) {
            size_t end = (size_t)ph.p_vaddr + (size_t)ph.p_memsz;
            if (end > ctx->size) ctx->size = end;
        }
    }
    ctx->path  = info->dlpi_name;
    ctx->found = true;
    return 1; // stop iteration
}

static ModuleInfo find_module(const char* soname) {
    PhdrCtx ctx{ soname, 0, 0, {}, false };
    ::dl_iterate_phdr(phdr_cb, &ctx);
    ModuleInfo m;
    if (ctx.found) {
        m.base = ctx.base;
        m.size = ctx.size;
        m.path = ctx.path;
    }
    return m;
}

// ============================================================================
// SECTION 2 — page permission + patch_bytes (FIX #6: preserve prot)
// ============================================================================

static long page_size() {
    static long ps = ::sysconf(_SC_PAGESIZE);
    return ps > 0 ? ps : 4096;
}

// read the protection bits for the mapping containing `addr`
static int get_page_prot(uintptr_t addr) {
    int fd = ::open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    int result = -1;
    char buf[4096];
    size_t used = 0;
    // stream the file line by line
    while (true) {
        ssize_t n = ::read(fd, buf + used, sizeof(buf) - used - 1);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = '\0';

        char* line = buf;
        while (char* nl = std::strchr(line, '\n')) {
            *nl = '\0';
            uintptr_t lo = 0, hi = 0;
            char perms[8] = {0};
            if (std::sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3) {
                if (addr >= lo && addr < hi) {
                    int prot = 0;
                    if (perms[0] == 'r') prot |= PROT_READ;
                    if (perms[1] == 'w') prot |= PROT_WRITE;
                    if (perms[2] == 'x') prot |= PROT_EXEC;
                    result = prot;
                    goto done;
                }
            }
            line = nl + 1;
        }
        size_t remain = used - (size_t)(line - buf);
        if (remain) std::memmove(buf, line, remain);
        used = remain;
    }
done:
    ::close(fd);
    return result;
}

static bool patch_bytes(void* addr, const void* data, size_t len) {
    if (!addr || !data || !len) return false;

    uintptr_t a = (uintptr_t)addr & ~(uintptr_t)(page_size() - 1);
    size_t    l = ((uintptr_t)addr + len) - a;

    int orig_prot = get_page_prot((uintptr_t)addr);
    if (orig_prot < 0) {
        LOGE("patch_bytes: cannot read prot at 0x%lx", (unsigned long)addr);
        return false;
    }

    // add write, keep existing bits (so we don't drop PROT_EXEC while patching
    // if the page is already executable code)
    if (::mprotect((void*)a, l, orig_prot | PROT_WRITE) != 0) {
        LOGE("patch_bytes: mprotect RW failed at 0x%lx (errno=%d)",
             (unsigned long)a, errno);
        return false;
    }

    std::memcpy(addr, data, len);
    __builtin___clear_cache((char*)addr, (char*)addr + len);

    // restore original protection
    if (::mprotect((void*)a, l, orig_prot) != 0) {
        LOGW("patch_bytes: restore prot failed at 0x%lx (errno=%d)",
             (unsigned long)a, errno);
    }
    return true;
}

// ============================================================================
// SECTION 3 — ARM64 instructions + prologue guard (FIX #1)
// ============================================================================

#if defined(__aarch64__)
static constexpr uint32_t INSN_MOV_X0_0  = 0xD2800000u; // mov x0, #0
static constexpr uint32_t INSN_MOV_X0_N1 = 0x92800000u; // mov x0, #-1
static constexpr uint32_t INSN_FMOV_S0_0 = 0x1E2703E0u; // fmov s0, wzr
static constexpr uint32_t INSN_FMOV_D0_0 = 0x9E6703E0u; // fmov d0, xzr
static constexpr uint32_t INSN_RET        = 0xD65F03C0u; // ret

// recognise common function prologues so we never patch mid-function
static bool is_function_start(uintptr_t addr) {
    if (!addr) return false;
    uint32_t i = *(const uint32_t*)addr;
    // stp x29, x30, [sp, #-N]!     → 0xA9Bxxxxx
    if ((i & 0xFFC00000u) == 0xA9800000u) return true;
    // stp x29, x30, [sp, #N]       → 0xA90xxxxx
    if ((i & 0xFFC00000u) == 0xA9000000u) return true;
    // sub sp, sp, #imm             → 0xD10xxxxx
    if ((i & 0xFF800000u) == 0xD1000000u) return true;
    // paciasp                      → 0xD503233F
    if (i == 0xD503233Fu) return true;
    // ret (empty function)         → 0xD65F03C0
    if (i == INSN_RET) return true;
    return false;
}

static bool ret0(uintptr_t addr) {
    if (!is_function_start(addr)) {
        LOGE("ret0: 0x%lx not a function start (insn=0x%08x)",
             (unsigned long)addr, *(const uint32_t*)addr);
        return false;
    }
    uint32_t code[2] = { INSN_MOV_X0_0, INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}

static bool ret_n1(uintptr_t addr) {
    if (!is_function_start(addr)) {
        LOGE("ret_n1: 0x%lx not a function start", (unsigned long)addr);
        return false;
    }
    uint32_t code[2] = { INSN_MOV_X0_N1, INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}

static bool ret_f0(uintptr_t addr) {
    if (!is_function_start(addr)) return false;
    uint32_t code[2] = { INSN_FMOV_S0_0, INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}

static bool ret_d0(uintptr_t addr) {
    if (!is_function_start(addr)) return false;
    uint32_t code[2] = { INSN_FMOV_D0_0, INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}

static bool ret_void(uintptr_t addr) {
    if (!is_function_start(addr)) {
        LOGE("ret_void: 0x%lx not a function start", (unsigned long)addr);
        return false;
    }
    uint32_t code[1] = { INSN_RET };
    return patch_bytes((void*)addr, code, sizeof(code));
}

#elif defined(__arm__)
static constexpr uint32_t INSN_MOV_R0_0  = 0xE3A00000u; // mov r0,#0
static constexpr uint32_t INSN_MVN_R0_0  = 0xE3E00000u; // mvn r0,#0
static constexpr uint32_t INSN_BX_LR      = 0xE12FFF1Eu;

static bool is_function_start(uintptr_t addr) {
    if (!addr) return false;
    uint32_t i = *(const uint32_t*)addr;
    // push {..., lr}  = 0xE92Dxxxx
    if ((i & 0xFFFF0000u) == 0xE92D0000u) return true;
    // stmdb sp!, {...} same family
    if ((i & 0xFFF00000u) == 0xE9200000u) return true;
    // bx lr (empty function)
    if (i == INSN_BX_LR) return true;
    return false;
}
static bool ret0(uintptr_t addr) {
    if (!is_function_start(addr)) return false;
    uint32_t c[2] = { INSN_MOV_R0_0, INSN_BX_LR };
    return patch_bytes((void*)addr, c, sizeof(c));
}
static bool ret_n1(uintptr_t addr) {
    if (!is_function_start(addr)) return false;
    uint32_t c[2] = { INSN_MVN_R0_0, INSN_BX_LR };
    return patch_bytes((void*)addr, c, sizeof(c));
}
static bool ret_void(uintptr_t addr) {
    if (!is_function_start(addr)) return false;
    uint32_t c[1] = { INSN_BX_LR };
    return patch_bytes((void*)addr, c, sizeof(c));
}
static bool ret_f0(uintptr_t addr) { return ret0(addr); }
static bool ret_d0(uintptr_t addr) { return ret0(addr); }
#endif

// ============================================================================
// SECTION 4 — offsets (from libanogs.so.c)
// ============================================================================

namespace offsets {

// ---- integrity checker — MUST patch first ----
constexpr uintptr_t kInteg_1F89AC       = 0x1F89AC;
constexpr uintptr_t kInteg_1F89D8       = 0x1F89D8;
constexpr uintptr_t kInteg_1F8AB8       = 0x1F8AB8;

// ---- init ----
constexpr uintptr_t kInit_1C36CC        = 0x1C36CC;
constexpr uintptr_t kInit_1C3740        = 0x1C3740;

// ---- detection chain ----
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

// ---- env check ----
constexpr uintptr_t kEnv_1B2864         = 0x1B2864;
constexpr uintptr_t kEnv_1B2B80         = 0x1B2B80;
constexpr uintptr_t kEnv_1B2F00         = 0x1B2F00;
constexpr uintptr_t kEnv_1B3280         = 0x1B3280;
constexpr uintptr_t kEnv_1B3578         = 0x1B3578;

// ---- watchdog ----
constexpr uintptr_t kThread_4C0968      = 0x4C0968;
constexpr uintptr_t kThread_377144      = 0x377144;

// ---- kill / response ----
constexpr uintptr_t kKill_2D4F08        = 0x2D4F08;
constexpr uintptr_t kKill_2D5158        = 0x2D5158;
constexpr uintptr_t kKill_30CA70        = 0x30CA70;
constexpr uintptr_t kKill_30CACC        = 0x30CACC;

// ---- report packers (Stage 6 — off until reversed) ----
constexpr uintptr_t kReport_1CC130      = 0x1CC130;
constexpr uintptr_t kReport_1CC1DC      = 0x1CC1DC;
constexpr uintptr_t kReport_1CC278      = 0x1CC278;

// ---- syscall wrappers ----
constexpr uintptr_t kSys_3ED518         = 0x3ED518;
constexpr uintptr_t kSys_3ED61C         = 0x3ED61C;
constexpr uintptr_t kSys_3ED720         = 0x3ED720;
constexpr uintptr_t kSys_3ED760         = 0x3ED760;
constexpr uintptr_t kSysRange_4E0xxx_start = 0x4E0140;
constexpr uintptr_t kSysRange_4E0xxx_end   = 0x4E0F00;

// ---- timing check ----
constexpr uintptr_t kTime_39FF04        = 0x39FF04;
constexpr uintptr_t kTime_39FF30        = 0x39FF30;

} // namespace offsets

// ============================================================================
// SECTION 5 — fingerprint gate (FIX #5)
// ============================================================================
// FNV-1a over first N bytes of .text; if the SO doesn't match a known
// fingerprint, we refuse to patch.
//
// HOW TO POPULATE:
//   1. Build this file, run on device with the target APK.
//   2. Read logcat line: "libanogs.so fingerprint = 0x................"
//   3. Paste that value into KNOWN_FP[]. Add one entry per game/version.
// ============================================================================

static uint64_t fnv1a(const void* data, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

// hash first 4096 bytes of the first PT_LOAD executable segment
static uint64_t fingerprint_so(uintptr_t base) {
    const Elf64_Ehdr* eh = (const Elf64_Ehdr*)base;
    if (eh->e_ident[EI_MAG0] != ELFMAG0) return 0;

    const Elf64_Phdr* ph = (const Elf64_Phdr*)(base + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
            const uint8_t* seg = (const uint8_t*)(base + ph[i].p_vaddr);
            size_t n = ph[i].p_filesz < 4096 ? (size_t)ph[i].p_filesz : 4096;
            return fnv1a(seg, n);
        }
    }
    return 0;
}

// ---- list of approved fingerprints ----
// Populate after running v4 once against the real game.
static const uint64_t KNOWN_FP[] = {
    // 0x................................ULL,  // <-- fill from logcat
};

static bool fingerprint_approved(uint64_t fp) {
    if (sizeof(KNOWN_FP) == 0) {
        LOGW("KNOWN_FP[] empty — fingerprint gate bypassed (dev mode)");
        return true;
    }
    for (uint64_t v : KNOWN_FP)
        if (v == fp) return true;
    return false;
}

// ============================================================================
// SECTION 6 — inline hook with real trampoline (FIX #3)
// ============================================================================

namespace hook {

#if defined(__aarch64__)

// Build a callable trampoline:
//   [ 16 bytes of the original target prologue ]
//   [ ldr x16, #8 ; br x16 ; .quad (target+16) ]
static void* make_trampoline(void* target) {
    void* mem = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("make_trampoline: mmap failed (errno=%d)", errno);
        return nullptr;
    }
    std::memcpy(mem, target, 16);

    uint32_t* p = (uint32_t*)((char*)mem + 16);
    p[0] = 0x58000050u; // ldr x16, #8
    p[1] = 0xD61F0200u; // br  x16
    *(uint64_t*)(p + 2) = (uint64_t)target + 16;

    if (::mprotect(mem, 4096, PROT_READ | PROT_EXEC) != 0) {
        LOGE("make_trampoline: mprotect RX failed (errno=%d)", errno);
        ::munmap(mem, 4096);
        return nullptr;
    }
    __builtin___clear_cache((char*)mem, (char*)mem + 32);
    return mem;
}

static bool inline_hook(void* target, void* replace, void** trampoline_out) {
    if (!target || !replace) return false;

    void* tramp = make_trampoline(target);
    if (!tramp) return false;
    if (trampoline_out) *trampoline_out = tramp;

    uint32_t code[2] = { 0x58000050u, 0xD61F0200u };
    uint64_t addr = (uint64_t)replace;

    uint8_t full[16];
    std::memcpy(full, code, 8);
    std::memcpy(full + 8, &addr, 8);

    if (!patch_bytes(target, full, 16)) {
        ::munmap(tramp, 4096);
        if (trampoline_out) *trampoline_out = nullptr;
        return false;
    }
    return true;
}

#elif defined(__arm__)

static void* make_trampoline(void* target) {
    void* mem = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return nullptr;
    std::memcpy(mem, target, 8);

    uint32_t* p = (uint32_t*)((char*)mem + 8);
    p[0] = 0xE51FF004u;                    // ldr pc, [pc, #-4]
    p[1] = (uint32_t)(uintptr_t)target + 8;

    if (::mprotect(mem, 4096, PROT_READ | PROT_EXEC) != 0) {
        ::munmap(mem, 4096);
        return nullptr;
    }
    __builtin___clear_cache((char*)mem, (char*)mem + 16);
    return mem;
}

static bool inline_hook(void* target, void* replace, void** trampoline_out) {
    if (!target || !replace) return false;
    void* tramp = make_trampoline(target);
    if (!tramp) return false;
    if (trampoline_out) *trampoline_out = tramp;

    uint32_t code[2] = { 0xE51FF004u, (uint32_t)(uintptr_t)replace };
    if (!patch_bytes(target, code, 8)) {
        ::munmap(tramp, 4096);
        if (trampoline_out) *trampoline_out = nullptr;
        return false;
    }
    return true;
}

#endif

} // namespace hook

// ============================================================================
// SECTION 7 — syscall wrapper scan
// ============================================================================

static int patch_syscall_wrappers(uintptr_t base) {
    int patched = 0;

    // fixed wrappers we know by offset
    uintptr_t fixed[] = {
        offsets::kSys_3ED518,
        offsets::kSys_3ED61C,
        offsets::kSys_3ED720,
        offsets::kSys_3ED760,
    };
    for (auto off : fixed)
        if (ret0(base + off)) patched++;

    // scan the 4E0xxx block for SVC #0; patch the SVC itself to "mov x0,#0"
    // (keeps the wrapper callable, just makes the syscall a no-op that
    // returns 0 in x0 — safer than ret-ing the wrapper body)
    for (uintptr_t off = offsets::kSysRange_4E0xxx_start;
         off < offsets::kSysRange_4E0xxx_end; off += 4) {
        uint32_t insn = *(const uint32_t*)(base + off);
        if (insn == 0xD4000001u) {                    // svc #0
            uint32_t patch[1] = { INSN_MOV_X0_0 };
            if (patch_bytes((void*)(base + off), patch, 4)) patched++;
        }
    }
    return patched;
}

// ============================================================================
// SECTION 8 — libc kill suppression
// ============================================================================

namespace killguard {

static void (*real_exit)(int)                 = nullptr;
static void (*real__exit)(int)                = nullptr;
static void (*real_abort)()                   = nullptr;
static int  (*real_kill)(pid_t, int)          = nullptr;
static int  (*real_tgkill)(pid_t, pid_t, int) = nullptr;

static void hook_exit(int)  {}
static void hook__exit(int) {}
static void hook_abort()    {}

static int hook_kill(pid_t pid, int sig) {
    if (pid == ::getpid() &&
        (sig == SIGKILL || sig == SIGABRT || sig == SIGSEGV))
        return 0;
    return real_kill ? real_kill(pid, sig) : -1;
}

static int hook_tgkill(pid_t tgid, pid_t tid, int sig) {
    if (tgid == ::getpid() && (sig == SIGKILL || sig == SIGABRT))
        return 0;
    return real_tgkill ? real_tgkill(tgid, tid, sig) : -1;
}

static void install() {
    real_exit   = (void (*)(int))       ::dlsym(RTLD_DEFAULT, "exit");
    real__exit  = (void (*)(int))       ::dlsym(RTLD_DEFAULT, "_exit");
    real_abort  = (void (*)())          ::dlsym(RTLD_DEFAULT, "abort");
    real_kill   = (int (*)(pid_t,int))  ::dlsym(RTLD_DEFAULT, "kill");
    real_tgkill = (int (*)(pid_t,pid_t,int))::dlsym(RTLD_DEFAULT, "tgkill");

    void* dummy;
    if (real_exit)   hook::inline_hook((void*)real_exit,   (void*)hook_exit,   &dummy);
    if (real__exit)  hook::inline_hook((void*)real__exit,  (void*)hook__exit,  &dummy);
    if (real_abort)  hook::inline_hook((void*)real_abort,  (void*)hook_abort,  &dummy);
    if (real_kill)   hook::inline_hook((void*)real_kill,   (void*)hook_kill,   &dummy);
    if (real_tgkill) hook::inline_hook((void*)real_tgkill, (void*)hook_tgkill, &dummy);
}

} // namespace killguard

// ============================================================================
// SECTION 9 — apply_full_bypass (ordered by dependency)
// ============================================================================

static std::atomic<bool> g_applied{false};
static ModuleInfo        g_mod{};

static void apply_full_bypass(uintptr_t base, size_t size) {
    if (g_applied.exchange(true)) return;
    LOGI("applying bypass: base=0x%lx size=0x%zx",
         (unsigned long)base, size);

    // ---- fingerprint gate ----
    uint64_t fp = fingerprint_so(base);
    LOGI("libanogs.so fingerprint = 0x%016llx", (unsigned long long)fp);
    if (!fingerprint_approved(fp)) {
        LOGE("fingerprint NOT approved — refusing to patch");
        g_applied = false;
        return;
    }

    // ---- Stage 0: integrity checker (must be first) ----
    ret0(base + offsets::kInteg_1F89AC);
    ret0(base + offsets::kInteg_1F89D8);
    ret0(base + offsets::kInteg_1F8AB8);
    LOGI("Stage 0: integrity checker neutralised");

    // ---- Stage 1: syscall wrappers ----
    int sys = patch_syscall_wrappers(base);
    LOGI("Stage 1: syscall wrappers patched = %d", sys);

    // ---- Stage 2: watchdog ----
    ret_n1(base + offsets::kThread_4C0968);
    ret_n1(base + offsets::kThread_377144);
    LOGI("Stage 2: watchdog blocked");

    // ---- Stage 3: detection chain ----
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
    LOGI("Stage 3: detection + env chain neutralised");

    // ---- Stage 4: timing ----
    ret0(base + offsets::kTime_39FF04);
    ret0(base + offsets::kTime_39FF30);
    LOGI("Stage 4: timing checks neutralised");

    // ---- Stage 5: kill ----
    ret_void(base + offsets::kKill_2D4F08);
    ret_void(base + offsets::kKill_2D5158);
    ret_void(base + offsets::kKill_30CA70);
    ret_void(base + offsets::kKill_30CACC);
    killguard::install();
    LOGI("Stage 5: kill suppressed");

    // ---- Stage 6: report packers ----
    // OFF by default — needs reversed format or server marks "tampered".
    // Enable only after sub_1CC44C layout is confirmed.
    // ret0(base + offsets::kReport_1CC130);
    // ret0(base + offsets::kReport_1CC1DC);
    // ret0(base + offsets::kReport_1CC278);
    LOGW("Stage 6: report spoof SKIPPED (format not reversed)");

    LOGI("bypass fully applied");
}

// ============================================================================
// SECTION 10 — polling thread (FIX #4: no dlopen hook)
// ============================================================================

static void* poll_thread(void*) {
    // 30 s budget, 10 ms cadence
    for (int i = 0; i < 3000; ++i) {
        ModuleInfo m = find_module("libanogs.so");
        if (m.valid()) {
            g_mod = m;
            apply_full_bypass(m.base, m.size);
            return nullptr;
        }
        ::usleep(10 * 1000);
    }
    LOGW("timeout waiting for libanogs.so");
    return nullptr;
}

// ============================================================================
// SECTION 11 — constructor
// ============================================================================

__attribute__((constructor))
static void anogs_bypass_ctor() {
    LOGI("anogs_bypass v4 ctor");

    // if already mapped (companion lib case), patch immediately
    ModuleInfo m = find_module("libanogs.so");
    if (m.valid()) {
        g_mod = m;
        apply_full_bypass(m.base, m.size);
        return;
    }

    // otherwise poll — safe, no dlopen hook surface
    pthread_t t;
    if (pthread_create(&t, nullptr, poll_thread, nullptr) == 0)
        pthread_detach(t);
    else
        LOGE("pthread_create failed (errno=%d)", errno);
}

} // namespace anogs

// ============================================================================
// SECTION 12 — JNI_OnLoad
// ============================================================================

