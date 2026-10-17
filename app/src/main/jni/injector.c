// Simple ptrace dlopen injector for Android arm64
// Usage: ./injector <pid> <payload_path>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <android/log.h>

#if defined(__aarch64__)
// ARM64 register access via ptrace
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define NT_PRSTATUS 1

struct user_pt_regs_local {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static int read_regs(int pid, struct user_pt_regs_local* regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

static int write_regs(int pid, struct user_pt_regs_local* regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}
#endif

// Read a value from remote process memory
static int read_remote(int pid, uint64_t addr, void* buf, size_t len) {
    struct iovec local = { buf, len };
    struct iovec remote = { (void*)addr, len };
    ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return r == (ssize_t)len ? 0 : -1;
}

// Write a value to remote process memory
static int write_remote(int pid, uint64_t addr, const void* buf, size_t len) {
    struct iovec local = { (void*)buf, len };
    struct iovec remote = { (void*)addr, len };
    ssize_t r = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return r == (ssize_t)len ? 0 : -1;
}

// Find base address of a module in target
static uint64_t find_module_base(int pid, const char* name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            sscanf(line, "%" SCNx64 "-", &base);
            break;
        }
    }
    fclose(f);
    return base;
}

// Resolve dlopen in target's linker (bionic)
static uint64_t find_dlopen(int pid) {
    // dlopen is in libdl.so which is a stub that jumps into linker
    // Simpler: find dlopen symbol in target via /proc/pid/maps + ELF parsing
    // Fallback: use known offset pattern — find "dlopen" string in linker and compute
    // FOR SIMPLICITY: use libdl.so's dlopen export address
    uint64_t libdl_base = find_module_base(pid, "libdl.so");
    if (!libdl_base) return 0;
    // libdl.so's dlopen is a PLT stub that jumps to linker's __dl_dlopen
    // That's actually the exported symbol, ptrace can call it
    // Find it via parsing ELF header of libdl.so from remote memory
    Elf64_Ehdr ehdr;
    if (read_remote(pid, libdl_base, &ehdr, sizeof(ehdr)) != 0) return 0;
    if (memcmp(ehdr.e_ident, ELFMAG, 4) != 0) return 0;

    // Read section headers
    Elf64_Shdr* shdrs = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
    if (!shdrs) return 0;
    if (read_remote(pid, libdl_base + ehdr.e_shoff, shdrs, sizeof(Elf64_Shdr) * ehdr.e_shnum) != 0) {
        free(shdrs); return 0;
    }

    // Find .dynstr and .dynsym
    Elf64_Shdr *dynstr = NULL, *dynsym = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_STRTAB && !dynstr) dynstr = &shdrs[i];
        if (shdrs[i].sh_type == SHT_DYNSYM && !dynsym) dynsym = &shdrs[i];
    }
    if (!dynstr || !dynsym) { free(shdrs); return 0; }

    // Read dynsym and dynstr
    Elf64_Sym* syms = malloc(dynsym->sh_size);
    char* strtab = malloc(dynstr->sh_size);
    if (!syms || !strtab) { free(syms); free(strtab); free(shdrs); return 0; }

    read_remote(pid, libdl_base + dynsym->sh_offset, syms, dynsym->sh_size);
    read_remote(pid, libdl_base + dynstr->sh_offset, strtab, dynstr->sh_size);

    uint64_t result = 0;
    int num_syms = dynsym->sh_size / sizeof(Elf64_Sym);
    for (int i = 0; i < num_syms; i++) {
        if (strcmp(strtab + syms[i].st_name, "dlopen") == 0) {
            result = libdl_base + syms[i].st_value;
            break;
        }
    }
    free(syms); free(strtab); free(shdrs);
    return result;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <payload.so>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    const char* payload = argv[2];
    __android_log_print(ANDROID_LOG_INFO, "LionInjector", "pid=%d payload=%s", pid, payload);

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        perror("ptrace attach");
        return 1;
    }
    waitpid(pid, NULL, 0);

#if defined(__aarch64__)
    struct user_pt_regs_local saved_regs, regs;
    if (read_regs(pid, &saved_regs) != 0) {
        perror("read regs");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    regs = saved_regs;

    // Find dlopen
    uint64_t dlopen_addr = find_dlopen(pid);
    if (!dlopen_addr) {
        __android_log_print(ANDROID_LOG_ERROR, "LionInjector", "dlopen not found");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    __android_log_print(ANDROID_LOG_INFO, "LionInjector", "dlopen=0x%" PRIx64, dlopen_addr);

    // Find mmap in target (for allocating string)
    uint64_t libc_base = find_module_base(pid, "libc.so");
    // Simple: mmap via syscall — actually use existing SP to place string in stack
    // Simpler: write path to end of target's stack (safe-ish, will restore after)
    // Best: find mmap in libc

    uint64_t mmap_addr = 0;
    if (libc_base) {
        // parse libc.so for mmap
        Elf64_Ehdr ehdr;
        if (read_remote(pid, libc_base, &ehdr, sizeof(ehdr)) == 0) {
            Elf64_Shdr* shdrs = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
            if (shdrs && read_remote(pid, libc_base + ehdr.e_shoff, shdrs, sizeof(Elf64_Shdr) * ehdr.e_shnum) == 0) {
                Elf64_Shdr *dynstr = NULL, *dynsym = NULL;
                for (int i = 0; i < ehdr.e_shnum; i++) {
                    if (shdrs[i].sh_type == SHT_STRTAB && !dynstr) dynstr = &shdrs[i];
                    if (shdrs[i].sh_type == SHT_DYNSYM && !dynsym) dynsym = &shdrs[i];
                }
                if (dynstr && dynsym) {
                    Elf64_Sym* syms = malloc(dynsym->sh_size);
                    char* strtab = malloc(dynstr->sh_size);
                    if (syms && strtab) {
                        read_remote(pid, libc_base + dynsym->sh_offset, syms, dynsym->sh_size);
                        read_remote(pid, libc_base + dynstr->sh_offset, strtab, dynstr->sh_size);
                        int num_syms = dynsym->sh_size / sizeof(Elf64_Sym);
                        for (int i = 0; i < num_syms; i++) {
                            if (strcmp(strtab + syms[i].st_name, "mmap") == 0) {
                                mmap_addr = libc_base + syms[i].st_value;
                                break;
                            }
                        }
                    }
                    free(syms); free(strtab);
                }
            }
            free(shdrs);
        }
    }

    if (!mmap_addr) {
        __android_log_print(ANDROID_LOG_ERROR, "LionInjector", "mmap not found");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    __android_log_print(ANDROID_LOG_INFO, "LionInjector", "mmap=0x%" PRIx64, mmap_addr);

    // Allocate 0x1000 in target via mmap(nullptr, 0x1000, PROT_RW, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    regs.regs[0] = 0;       // x0 = addr
    regs.regs[1] = 0x1000;  // x1 = len
    regs.regs[2] = 3;       // x2 = PROT_READ | PROT_WRITE
    regs.regs[3] = 0x22;    // x3 = MAP_PRIVATE | MAP_ANONYMOUS
    regs.regs[4] = (uint64_t)-1;  // x4 = fd
    regs.regs[5] = 0;       // x5 = offset
    regs.pc = mmap_addr;
    regs.regs[30] = 0;      // LR = 0 (intentional SIGSEGV to stop)
    if (write_regs(pid, &regs) != 0) { perror("write regs"); ptrace(PTRACE_DETACH, pid, 0, 0); return 1; }
    ptrace(PTRACE_CONT, pid, 0, 0);
    int status;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
        read_regs(pid, &regs);
    }
    uint64_t str_addr = regs.regs[0];
    __android_log_print(ANDROID_LOG_INFO, "LionInjector", "str_addr=0x%" PRIx64, str_addr);

    // Write payload path
    if (write_remote(pid, str_addr, payload, strlen(payload) + 1) != 0) {
        perror("write_remote path");
        write_regs(pid, &saved_regs);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }

    // Call dlopen(str_addr, RTLD_NOW)
    regs = saved_regs;
    regs.regs[0] = str_addr;  // x0 = path
    regs.regs[1] = 2;         // x1 = RTLD_NOW
    regs.pc = dlopen_addr;
    regs.regs[30] = 0;
    if (write_regs(pid, &regs) != 0) { perror("write regs 2"); ptrace(PTRACE_DETACH, pid, 0, 0); return 1; }
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
        read_regs(pid, &regs);
        __android_log_print(ANDROID_LOG_INFO, "LionInjector", "dlopen ret=0x%" PRIx64, regs.regs[0]);
    }

    // Restore
    write_regs(pid, &saved_regs);
    ptrace(PTRACE_DETACH, pid, 0, 0);
#endif

    __android_log_print(ANDROID_LOG_INFO, "LionInjector", "done");
    return 0;
}
