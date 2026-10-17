#include <jni.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <android/log.h>
#include <dlfcn.h>
#include "zygisk.hpp"

#define LOG_TAG "LionZygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

static const char* TARGET_PKGS[] = {
    "com.dts.freefireth",
    "com.dts.freefiremax",
    nullptr
};

class LionModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        LOGI("=== LionZygisk: onLoad ===");
        this->api_ = api;
        this->env_ = env;
    }
    
    void preAppSpecialize(AppSpecializeArgs* args) override {
        LOGI("=== LionZygisk: preAppSpecialize ===");
        is_target_ = false;
        if (!args->nice_name) return;
        
        const char* process = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (process) {
            for (int i = 0; TARGET_PKGS[i]; i++) {
                if (strcmp(process, TARGET_PKGS[i]) == 0) {
                    is_target_ = true;
                    LOGI("Target detected: %s", process);
                    break;
                }
            }
            env_->ReleaseStringUTFChars(args->nice_name, process);
        }
        
        if (is_target_) {
            api_->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        }
    }
    
    void postAppSpecialize(const AppSpecializeArgs* args) override {
        LOGI("=== LionZygisk: postAppSpecialize is_target=%d ===", is_target_);
        if (!is_target_) return;
        
        LOGI("=== LionZygisk: Injecting libmain.so ===");
        
        int dir_fd = api_->getModuleDir();
        if (dir_fd < 0) {
            LOGE("Failed to get module dir (fd=%d)", dir_fd);
            return;
        }
        
        const char* abi_path;
        #if defined(__aarch64__)
        abi_path = "/proc/self/fd/%d/zygisk/arm64-v8a/libmain.so";
        #elif defined(__arm__)
        abi_path = "/proc/self/fd/%d/zygisk/armeabi-v7a/libmain.so";
        #else
        LOGE("Unsupported ABI");
        return;
        #endif
        
        char path[256];
        snprintf(path, sizeof(path), abi_path, dir_fd);
        
        LOGI("Loading: %s", path);
        
        void* handle = dlopen(path, RTLD_NOW);
        if (!handle) {
            LOGE("Failed to dlopen: %s", dlerror());
            return;
        }
        
        LOGI("=== libmain.so loaded successfully ===");

        typedef void (*hack_fn)();
        hack_fn hack = (hack_fn)dlsym(handle, "hack");
        if (hack) {
            LOGI("=== Calling hack() ===");
            hack();
        } else {
            LOGE("=== hack() symbol not found: %s ===", dlerror());
        }
    }
    
private:
    Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
    bool is_target_ = false;
};

REGISTER_ZYGISK_MODULE(LionModule)
