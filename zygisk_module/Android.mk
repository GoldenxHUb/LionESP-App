LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE           := zygisk
LOCAL_SRC_FILES        := zygisk.cpp
LOCAL_LDLIBS           := -llog -ldl
LOCAL_CPPFLAGS         := -std=c++17 -fno-exceptions -fno-rtti -fvisibility=hidden
LOCAL_CFLAGS           := -fvisibility=hidden
include $(BUILD_SHARED_LIBRARY)
