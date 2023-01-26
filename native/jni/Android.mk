LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := zygisk_module
LOCAL_C_INCLUDES := $(LOCAL_PATH)/lsplt/src/main/jni/include
LOCAL_SRC_FILES := zygisk.cpp lsplt/src/main/jni/elf_util.cc lsplt/src/main/jni/lsplt.cc
LOCAL_STATIC_LIBRARIES := libcxx
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include jni/libcxx/Android.mk
