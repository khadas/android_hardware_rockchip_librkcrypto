LOCAL_PATH:= $(call my-dir)

ifeq (1,$(strip $(shell expr $(PLATFORM_VERSION) \>= 11)))
ifeq ($(strip $(TARGET_ARCH)), arm64)
	CLIENT_LIB_PATH ?= $(shell pwd)/hardware/rockchip/optee/v2/arm64
else
	CLIENT_LIB_PATH ?= $(shell pwd)/hardware/rockchip/optee/v2/arm
endif
else
ifeq ($(strip $(TARGET_ARCH)), arm64)
	CLIENT_LIB_PATH ?= $(shell pwd)/vendor/rockchip/common/security/optee/v2/lib/arm64
else
	CLIENT_LIB_PATH ?= $(shell pwd)/vendor/rockchip/common/security/optee/v2/lib/arm
endif
endif

include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD -DUSER_SPACE -DMAJOR_IN_SYSMACROS=1 -D_GNU_SOURCE
LOCAL_CFLAGS += -Wall  -Wno-error -Wno-enum-conversion -Wno-unused-parameter

LOCAL_LDFLAGS += -ldl
LOCAL_LDFLAGS += -llog

SRC_FILES_DIR := $(wildcard $(LOCAL_PATH)/src/*.c)
SRC_FILES_DIR += $(wildcard $(LOCAL_PATH)/third_party/libdrm/src/*.c)
LOCAL_SRC_FILES := $(SRC_FILES_DIR:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/third_party/libdrm/include \
                    $(LOCAL_PATH)/third_party/libdrm/include/drm \

LOCAL_MODULE:= librkcrypto
LOCAL_MODULE_TAGS := optional

ifeq ($(strip $(TARGET_ARCH)), arm64)
	LOCAL_MULTILIB := 64
else
	LOCAL_MULTILIB := 32
endif

LOCAL_VENDOR_MODULE := true
include $(BUILD_SHARED_LIBRARY)

# Build the Android.mk in all sub-dir
include $(call all-makefiles-under, $(LOCAL_PATH))