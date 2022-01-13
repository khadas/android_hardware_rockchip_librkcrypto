LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD -DUSER_SPACE -DMAJOR_IN_SYSMACROS=1 -D_GNU_SOURCE
LOCAL_CFLAGS += -Wall  -Wno-error -Wno-enum-conversion -Wno-unused-parameter

# micro define for libteec
LOCAL_CFLAGS += -DBINARY_PREFIX=\"TEEC\"

LOCAL_LDFLAGS += -llog

TEEC_PATH := $(LOCAL_PATH)/third_party/optee_client/libteec

SRC_FILES_DIR := $(wildcard $(LOCAL_PATH)/src/*.c)
SRC_FILES_DIR += $(wildcard $(LOCAL_PATH)/third_party/libdrm/src/*.c)
SRC_FILES_DIR += $(wildcard $(TEEC_PATH)/src/tee_client_api.c)
SRC_FILES_DIR += $(wildcard $(TEEC_PATH)/src/teec_trace.c)
LOCAL_SRC_FILES := $(SRC_FILES_DIR:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/third_party/libdrm/include \
                    $(LOCAL_PATH)/third_party/libdrm/include/drm \
		    $(TEEC_PATH)/include \
		    $(TEEC_PATH)/../public

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