LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD -DUSER_SPACE -Wno-typedef-redefinition
LOCAL_CFLAGS += -Wall
LOCAL_LDFLAGS += -llog

SRC_FILES_DIR := $(wildcard $(LOCAL_PATH)/*.c)

LOCAL_SRC_FILES += $(SRC_FILES_DIR:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include \
		$(LOCAL_PATH)/include \

LOCAL_LDFLAGS += -lrkcrypto
LOCAL_STATIC_LIBRARIES := libc_mode

LOCAL_MODULE := librkcrypto_test
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true
include $(BUILD_EXECUTABLE)

# Build test c_mode
include $(LOCAL_PATH)/c_mode/Android.mk