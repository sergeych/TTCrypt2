TARGET_PREFER_32_BIT := true

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
 
# C++11 and threading enabling features. 
LOCAL_CPPFLAGS := -std=c++11 -pthread -Ithrift/ -O3

ifeq ($(TARGET_ARCH_ABI), armeabi)
    LOCAL_CPPFLAGS += -DNO_FUTURE
endif

# rtti and exceptions features
LOCAL_CPP_FEATURES := rtti exceptions

LOCAL_ARM_MODE := arm
 
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../.. 
 
LOCAL_MODULE    := ttcrypt
LOCAL_SRC_FILES := RsaKey.cpp ttcrypt/big_integer.cpp ttcrypt/byte_buffer.cpp ttcrypt/common_utils.cpp
LOCAL_SRC_FILES += ttcrypt/pollard_rho.cpp ttcrypt/rsa_key.cpp ttcrypt/text_utils.cpp ttcrypt/ttcrypt.cpp
LOCAL_SRC_FILES += ttcrypt/sha1.cpp ttcrypt/sha256.c

LOCAL_SHARED_LIBRARIES = gmp

LOCAL_LDLIBS := -llog 

include $(BUILD_SHARED_LIBRARY)

include $(LOCAL_PATH)/gmp/Android.mk
