#BUILD WITH:
#
# NDK_PROJECT_PATH=FULL_PATH/opensc-java/jni/src/ ndk-build -C FULL_PATH/opensc-java/jni/src -j4 NDK_APPLICATION_MK=FULL_PATH/opensc-java/jni/build/android/Application.mk -B V=1 NDK_DEBUG=1
#
# assuming you have 4 cores in the system and you build in the same directory as the Android.mk file

LOCAL_PATH := $(NDK_PROJECT_PATH) # Use NDK_PROJECT_PATH to determine directory with source

# Included in comments is an example on how to also include prebuilt libraries that will provide the PKCS11
# functionality. These cannot be loaded dynamically in android but have to be "pre-included" when building the jni.
# The android linker will then automatically load the libraries providing the PKCS11 native functionality.
##############
# Build any dependency mylib_prebuilt might have first.
##############
#include $(CLEAR_VARS)

#LOCAL_MODULE := mylib_prebuilt_dependency
#LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/prebuilt_libs/mylib_prebuilt_dependency_include
#LOCAL_SRC_FILES := $(LOCAL_PATH)/prebuilt_libs/$(TARGET_ARCH_ABI)/libmylib_prebuilt_dependency.so
#$(info $(LOCAL_SRC_FILES))

#include $(PREBUILT_SHARED_LIBRARY)

#####################
# Build mylib_prebuilt
#####################
#include $(CLEAR_VARS)

#LOCAL_MODULE := mylib_prebuilt
#LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/prebuilt_libs/mylib_prebuilt_include
#LOCAL_SRC_FILES := $(LOCAL_PATH)/prebuilt_libs/$(TARGET_ARCH_ABI)/mylib_prebuilt.so

#include $(PREBUILT_SHARED_LIBRARY)

####################
# Build OpenSC JNI bindings
####################
include $(CLEAR_VARS)

LOCAL_MODULE := libOpenSCjniAndroid

LOCAL_C_INCLUDES := $(LOCAL_PATH) \
					$(LOCAL_PATH)/jniP11 \
					$(LOCAL_PATH)/jniP11/opensc \
					$(LOCAL_PATH)/jnix

# include all c files in subdirs
PROJECT_FILES := $(wildcard $(LOCAL_PATH)/*.c)
PROJECT_FILES += $(wildcard $(LOCAL_PATH)/**/*.c)
PROJECT_FILES += $(wildcard $(LOCAL_PATH)/**/**/*.c)

PROJECT_FILES := $(PROJECT_FILES:$(LOCAL_PATH)/%=%)

LOCAL_SRC_FILES := $(PROJECT_FILES)

LOCAL_CFLAGS := -rdynamic -DANDROID -DOT_LOGGING

LOCAL_SHARED_LIBRARIES := libcutils libc libdl # mylib_prebuilt #mylib_prebuilt_dependency
LOCAL_STATIC_LIBRARIES := libstlport

LOCAL_LDLIBS := -llog

#ifeq ($(TARGET_ARCH),arm)
# might be necessary if errors occur only on arm
#LOCAL_LDFLAGS := -Wl,--hash-style=sysv
#endif

include $(BUILD_SHARED_LIBRARY)
