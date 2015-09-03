APP_STL := gnustl_static
APP_PLATFORM := android-21
APP_ABI := armeabi armeabi-v7a x86 #all
APP_CFLAGS := -g -Wall -O2

APP_BUILD_SCRIPT := ../build/android/Android.mk #assumes it's in the jni/src directory
NDK_TOOLCHAIN_VERSION := 4.9
