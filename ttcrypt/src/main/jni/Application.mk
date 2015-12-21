# use this to select gcc instead of clang
NDK_TOOLCHAIN_VERSION := 4.8
#NDK_TOOLCHAIN_VERSION := clang
# OR use this to select the latest clang version:

APP_STL := gnustl_static
# then enable c++11 extentions in source code

APP_ABI := all
#APP_ABI := x86 armeabi-v7a mips armeabi
#APP_ABI := armeabi

