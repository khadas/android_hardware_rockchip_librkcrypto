cmake_minimum_required (VERSION 2.8)

set (CMAKE_SYSTEM_NAME Linux)

if (BUILD STREQUAL 64)
	set (CMAKE_SYSTEM_PROCESSOR aarch64)
else ()
	set(CMAKE_SYSTEM_PROCESSOR arm)
endif ()

set (TOOLCHAIN_PREBUILTS "${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilts")
set (TOOLCHAIN_PATH_ARM32 "gcc/linux-x86/arm/gcc-arm-10.2-2020.11-x86_64-arm-none-linux-gnueabihf/bin")
set (TOOLCHAIN_PATH_AARCH64 "gcc/linux-x86/aarch64/gcc-arm-10.2-2020.11-x86_64-aarch64-none-linux-gnu/bin")
set (CROSS_COMPILE32 "arm-none-linux-gnueabihf-gcc")
set (CROSS_COMPILE64 "aarch64-none-linux-gnu-gcc")
set (CROSS_COMPILE32_GXX "arm-none-linux-gnueabihf-g++")
set (CROSS_COMPILE64_GXX "aarch64-none-linux-gnu-g++")
set (AARCH64_TOOLCHAIN_GCC "${TOOLCHAIN_PREBUILTS}/${TOOLCHAIN_PATH_AARCH64}/${CROSS_COMPILE64}")
set (AARCH64_TOOLCHAIN_GXX "${TOOLCHAIN_PREBUILTS}/${TOOLCHAIN_PATH_AARCH64}/${CROSS_COMPILE64_GXX}")
set (ARM32_TOOLCHAIN_GCC "${TOOLCHAIN_PREBUILTS}/${TOOLCHAIN_PATH_ARM32}/${CROSS_COMPILE32}")
set (ARM32_TOOLCHAIN_GXX "${TOOLCHAIN_PREBUILTS}/${TOOLCHAIN_PATH_ARM32}/${CROSS_COMPILE32_GXX}")

if (CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64)
	set (CMAKE_C_COMPILER ${AARCH64_TOOLCHAIN_GCC})
	set (CMAKE_CXX_COMPILER ${AARCH64_TOOLCHAIN_GXX})
	set (ARM_PLATFORM "arm64")
else ()
	set (CMAKE_C_COMPILER ${ARM32_TOOLCHAIN_GCC})
	set (CMAKE_CXX_COMPILER ${ARM32_TOOLCHAIN_GXX})
	set (ARM_PLATFORM "arm")
endif ()

project (rkcrypto C)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING
	"Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
	FORCE)
endif(NOT CMAKE_BUILD_TYPE)

include_directories(include)
include_directories(third_party/libdrm)
file(GLOB SOURCES "src/*.c")

add_library(rkcrypto SHARED ${SOURCES})

target_link_libraries(rkcrypto dl)

add_subdirectory(demo)

add_subdirectory(test)
