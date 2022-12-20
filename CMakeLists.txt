cmake_minimum_required (VERSION 2.8)
project (rkcrypto C)

################################################################################
# toolchain config
################################################################################
set (CMAKE_SYSTEM_NAME Linux)

if (NOT DEFINED CMAKE_C_COMPILER)
	message(FATAL_ERROR "librkcrypto: CMAKE_C_COMPILER not define")
endif()

if (NOT DEFINED CMAKE_CXX_COMPILER)
	message(FATAL_ERROR "librkcrypto: CMAKE_CXX_COMPILER not define")
endif()

################################################################################
# compile flags
################################################################################
add_compile_options(-Wall -Werror)
add_compile_options(-Wno-unused-function)
add_compile_options(-Wno-unused-parameter)
add_compile_options(-Wno-format-truncation)
add_compile_options(-Wno-maybe-uninitialized)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING
	"Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
	FORCE)
endif(NOT CMAKE_BUILD_TYPE)

################################################################################
# librkcrypto files
################################################################################
include_directories(include)
file(GLOB SOURCES "src/*.c")

################################################################################
# libdrm dependencies
################################################################################
include_directories(third_party/libdrm/include)
include_directories(third_party/libdrm/include/drm)
file(GLOB SOURCES_DRM "third_party/libdrm/src/*.c")
add_definitions(-DMAJOR_IN_SYSMACROS=1 -D_GNU_SOURCE)

################################################################################
# libteec dependencies
################################################################################
add_definitions(-DBINARY_PREFIX=\"TEEC\")
set(TEEC_PATH third_party/optee_client/libteec)
include_directories(${TEEC_PATH}/../public ${TEEC_PATH}/include)
file(GLOB SOURCES_TEEC
	${TEEC_PATH}/src/tee_client_api.c
	${TEEC_PATH}/src/teec_trace.c)

################################################################################
# build librkcrypto shared library
################################################################################
add_library(rkcrypto SHARED ${SOURCES} ${SOURCES_DRM} ${SOURCES_TEEC})

################################################################################
# build librkcrypto static library
################################################################################
add_library(rkcrypto_static STATIC ${SOURCES} ${SOURCES_DRM} ${SOURCES_TEEC})
SET_TARGET_PROPERTIES (rkcrypto_static PROPERTIES OUTPUT_NAME "rkcrypto")

################################################################################
# build other components
################################################################################
add_subdirectory(test)
