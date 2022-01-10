file(GLOB TEST_SOURCES "./*.c")
include_directories(include)
include_directories(c_mode)
add_executable(librkcrypto_test ${TEST_SOURCES})

target_link_libraries(librkcrypto_test c_mode)
target_link_libraries(librkcrypto_test rkcrypto)

add_subdirectory(c_mode)