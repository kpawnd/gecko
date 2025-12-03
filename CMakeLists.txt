cmake_minimum_required(VERSION 3.16)
project(gecko VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(GECKO_BUILD_TESTS "Build test suite" ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX- /D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
endif()

# Platform detection
if(WIN32)
    add_compile_definitions(GECKO_WINDOWS)
    set(PLATFORM_LIBS bcrypt setupapi)
else()
    add_compile_definitions(GECKO_LINUX)
    set(PLATFORM_LIBS)
endif()

# Core library sources
set(CORE_SOURCES
    src/crypto/aes.c
    src/crypto/gcm.c
    src/crypto/sha256.c
    src/crypto/pbkdf2.c
    src/crypto/random.c
    src/vault/vault.c
    src/usb/usb.c
    src/util/util.c
)

# Create static library
add_library(gecko_core STATIC
    ${CORE_SOURCES}
)

target_include_directories(gecko_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(gecko_core PUBLIC ${PLATFORM_LIBS})

# Main executable
add_executable(gecko
    src/cli/main.c
)

target_link_libraries(gecko PRIVATE gecko_core)

# Tests (only if test files exist)
if(GECKO_BUILD_TESTS AND EXISTS "${CMAKE_SOURCE_DIR}/tests/test_crypto.c")
    enable_testing()
    
    add_executable(test_crypto
        tests/test_crypto.c
    )
    target_link_libraries(test_crypto PRIVATE gecko_core)
    add_test(NAME crypto COMMAND test_crypto)
    
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/test_vault.c")
        add_executable(test_vault
            tests/test_vault.c
        )
        target_link_libraries(test_vault PRIVATE gecko_core)
        add_test(NAME vault COMMAND test_vault)
    endif()
endif()

# Install
install(TARGETS gecko DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)
