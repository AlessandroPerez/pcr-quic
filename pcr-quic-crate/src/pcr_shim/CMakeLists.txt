# PCR-QUIC Crypto Shim - CMake build configuration
#
# This builds the C crypto shim library that wraps BoringSSL functions
# for use by the Rust PCR-QUIC implementation.

cmake_minimum_required(VERSION 3.10)
project(pcr_crypto_shim C)

# Options
option(PCR_USE_MLKEM768 "Enable ML-KEM-768 support via liboqs" OFF)

# Find BoringSSL (should be built by quiche's build system)
# The parent quiche build.rs will set BORINGSSL_ROOT_DIR
if(NOT DEFINED BORINGSSL_ROOT_DIR)
    # Default to quiche's deps/boringssl
    get_filename_component(BORINGSSL_ROOT_DIR 
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../deps/boringssl" ABSOLUTE)
endif()

# BoringSSL include directory
set(BORINGSSL_INCLUDE_DIR "${BORINGSSL_ROOT_DIR}/src/include")

# Source files
set(PCR_SHIM_SOURCES
    crypto_shim.c
)

set(PCR_SHIM_HEADERS
    crypto_shim.h
)

# Create static library
add_library(pcr_crypto_shim STATIC ${PCR_SHIM_SOURCES} ${PCR_SHIM_HEADERS})

# Include directories
target_include_directories(pcr_crypto_shim
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${BORINGSSL_INCLUDE_DIR}
)

# Compiler options
target_compile_options(pcr_crypto_shim PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -fPIC
)

# ML-KEM-768 support via liboqs
if(PCR_USE_MLKEM768)
    target_compile_definitions(pcr_crypto_shim PRIVATE PCR_USE_MLKEM768)
    
    # Find liboqs
    find_package(liboqs QUIET)
    if(liboqs_FOUND)
        target_link_libraries(pcr_crypto_shim PRIVATE liboqs::oqs)
    else()
        # Try pkg-config
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(LIBOQS REQUIRED liboqs)
        target_include_directories(pcr_crypto_shim PRIVATE ${LIBOQS_INCLUDE_DIRS})
        target_link_directories(pcr_crypto_shim PRIVATE ${LIBOQS_LIBRARY_DIRS})
        target_link_libraries(pcr_crypto_shim PRIVATE ${LIBOQS_LIBRARIES})
    endif()
endif()

# Install targets
install(TARGETS pcr_crypto_shim
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${PCR_SHIM_HEADERS}
    DESTINATION include/pcr_crypto_shim
)
