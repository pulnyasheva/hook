cmake_minimum_required(VERSION 3.22.1)

project("monitoring")

set(LIB_ROOT_DIR "../../../..")
set(MONITOR_HOOK_DIR ${LIB_ROOT_DIR}/monitoringHook)

include_directories(${MONITOR_HOOK_DIR}/include)
include_directories(${MONITOR_HOOK_DIR}/openssl/include)
link_directories(${LIB_ROOT_DIR}/libs)

add_library(memory SHARED IMPORTED)
set_target_properties(memory PROPERTIES IMPORTED_LOCATION ${LIB_ROOT_DIR}/libs/libmemory.so)

add_library(ssl SHARED IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION ${MONITOR_HOOK_DIR}/openssl/lib/arm64-v8a/libssl.so)

add_library(crypto SHARED IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${MONITOR_HOOK_DIR}/openssl/lib/arm64-v8a/libcrypto.so)

add_library(inline SHARED IMPORTED)
set_target_properties(inline PROPERTIES IMPORTED_LOCATION ${LIB_ROOT_DIR}/libs/libinline.so)

add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES IMPORTED_LOCATION ${MONITOR_HOOK_DIR}/shadowhook/lib/arm64-v8a/libshadowhook.so)

add_library(${CMAKE_PROJECT_NAME} SHARED
        example.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        inline
        shadowhook
        memory
        ssl
        crypto)