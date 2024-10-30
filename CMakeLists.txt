cmake_minimum_required(VERSION 3.22.1)
project("memory")

set(ROOT_DIR "monitoringHook")
set(OPENSSL_ROOT_DIR ${ROOT_DIR}/openssl)

include_directories(${OPENSSL_ROOT_DIR}/include)
include_directories(${ROOT_DIR}/include)

link_directories(${OPENSSL_ROOT_DIR}/lib/arm64-v8a)

add_library(ssl SHARED IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION ${OPENSSL_ROOT_DIR}/lib/arm64-v8a/libssl.so)

add_library(crypto SHARED IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_ROOT_DIR}/lib/arm64-v8a/libcrypto.so)

add_library(${CMAKE_PROJECT_NAME} SHARED
        ${ROOT_DIR}/Common.cpp
        ${ROOT_DIR}/InlineHook.cpp
        ${ROOT_DIR}/GotPltHook.cpp
        ${ROOT_DIR}/Tracker.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        ssl
        crypto)

option(BUILD_INLINE_TEST "Build inline test" OFF)
option(BUILD_GOTPLT_TEST "Build gotplt test" OFF)

set(SHADOWHOOK_ROOT_DIR ${ROOT_DIR}/shadowhook)

include_directories(${SHADOWHOOK_ROOT_DIR}/include)
link_directories(${SHADOWHOOK_ROOT_DIR}/lib/arm64-v8a)

add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES IMPORTED_LOCATION ${SHADOWHOOK_ROOT_DIR}/lib/arm64-v8a/libshadowhook.so)

if(BUILD_INLINE_TEST)
    add_library(inline SHARED ${ROOT_DIR}/Inline.cpp)
    target_link_libraries(inline log shadowhook)
endif()

set(BYTEHOOK_ROOT_DIR ${ROOT_DIR}/bytehook)

include_directories(${BYTEHOOK_ROOT_DIR}/include)
link_directories(${BYTEHOOK_ROOT_DIR}/lib/arm64-v8a)

add_library(bytehook SHARED IMPORTED)
set_target_properties(bytehook PROPERTIES IMPORTED_LOCATION ${BYTEHOOK_ROOT_DIR}/lib/arm64-v8a/libbytehook.so)

if(BUILD_GOTPLT_TEST)
    add_library(gotplt SHARED ${ROOT_DIR}/GotPlt.cpp)
    target_link_libraries(gotplt log bytehook)
endif()
