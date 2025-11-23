cmake_minimum_required(VERSION 3.10)
project(OverProto VERSION 1.0.0 
    HOMEPAGE_URL "https://github.com/nickolajgrishuk/overproto"
    LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fdata-sections")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fomit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fno-unwind-tables")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fno-asynchronous-unwind-tables")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fvisibility=hidden")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fmerge-constants")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now")

option(OVERPROTO_STRIP_SYMBOLS "Strip symbols from release builds (reduces size)" OFF)
if(OVERPROTO_STRIP_SYMBOLS)
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -s")
endif()


find_package(Threads REQUIRED)

set(OVERPROTO_PUBLIC_HEADERS
    src/include/overproto.h
)

set(OVERPROTO_PRIVATE_HEADERS
    src/core/common.h
    src/core/crc32.h
    src/core/packet.h
    src/core/fragment.h
    src/transport/tcp.h
    src/transport/udp.h
    src/transport/reliable.h
    src/optimize/compress.h
    src/optimize/crypto.h
)

set(OVERPROTO_SOURCES
    src/core/crc32.c
    src/core/packet.c
    src/core/fragment.c
    src/transport/tcp.c
    src/transport/udp.c
    src/transport/reliable.c
    src/optimize/compress.c
    src/optimize/crypto.c
    src/api/overproto.c
)

add_library(overproto STATIC ${OVERPROTO_SOURCES})


set_target_properties(overproto PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    PUBLIC_HEADER "${OVERPROTO_PUBLIC_HEADERS}"
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

target_include_directories(overproto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/include>
        $<INSTALL_INTERFACE:include/overproto>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/optimize
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api
)

target_link_libraries(overproto
    PUBLIC
        Threads::Threads
)

install(FILES ${OVERPROTO_PUBLIC_HEADERS}
    DESTINATION include/overproto
)

install(TARGETS overproto
    EXPORT OverProtoTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(EXPORT OverProtoTargets
    FILE OverProtoTargets.cmake
    NAMESPACE OverProto::
    DESTINATION lib/cmake/OverProto
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/OverProtoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/OverProtoConfigVersion.cmake"
    DESTINATION lib/cmake/OverProto
)

option(OVERPROTO_WITH_ZLIB "Enable zlib compression support" ON)
option(OVERPROTO_WITH_OPENSSL "Enable OpenSSL encryption support" OFF)

if(OVERPROTO_WITH_ZLIB)
    find_package(ZLIB)
    if(ZLIB_FOUND)
        target_compile_definitions(overproto PRIVATE OVERPROTO_USE_ZLIB)
        target_link_libraries(overproto PUBLIC ZLIB::ZLIB)
        message(STATUS "OverProto: zlib support enabled")
    else()
        message(WARNING "OverProto: zlib requested but not found - compression disabled")
        target_compile_definitions(overproto PRIVATE OVERPROTO_DISABLE_ZLIB)
    endif()
else()
    target_compile_definitions(overproto PRIVATE OVERPROTO_DISABLE_ZLIB)
    message(STATUS "OverProto: zlib support disabled")
endif()

if(OVERPROTO_WITH_OPENSSL)
    find_package(OpenSSL)
    if(OpenSSL_FOUND)
        target_compile_definitions(overproto PRIVATE OVERPROTO_USE_OPENSSL)
        target_link_libraries(overproto PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        message(STATUS "OverProto: OpenSSL support enabled")
    else()
        message(WARNING "OverProto: OpenSSL requested but not found - encryption disabled")
        target_compile_definitions(overproto PRIVATE OVERPROTO_DISABLE_OPENSSL)
    endif()
else()
    target_compile_definitions(overproto PRIVATE OVERPROTO_DISABLE_OPENSSL)
    message(STATUS "OverProto: OpenSSL support disabled")
endif()

option(OVERPROTO_BUILD_EXAMPLES "Build example programs" OFF)

if(OVERPROTO_BUILD_EXAMPLES)
    add_executable(overproto_server examples/simple_server.c)
    target_link_libraries(overproto_server PRIVATE overproto)
    
    add_executable(overproto_client examples/simple_client.c)
    target_link_libraries(overproto_client PRIVATE overproto)
    
    message(STATUS "OverProto: examples enabled")
endif()

message(STATUS "OverProto version: ${PROJECT_VERSION}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C standard: ${CMAKE_C_STANDARD}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")