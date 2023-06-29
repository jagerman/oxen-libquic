cmake_minimum_required(VERSION 3.13...3.25)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

option(BUILD_SHARED_LIBS "Build as shared library" OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LANGS C CXX)
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
	foreach(lang ${LANGS})
    	if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      		message(STATUS "Enabling ccache for ${lang}")
      		set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    	endif()
  endforeach()
endif()

project(oxen-libquic
    VERSION 0.0.5
    DESCRIPTION "Modular QUIC library for stream and connection management"
    LANGUAGES ${LANGS})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

message(STATUS "${PROJECT_NAME} v${PROJECT_VERSION}")

option(WITH_LTO "Compile with Link-time Optimization" ON)
if(WITH_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
    if(IPO_ENABLED)
        message(STATUS "LTO enabled")
    else()
        message(WARNING "LTO not supported by compiler: ${ipo_error}")
    endif()
else()
    message(STATUS "LTO disabled")
    set(IPO_ENABLED OFF)
endif()

set(IPO_ENABLED OFF)
if(IPO_ENABLED AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

include(GNUInstallDirs)

# Interface target for any general includes, flags, etc. that is meant to be inherited publicly.
add_library(common INTERFACE)
# Interface target for internal flags, include paths, etc. that are PRIVATE for project source
# compilation, but not for potential external targets that depend on us.
add_library(internal INTERFACE)

target_include_directories(common INTERFACE include)
target_include_directories(internal INTERFACE include/quic)

if(WARNINGS_AS_ERRORS)
    target_compile_options(internal INTERFACE -Werror)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(libquic_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(libquic_IS_TOPLEVEL_PROJECT FALSE)
endif()

option(LIBQUIC_BUILD_TESTS "Build libquic test suite and programs" ${libquic_IS_TOPLEVEL_PROJECT})
option(LIBQUIC_INSTALL "Install libquic headers and libraries" ${libquic_IS_TOPLEVEL_PROJECT})

configure_file(include/quic/version.hpp.in include/quic/version.hpp @ONLY)

add_subdirectory(external)
add_subdirectory(src)

if(LIBQUIC_BUILD_TESTS)
    add_subdirectory(tests)
endif()

add_library(libquic::libquic ALIAS quic)
export(
    TARGETS quic
    NAMESPACE libquic::
    FILE oxen-libquicTargets.cmake
)

if(LIBQUIC_INSTALL)
    install(
        FILES
        include/quic/connection.hpp
        include/quic/context.hpp
        include/quic/crypto.hpp
        include/quic/endpoint.hpp
        include/quic/export.h
        include/quic/gnutls_crypto.hpp
        include/quic/network.hpp
        include/quic/opt.hpp
        include/quic/stream.hpp
        include/quic/udp.hpp
        include/quic/utils.hpp
        ${CMAKE_CURRENT_BINARY_DIR}/include/quic/version.hpp

        DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}/quic
    )

    install(
        FILES include/quic.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/quic
    )

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/oxen-libquic.pc
        DESTINATION ${CMAKE_INSTALL_DATADIR}/pkgconfig
    )
endif()
