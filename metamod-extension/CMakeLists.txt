cmake_minimum_required(VERSION 3.15)
project(smartbots LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- 32-bit build (Insurgency 2014 is i486) ---
add_compile_options(-m32)
add_link_options(-m32)

# --- SDK paths ---
set(HL2SDK "${CMAKE_SOURCE_DIR}/vendor/hl2sdk-insurgency" CACHE PATH "Path to HL2SDK")
set(MMSOURCE "${CMAKE_SOURCE_DIR}/vendor/metamod-source" CACHE PATH "Path to Metamod:Source")

# Validate SDKs are present (git submodule update --init)
if(NOT EXISTS "${HL2SDK}/public")
    message(FATAL_ERROR
        "HL2SDK not found at ${HL2SDK}/public\n"
        "Run: git submodule update --init --recursive")
endif()
if(NOT EXISTS "${MMSOURCE}/core")
    message(FATAL_ERROR
        "Metamod:Source not found at ${MMSOURCE}/core\n"
        "Run: git submodule update --init --recursive")
endif()

# --- Extension shared library ---
add_library(smartbots SHARED
    src/extension.cpp
    src/sig_resolve.cpp
    src/detour.cpp
    src/bot_action_hook.cpp
    src/bot_state.cpp
    src/bot_command.cpp
    src/game_events.cpp
    src/bot_voice.cpp
    src/nav_flanking.cpp
    src/nav_objectives.cpp
    src/bot_tactics.cpp
    src/bot_trace.cpp
)

set_target_properties(smartbots PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)

# --- Include paths ---
target_include_directories(smartbots PRIVATE
    src

    # Metamod:Source
    ${MMSOURCE}/core
    ${MMSOURCE}/core/sourcehook

    # HL2SDK
    ${HL2SDK}/public
    ${HL2SDK}/public/engine
    ${HL2SDK}/public/mathlib
    ${HL2SDK}/public/vstdlib
    ${HL2SDK}/public/tier0
    ${HL2SDK}/public/tier1
    ${HL2SDK}/public/game/server
)

# --- Compiler definitions ---
target_compile_definitions(smartbots PRIVATE
    # Source engine version (SDK2013 = Insurgency 2014)
    SOURCE_ENGINE=14
    SE_EPISODEONE=1
    SE_DARKMESSIAH=2
    SE_ORANGEBOX=3
    SE_BLOODYGOODTIME=4
    SE_EYE=5
    SE_CSS=6
    SE_ORANGEBOXVALVE=7
    SE_LEFT4DEAD=8
    SE_LEFT4DEAD2=9
    SE_ALIENSWARM=10
    SE_PORTAL2=11
    SE_CSGO=12
    SE_SDK2013=14

    # Platform
    POSIX
    _LINUX
    LINUX
    GNUC
    COMPILER_GCC

    # libc compat
    stricmp=strcasecmp
    _stricmp=strcasecmp
    strnicmp=strncasecmp
    _strnicmp=strncasecmp
    _snprintf=snprintf
    _vsnprintf=vsnprintf

    HAVE_STDINT_H
    META_NO_HL2SDK                    # Use Metamod's own CreateInterface (has visibility attr)
    META_IS_SOURCE2=0
)

# --- Compiler flags ---
target_compile_options(smartbots PRIVATE
    -Wall
    -Wno-non-virtual-dtor
    -Wno-overloaded-virtual
    -Wno-class-memaccess
    -Wno-register
    -fpermissive              # HL2SDK headers have implicit include-order dependencies
    -fno-strict-aliasing      # SDK uses type-punning extensively
    -fno-exceptions
    -fno-rtti
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -pipe
)

# --- HL2SDK libraries ---
set(HL2SDK_LIB "${HL2SDK}/lib/linux")

# Static libraries from SDK (tier1 provides ConVar/ConCommandBase, interfaces for Insurgency SDK)
target_link_libraries(smartbots PRIVATE
    ${HL2SDK_LIB}/tier1_i486.a
    ${HL2SDK_LIB}/interfaces_i486.a
)

# Dynamic libraries resolved at runtime from the game server
target_link_libraries(smartbots PRIVATE
    ${HL2SDK_LIB}/libtier0_srv.so
    ${HL2SDK_LIB}/libvstdlib_srv.so
)

# --- Linker ---
target_link_options(smartbots PRIVATE
    -static-libgcc
    -static-libstdc++
)

target_link_libraries(smartbots PRIVATE
    dl
)
