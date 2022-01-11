cmake_minimum_required(VERSION 3.10)  # bionic's cmake version

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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


project(lokinet-win32
  VERSION 0.0.1
  DESCRIPTION "lokinet win32 platform bits - MSVC is an abomination"
  LANGUAGES ${LANGS})

include(CheckCXXSourceCompiles)
include(CheckLibraryExists)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(lokinet_win32
  STATIC
  src/lokinet_wfp.cpp)

target_include_directories(lokinet_win32
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(wfp_files
  libwfp/conditionbuilder.cpp
  libwfp/sublayerbuilder.cpp
  libwfp/internal/conditionassembler.cpp
  libwfp/ipnetwork.cpp
  libwfp/filterbuilder.cpp
  libwfp/ipaddress.cpp
  libwfp/objectexplorer.cpp
  libwfp/objectinstaller.cpp
  libwfp/providerbuilder.cpp
  libwfp/filterengine.cpp
  libwfp/objectmonitor.cpp
  libwfp/objectenumerator.cpp
  libwfp/conditions/conditionip.cpp
  libwfp/conditions/conditionport.cpp
  libwfp/conditions/conditionportrange.cpp
  libwfp/conditions/conditionicmp.cpp
  libwfp/conditions/conditiondirection.cpp
  libwfp/conditions/conditionapplication.cpp
  libwfp/conditions/conditionprotocol.cpp
  libwfp/conditions/conditioninterface.cpp
  libwfp/conditions/conditionloopback.cpp
  libwfp/objectdeleter.cpp
  libwfp/transaction.cpp
  libwfp/stdafx.cpp
  libwfp/layerconditions.cpp)

set(wfp_root
  ${CMAKE_CURRENT_SOURCE_DIR}/libwfp/src/)

list(TRANSFORM wfp_files PREPEND ${wfp_root})

set(common_files
  libcommon/fileenumerator.cpp
  libcommon/process/process.cpp
  libcommon/process/applicationrunner.cpp
  libcommon/logging/logsink.cpp
  libcommon/registry/registrykey.cpp
  libcommon/registry/registry.cpp
  libcommon/registry/registrymonitor.cpp
  libcommon/registry/registrypath.cpp
  libcommon/filesystem.cpp
  libcommon/string.cpp
  libcommon/trace/consoletracesink.cpp
  libcommon/trace/trace.cpp
  libcommon/trace/filetracesink.cpp
  libcommon/serialization/deserializer.cpp
  libcommon/serialization/serializer.cpp
  libcommon/binarycomposer.cpp
  libcommon/security.cpp
  libcommon/guid.cpp
  libcommon/network.cpp
  libcommon/burstguard.cpp
  libcommon/error.cpp
  libcommon/resourcedata.cpp
  libcommon/stdafx.cpp
  libcommon/network/adapters.cpp)


set(common_root
  ${CMAKE_CURRENT_SOURCE_DIR}/windows-libraries/src/)

list(TRANSFORM common_files PREPEND ${common_root})

add_library(mullvad_common
  STATIC
  ${common_files})

add_library(mullvad_wfp
  STATIC
  ${wfp_files})

target_include_directories(mullvad_common
  PUBLIC
  ${common_root}/libcommon
  ${common_root})

target_include_directories(mullvad_wfp
  PUBLIC
  ${wfp_root}/libwfp
  ${wfp_root})

target_link_libraries(mullvad_wfp
  PUBLIC
  mullvad_common)

target_link_libraries(lokinet_win32
  PRIVATE
  mullvad_wfp)
