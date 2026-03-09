cmake_minimum_required(VERSION 3.20)
project(ht68fb_idp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED IDA_SDK_DIR)
  message(FATAL_ERROR "Set -DIDA_SDK_DIR=/path/to/idasdk")
endif()

add_library(ht68fb MODULE
  proc.cpp
  ana.cpp
  emu.cpp
  out.cpp
  ins.cpp
  reg.cpp
)

target_include_directories(ht68fb PRIVATE
  ${IDA_SDK_DIR}/include
)

target_compile_definitions(ht68fb PRIVATE
  __IDP__
  __NT__
  __X64__
  __EA64__
)

if(WIN32)
  target_link_libraries(ht68fb PRIVATE
    ${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib
  )
  if(MSVC)
    target_link_options(ht68fb PRIVATE /EXPORT:LPH)
  endif()
endif()

if(MSVC)
  target_compile_options(ht68fb PRIVATE /W4)
else()
  target_compile_options(ht68fb PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(ht68fb PROPERTIES
  PREFIX ""
  OUTPUT_NAME "ht68fb"
)
