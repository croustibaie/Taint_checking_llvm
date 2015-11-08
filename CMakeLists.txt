cmake_minimum_required(VERSION 3.3)

set(CMAKE_CXX_FLAGS "-std=c++11 -fno-rtti")

find_package(LLVM REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_subdirectory(ASBDetection)
