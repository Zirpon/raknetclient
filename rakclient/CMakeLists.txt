cmake_minimum_required(VERSION 2.6)
project (rakclient)
FILE(GLOB_RECURSE SRC ${PROJECT_SOURCE_DIR}/*.cpp)

SET(CMAKE_C_COMPILER "gcc")
SET(CMAKE_CXX_COMPILER "g++")
SET(CMAKE_CXX_FLAGS "-std=c++11 -O2")

SET(PROJ_ROOT ${PROJECT_SOURCE_DIR})
INCLUDE_DIRECTORIES(${PROJ_ROOT})
INCLUDE_DIRECTORIES(${PROJ_ROOT}/../thirdparty/include/)
INCLUDE_DIRECTORIES(${PROJ_ROOT}/../thirdparty/include/raknet)
INCLUDE_DIRECTORIES(${PROJ_ROOT}/../thirdparty/include/lua)

LINK_DIRECTORIES(${PROJ_ROOT}/../thirdparty/lib)
add_library(rakclient SHARED ${SRC})
TARGET_LINK_LIBRARIES(rakclient raknet)
# math
TARGET_LINK_LIBRARIES(rakclient m)
# zlib
TARGET_LINK_LIBRARIES(rakclient z)
# Dynamic - link libraries : dlopen dlsym dlclose dlerror
TARGET_LINK_LIBRARIES(rakclient dl)
# Realtime Extensions library
TARGET_LINK_LIBRARIES(rakclient rt)

#add_library(rak SHARED ${SRC})

	
