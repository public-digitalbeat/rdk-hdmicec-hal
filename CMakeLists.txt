cmake_minimum_required (VERSION 2.6)

Project(HDMICEC_HAL)

set(CMAKE_BUILD_TYPE "Debug")

find_path (STAGING_INCDIR glib-2.0)

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${STAGING_INCDIR})
include_directories(${STAGING_INCDIR}/rdk/iarmbus)
include_directories(${STAGING_INCDIR}/rdk/iarmmgrs-hal)

set (HDMICEC_HAL_SOURCES ${CMAKE_SOURCE_DIR}/hdmi_cec_driver.c)
set (ARC_TEST_APP_SOURCES ${CMAKE_SOURCE_DIR}/arc-test.c)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-attributes -Wall -Wextra -fpermissive")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-attributes -Wall -Wextra -fpermissive -std=c++11")

add_executable(arc-test ${ARC_TEST_APP_SOURCES})
add_library(RCECHal SHARED ${HDMICEC_HAL_SOURCES})
target_link_libraries(RCECHal "-lpthread -lIARMBus")
target_link_libraries(arc-test "-lpthread")

install(TARGETS RCECHal DESTINATION lib)
