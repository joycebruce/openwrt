cmake_minimum_required(VERSION 2.8)

project(nvs C)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -I.)

INCLUDE_DIRECTORIES(
        ${CMAKE_CURRENT_SOURCE_DIR}
)

SET(NVS_LIB_NAME "nvs")

set(nvs_src nvs.c)

ADD_LIBRARY(${NVS_LIB_NAME} SHARED ${nvs_src})

INSTALL(FILES nvs.h DESTINATION include)

INSTALL(TARGETS nvs
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        )