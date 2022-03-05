cmake_minimum_required (VERSION 2.8)
project (pinjectra)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

add_executable(TestProcess TestProcess/TestProcess.c)

INSTALL( TARGETS TestProcess DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
