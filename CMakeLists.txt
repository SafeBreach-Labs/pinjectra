cmake_minimum_required (VERSION 3.13)
project (pinjectra)

add_executable(TestProcess TestProcess/TestProcess.c)

# ------------------------------------------------------------------------------
# Added below to support static linking of the TestProcess binary in Windows.
# ------------------------------------------------------------------------------

target_compile_options(
  TestProcess
  PRIVATE /MT
)

target_link_options(
  TestProcess
  PRIVATE /INCREMENTAL:NO
  PRIVATE /NODEFAULTLIB:MSVCRT
)

# ------------------------------------------------------------------------------

INSTALL(
  TARGETS TestProcess
  DESTINATION ${CMAKE_INSTALL_PREFIX}
  COMPONENT ${PROJECT_NAME}
)
