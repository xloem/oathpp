cmake_minimum_required (VERSION 2.6)
project (oath++)

find_package(PkgConfig REQUIRED)
pkg_check_modules(OATH REQUIRED liboath)

set (CMAKE_CXX_FLAGS "-Wall -pedantic -Wextra --std=c++11 ${CMAKE_CXX_FLAGS}")


add_library (oath++ oath++.cpp)
target_link_libraries (oath++ ${OATH_LIBRARIES})
target_include_directories (oath++ PUBLIC "${PROJECT_SOURCE_DIR}" ${OATH_INCLUDE_DIRS})
target_compile_options (oath++ PUBLIC ${OATH_CFLAGS_OTHER})

enable_testing()
# add_executable(test-asdf test/test-asdf.cpp)
# add_test(asdf test-asdf) # passes if exit code is 0
