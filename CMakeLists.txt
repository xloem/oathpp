cmake_minimum_required (VERSION 2.6)
project (oath++)

find_package(PkgConfig REQUIRED)
pkg_check_modules(OATH REQUIRED liboath)

set (CMAKE_CXX_FLAGS "-Wall -pedantic -Wextra --std=c++11 ${CMAKE_CXX_FLAGS}")


add_library (oath++ oath++.cpp)
target_link_libraries (oath++ ${OATH_LIBRARIES})
target_include_directories (oath++ PUBLIC "${PROJECT_SOURCE_DIR}" ${OATH_INCLUDE_DIRS})
target_compile_options (oath++ PUBLIC ${OATH_CFLAGS_OTHER})

install(TARGETS oath++ DESTINATION lib)
install(FILES oath++.hpp DESTINATION include)



enable_testing()
link_libraries(oath++)
add_executable(test-basic test/basic.cpp)
add_executable(test-coding test/coding.cpp)
add_executable(test-hotp_algo test/hotp_algo.cpp)
add_executable(test-hotp_validate test/hotp_validate.cpp)
add_executable(test-totp_algo test/totp_algo.cpp)
add_executable(test-totp_validate test/totp_validate.cpp)
add_executable(test-usersfile test/usersfile.cpp)
add_test(basic test-basic)
add_test(coding test-coding)
add_test(hotp_algo test-hotp_algo)
add_test(hotp_validate test-hotp_validate)
add_test(totp_algo test-totp_algo)
add_test(totp_validate test-totp_validate)
add_test(NAME usersfile COMMAND datefudge 2006-12-07 ./test-usersfile)
set_tests_properties(usersfile PROPERTIES ENVIRONMENT TZ=UTC)
