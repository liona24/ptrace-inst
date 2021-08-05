cmake_minimum_required(VERSION 3.0.0)
project(ptrace_inst VERSION 0.1.0)

add_library(ptrace_inst SHARED
    libptrace_inst/ptrace_inst.cpp
    libptrace_inst/process.cpp
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
include(FindPkgConfig)

pkg_check_modules (CAPSTONE REQUIRED capstone)
# Use CAPSTONE_FOUND, CAPSTONE_LIBRARIES, CAPSTONE_INCLUDE_DIRS vars
target_link_libraries(${PROJECT_NAME} ${CAPSTONE_LIBRARIES})

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

target_compile_options(ptrace_inst PRIVATE -Wall -Wextra -pedantic -Werror -Wno-gnu-zero-variadic-macro-arguments)
set_property(TARGET ptrace_inst PROPERTY CXX_STANDARD 17)
