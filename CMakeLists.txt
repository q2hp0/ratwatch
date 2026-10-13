cmake_minimum_required(VERSION 3.15)
project(ratwatch CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(ratwatch
  src/main.cpp
  src/persistence_scan.cpp
  src/process_scan.cpp
  src/network_scan.cpp
  src/memory_scan.cpp
  src/pe_scan.cpp
  src/responder.cpp
  src/service_scan.cpp
  src/wmi_scan.cpp
  src/hosts_scan.cpp
  src/signatures.cpp
  src/baseline.cpp
  src/config.cpp
  src/log.cpp
)

target_include_directories(ratwatch PRIVATE include)

if(WIN32)
  target_link_libraries(ratwatch PRIVATE advapi32 iphlpapi ws2_32 psapi)
endif()

if(MSVC)
  target_compile_definitions(ratwatch PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

if(MSVC)
  target_compile_options(ratwatch PRIVATE /W4)
else()
  target_compile_options(ratwatch PRIVATE -Wall -Wextra)
  # filesystem needs linking against stdc++fs on some older mingw/gcc setups
  if(WIN32)
    target_link_libraries(ratwatch PRIVATE stdc++fs)
  endif()
endif()

# this lets us build and run the core logic tests on linux too, since the
# scanners are split so the windows-only bits are isolated in their own files
option(RATWATCH_BUILD_TESTS "build the portable unit tests" ON)
if(RATWATCH_BUILD_TESTS)
  add_executable(ratwatch_tests
    tests/test_main.cpp
    src/baseline.cpp
    src/config.cpp
    src/pe_scan.cpp
    src/hosts_scan.cpp
    src/signatures.cpp
    src/log.cpp
  )
  target_include_directories(ratwatch_tests PRIVATE include)
endif()
