cmake_minimum_required (VERSION 2.6)
project(tuntest)

add_definitions(-DUNICODE)
add_definitions(-D_UNICODE)
add_definitions(-DWINVER=0x0601)
add_definitions(-D_WIN32_WINNT=0x0601)
add_definitions(-DWIN32_LEAN_AND_MEAN)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -static -O3")
add_executable(tuntest main.cpp c_tuntap_windows.cpp c_ndp.cpp)
target_link_libraries(tuntest boost_system ws2_32 iphlpapi)

add_executable(udp_sender udp_sender.cpp)
target_link_libraries(udp_sender boost_system ws2_32)