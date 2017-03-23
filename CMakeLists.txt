cmake_minimum_required(VERSION 3.6)
project(whilelist)

set(CMAKE_C_STANDARD 11)
find_package (Threads)
add_executable(server server.c whitelist.c)
add_executable(client client.c)

target_link_libraries(server pthread)