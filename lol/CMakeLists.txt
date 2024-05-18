set(CMAKE_CXX_STANDARD 23)
add_definitions(-DUNICODE -D_UNICODE)

add_executable(lol lol.cpp memscan/src/memscan/memscan.c memscan/src/memscan/util/util.c)
target_include_directories(lol PRIVATE memscan/src)