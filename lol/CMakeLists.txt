set(CMAKE_CXX_STANDARD 23)
add_definitions(-DUNICODE -D_UNICODE)

add_library(lol SHARED lol.cpp)
add_subdirectory(minhook)
target_link_libraries(lol minhook)
target_include_directories(lol PRIVATE minhook/src)