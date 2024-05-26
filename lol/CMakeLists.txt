set(CMAKE_CXX_STANDARD 23)
add_definitions(-DUNICODE -D_UNICODE)

add_executable(injector injector.cpp)

add_library(bypass SHARED bypass.cpp)
target_link_libraries(bypass minhook)
target_include_directories(bypass PRIVATE minhook/src)

add_library(lol SHARED lol.cpp)
target_link_libraries(lol minhook)
target_include_directories(lol PRIVATE minhook/src)

add_subdirectory(minhook)
