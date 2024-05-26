set(CMAKE_CXX_STANDARD 23)
add_definitions(-DUNICODE -D_UNICODE)

add_executable(injector injector.cpp)

add_library(exe SHARED exe.cpp)
target_link_libraries(exe minhook)
target_include_directories(exe PRIVATE minhook/src)

add_library(dll SHARED dll.cpp)
target_link_libraries(dll minhook)
target_include_directories(dll PRIVATE minhook/src)

add_library(lol SHARED lol.cpp)
target_link_libraries(lol minhook)
target_include_directories(lol PRIVATE minhook/src)

add_subdirectory(minhook)
