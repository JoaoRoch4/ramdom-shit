cmake_minimum_required(VERSION 3.16)
project(Criptografia LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Localiza a libsodium pelo pkg-config (Linux/macOS/MSYS2).
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_executable(cripto
    src/main.cpp
    src/Criptografador.cpp
)
target_include_directories(cripto PRIVATE include)
target_link_libraries(cripto PRIVATE PkgConfig::SODIUM)

if(MSVC)
    target_compile_options(cripto PRIVATE /W4)
else()
    target_compile_options(cripto PRIVATE -Wall -Wextra -Wpedantic)
endif()
