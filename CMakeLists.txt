cmake_minimum_required(VERSION 3.26)
project(SILENTMOON)
cmake_policy(SET CMP0135 NEW)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

set(TARGET_FOLDER
    target)

set(phnt_TAG "v1.1-19b15cc")
message(STATUS "Fetching phnt (${phnt_TAG})...")
FetchContent_Declare(phnt
        URL "https://github.com/mrexodia/phnt-single-header/releases/download/${phnt_TAG}/phnt.zip"
        URL_HASH "SHA256=ccd3cbc27c83b2870f6c8d2b72d47cc75a38fc7bb57b11fc9677a9ec46710e10"
)
FetchContent_MakeAvailable(phnt)

add_executable(${PROJECT_NAME} main.cpp src/eneio64.cpp src/vdm.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE includes)
target_link_libraries(${PROJECT_NAME} PRIVATE phnt::phnt)

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
endif()

set_target_properties(${PROJECT_NAME}
                      PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY
                      ${CMAKE_SOURCE_DIR}/${TARGET_FOLDER}/${CMAKE_BUILD_TYPE}
)