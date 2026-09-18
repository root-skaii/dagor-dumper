cmake_minimum_required(VERSION 3.20)
project(dagor_dumper CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The injected DLL must use the host's CRT (/MD); /MDd would corrupt the heap
# if the game frees DLL-allocated memory.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")

# /RTC1 is added by default for Debug and is incompatible with /O flags.
if(MSVC)
    foreach(_flag
            CMAKE_CXX_FLAGS_DEBUG
            CMAKE_C_FLAGS_DEBUG
            CMAKE_CXX_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS_RELWITHDEBINFO)
        string(REPLACE "/RTC1" "" ${_flag} "${${_flag}}")
    endforeach()
endif()

add_library(dagor_dumper SHARED
    src/dllmain.cpp
    src/logger.cpp
    src/scanner.cpp
    src/chain_walker.cpp
    src/em_locator.cpp
    src/das_rtti.cpp
    src/rtti_dump.cpp
)

target_include_directories(dagor_dumper PRIVATE include)
target_link_libraries(dagor_dumper PRIVATE psapi)

if(MSVC)
    target_compile_options(dagor_dumper PRIVATE
        /W3
        /wd4996   # _s-function deprecation
        /wd4267   # size_t -> int narrowing
        $<$<CONFIG:Release>:/O2 /GL>
        $<$<CONFIG:RelWithDebInfo>:/O2>
        $<$<CONFIG:Debug>:/Od /Zi>
    )

    target_link_options(dagor_dumper PRIVATE
        $<$<CONFIG:Release>:/LTCG>
        $<$<CONFIG:Debug>:/DEBUG>
    )
endif()

set_target_properties(dagor_dumper PROPERTIES
    OUTPUT_NAME "dagor_dumper"
    SUFFIX      ".dll"
    PREFIX      ""
)
