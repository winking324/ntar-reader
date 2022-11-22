cmake_minimum_required(VERSION 3.5)

project(ntar)

set(CMAKE_CXX_STANDARD 11)

set(TARGET_SOURCES
        src/block.cpp
        src/block_enhanced_packet.cpp
        src/block_interface_description.cpp
        src/block_interface_statistics.cpp
        src/block_name_resolution.cpp
        src/block_packet.cpp
        src/block_section_header.cpp
        src/block_simple_packet.cpp
        src/option.cpp
        src/pcap_reader.cpp
        src/section.cpp
        )

set(TARGET_PUBLIC_HEADERS
        include/block.h
        include/block_enhanced_packet.h
        include/block_interface_description.h
        include/block_interface_statistics.h
        include/block_name_resolution.h
        include/block_packet.h
        include/block_section_header.h
        include/block_simple_packet.h
        include/byte_io.h
        include/memory.h
        include/option.h
        include/pcap_reader.h
        include/section.h
        )

add_library(${PROJECT_NAME} STATIC
        ${TARGET_SOURCES}
        )

add_executable(test test/main.cpp)
target_link_libraries(test ntar)

target_include_directories(${PROJECT_NAME}
        PUBLIC ${PROJECT_SOURCE_DIR}/include
        )

set_target_properties(${PROJECT_NAME}
        PROPERTIES PUBLIC_HEADER
        "${TARGET_PUBLIC_HEADERS}"
        )

install(TARGETS ${PROJECT_NAME}
        DESTINATION lib
        PUBLIC_HEADER DESTINATION include/${PROJECT_NAME}
        )
