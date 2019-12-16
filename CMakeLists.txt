cmake_minimum_required(VERSION 2.8)
project(bootunpack)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O2")

set(SOURCE_FILES
        lz4/lz4_compress.c
        lz4/lz4_decompress.c
        lz4/lz4hc_compress.c
        kallsyms.c
        lzo_crc.c
        unlz4.c
        lzo1x_decompress.c
        bootunpack.c)


add_executable(bootunpack ${SOURCE_FILES})
target_link_libraries(bootunpack z)

