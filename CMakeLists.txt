project(frtpm)
cmake_minimum_required(VERSION 3.2)
add_definitions("-std=gnu++17 -Wall -pedantic -Werror -ggdb3")

set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fstack-protector-strong")
set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer")

add_executable(
  frtpm
  frtpm.cpp
)

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(frtpm Threads::Threads)

include(FindPkgConfig)

pkg_check_modules(ALSA REQUIRED alsa)
target_link_libraries(frtpm ${ALSA_LIBRARIES})
target_include_directories(frtpm PUBLIC ${ALSA_INCLUDE_DIRS})
target_compile_options(frtpm PUBLIC ${ALSA_CFLAGS_OTHER})

pkg_check_modules(AVAHI REQUIRED avahi-client)
target_link_libraries(frtpm ${AVAHI_LIBRARIES})
target_include_directories(frtpm PUBLIC ${AVAHI_INCLUDE_DIRS})
target_compile_options(frtpm PUBLIC ${AVAHI_CFLAGS_OTHER})

set_target_properties(frtpm PROPERTIES OUTPUT_NAME frtpm)

install(TARGETS frtpm
    COMPONENT frtpm
    RUNTIME DESTINATION "/usr/bin/"
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
        DESTINATION "/usr/share/frtpm"
        COMPONENT "frtpm")

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Folkert van Heusden <mail@vanheusden.com>")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_COMPRESSION_TYPE "lzma")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_STRIP_FILES OFF)
set(CPACK_DEB_AUTO_GENERATED_FILE_NAME ON)
set(CPACK_DEBIAN_DEBUGINFO_PACKAGE ON)
set(CPACK_DEBIAN_PACKAGE_DEBUG ON)
set(CPACK_DEBIAN_RUNTIME_DEBUGINFO_PACKAGE ON)
set(CPACK_DEBIAN_frtpm_DEBUGINFO_PACKAGE ON)

include(CPack)
