cmake_minimum_required (VERSION 2.6)
INCLUDE (CheckLibraryExists)
find_package(PkgConfig)


project (NuMMa)
set (NuMMa_VERSION_MAJOR 0)
set (NuMMa_VERSION_MINOR 1)
SET(PROJECT_VERSION "${NuMMa_VERSION_MAJOR}.${NuMMa_VERSION_MINOR}")
SET(PROJECT_DESCRIPTION "NuMMa is a memory manager for NUMA architectures")

SET(PKG_CONFIG_LIBDIR  "\${prefix}/lib"  )
SET(PKG_CONFIG_INCLUDEDIR  "\${prefix}/include"  )
SET(PKG_CONFIG_LIBS  "-L\${libdir}"  )
SET(PKG_CONFIG_CFLAGS  "-I\${includedir}"  )

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package (numap)
if (NUMAP_FOUND)


  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NUMAP_CFLAGS} ${NUMAP_CFLAGS_OTHER}")
  set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS}   ${NUMAP_LDFLAGS} ${NUMAP_LDFLAGS_OTHER}")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}  ${NUMAP_LDFLAGS} ${NUMAP_LDFLAGS_OTHER}")

  link_directories(${NUMAP_LIBDIR})
else (NUMAP_FOUND)
  message(FATAL_ERROR "numap not found")
endif (NUMAP_FOUND)

find_package (backtrace)
if (BACKTRACE_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${BACKTRACE_INCLUDE_DIR}")
  set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}  -L${BACKTRACE_DIR}/lib -lbacktrace")
    link_directories(${BACKTRACE_LIBDIR})
else (BACKTRACE_FOUND)
  message(FATAL_ERROR "backtrace not found")
endif (BACKTRACE_FOUND)

option(ENABLE_DEBUG "Enable Debug" ON)
if(ENABLE_DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g")
endif()

# configure a header file to pass some of the CMake settings
# to the source code

configure_file (
  "${PROJECT_SOURCE_DIR}/src/numma.h.in"
  "${PROJECT_BINARY_DIR}/src/numma.h"
  )

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)


# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
  SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
ENDIF("${isSystemDir}" STREQUAL "-1")


# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}/src")

# add the sub directories
include_directories("${PROJECT_SOURCE_DIR}/src")
add_subdirectory ("src")

install(TARGETS DESTINATION bin)

CONFIGURE_FILE(
  "${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
  )
install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc"
          DESTINATION lib/pkgconfig)
