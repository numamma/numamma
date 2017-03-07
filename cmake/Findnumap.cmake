#
# Find the NUMAP libraries and include dir
#

# NUMAP_INCLUDE_DIR  - Directories to include to use NUMAP
# NUMAP_LIBRARY    - Files to link against to use NUMAP
# NUMAP_FOUND        - When false, don't try to use NUMAP
#
# NUMAP_DIR can be used to make it simpler to find the various include
# directories and compiled libraries when NUMAP was not installed in the
# usual/well-known directories (e.g. because you made an in tree-source
# compilation or because you installed it in an "unusual" directory).
# Just set NUMAP_DIR it to your specific installation directory
#

pkg_search_module(NUMAP REQUIRED numap)

FIND_LIBRARY(NUMAP_LIBRARY numap
  PATHS
  /usr/lib
  /usr/local/lib
  ${NUMAP_DIR}
  ${NUMAP_DIR}/lib
)

IF(NUMAP_LIBRARY)
  GET_FILENAME_COMPONENT(NUMAP_GUESSED_INCLUDE_DIR_tmp "${NUMAP_LIBRARY}" PATH)
  STRING(REGEX REPLACE "lib$" "include" NUMAP_GUESSED_INCLUDE_DIR "${NUMAP_GUESSED_INCLUDE_DIR_tmp}")
ENDIF(NUMAP_LIBRARY)

FIND_PATH( NUMAP_INCLUDE_DIR numap.h
  PATHS
  ${NUMAP_GUESSED_INCLUDE_DIR}
  ${NUMAP_DIR}/include
  /usr/include
  /usr/local/include
)


IF( NUMAP_INCLUDE_DIR )
  IF( NUMAP_LIBRARY )
    SET( NUMAP_FOUND "YES" )
    MARK_AS_ADVANCED( NUMAP_DIR )
    MARK_AS_ADVANCED( NUMAP_INCLUDE_DIR )
    MARK_AS_ADVANCED( NUMAP_LIBRARY )
  ENDIF( NUMAP_LIBRARY )
ENDIF( NUMAP_INCLUDE_DIR )



IF( NOT NUMAP_FOUND )
  MESSAGE("NUMAP installation was not found. Please provide NUMAP_DIR:")
  MESSAGE("  - through the GUI when working with ccmake, ")
  MESSAGE("  - as a command line argument when working with cmake e.g. ")
  MESSAGE("    cmake .. -DNUMAP_DIR:PATH=/usr/local/numap ")
  MESSAGE("Note: the following message is triggered by cmake on the first ")
  MESSAGE("    undefined necessary PATH variable (e.g. NUMAP_INCLUDE_DIR).")
  MESSAGE("    Providing NUMAP_DIR (as above described) is probably the")
  MESSAGE("    simplest solution unless you have a really customized/odd")
  MESSAGE("    NUMAP installation...")
  SET(NUMAP_DIR "" CACHE PATH "Root of NUMAP install tree." )
ENDIF( NOT NUMAP_FOUND )
