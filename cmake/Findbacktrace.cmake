#
# Find the BACKTRACE libraries and include dir
#

# BACKTRACE_INCLUDE_DIR  - Directories to include to use BACKTRACE
# BACKTRACE_LIBRARY    - Files to link against to use BACKTRACE
# BACKTRACE_FOUND        - When false, don't try to use BACKTRACE
#
# BACKTRACE_DIR can be used to make it simpler to find the various include
# directories and compiled libraries when BACKTRACE was not installed in the
# usual/well-known directories (e.g. because you made an in tree-source
# compilation or because you installed it in an "unusual" directory).
# Just set BACKTRACE_DIR it to your specific installation directory
#
FIND_LIBRARY(BACKTRACE_LIBRARY backtrace
  PATHS
  /usr/lib
  /usr/local/lib
  ${BACKTRACE_DIR}
  ${BACKTRACE_DIR}/lib
)

IF(BACKTRACE_LIBRARY)
  GET_FILENAME_COMPONENT(BACKTRACE_GUESSED_INCLUDE_DIR_tmp "${BACKTRACE_LIBRARY}" PATH)
  STRING(REGEX REPLACE "lib$" "include" BACKTRACE_GUESSED_INCLUDE_DIR "${BACKTRACE_GUESSED_INCLUDE_DIR_tmp}")
ENDIF(BACKTRACE_LIBRARY)

FIND_PATH( BACKTRACE_INCLUDE_DIR libbacktrace/backtrace.h
  PATHS
  ${BACKTRACE_GUESSED_INCLUDE_DIR}
  ${BACKTRACE_DIR}/include
  /usr/include
  /usr/local/include
)


IF( BACKTRACE_INCLUDE_DIR )
  IF( BACKTRACE_LIBRARY )
    SET( BACKTRACE_FOUND "YES" )
    MARK_AS_ADVANCED( BACKTRACE_DIR )
    MARK_AS_ADVANCED( BACKTRACE_INCLUDE_DIR )
    MARK_AS_ADVANCED( BACKTRACE_LIBRARY )
  ENDIF( BACKTRACE_LIBRARY )
ENDIF( BACKTRACE_INCLUDE_DIR )



IF( NOT BACKTRACE_FOUND )
  MESSAGE("BACKTRACE installation was not found. Please provide BACKTRACE_DIR:")
  MESSAGE("  - through the GUI when working with ccmake, ")
  MESSAGE("  - as a command line argument when working with cmake e.g. ")
  MESSAGE("    cmake .. -DBACKTRACE_DIR:PATH=/usr/local/backtrace ")
  MESSAGE("Note: the following message is triggered by cmake on the first ")
  MESSAGE("    undefined necessary PATH variable (e.g. BACKTRACE_INCLUDE_DIR).")
  MESSAGE("    Providing BACKTRACE_DIR (as above described) is probably the")
  MESSAGE("    simplest solution unless you have a really customized/odd")
  MESSAGE("    BACKTRACE installation...")
  SET(BACKTRACE_DIR "" CACHE PATH "Root of BACKTRACE install tree." )
ENDIF( NOT BACKTRACE_FOUND )
