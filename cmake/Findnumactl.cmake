#
# Find the NUMACTL libraries and include dir
#

# NUMACTL_INCLUDE_DIRS  - Directories to include to use NUMACTL
# NUMACTL_LIBRARIES     - Files to link against to use NUMACTL
# NUMACTL_LIB_DIR       - The directory containing NUMACTL_LIBRARIES
# NUMACTL_FOUND         - When false, don't try to use NUMACTL
#
# NUMACTL_DIR can be used to make it simpler to find the various include
# directories and compiled libraries when NUMACTL was not installed in the
# usual/well-known directories (e.g. because you made an in tree-source
# compilation or because you installed it in an "unusual" directory).
# Just set NUMACTL_DIR it to your specific installation directory
#
FIND_PATH( NUMACTL_INCLUDE_DIR numa.h
  HINTS ${NUMACTL_DIR}/include
  )

find_library(NUMACTL_LIBRARY
  NAMES numa
  HINTS ${NUMACTL_DIR}/lib
  )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBXML2_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(numactl  DEFAULT_MSG
                                  NUMACTL_LIBRARY NUMACTL_INCLUDE_DIR)

IF( NUMACTL_INCLUDE_DIR )
  IF( NUMACTL_LIBRARY )
    SET( NUMACTL_FOUND "YES" )
    MARK_AS_ADVANCED( NUMACTL_INCLUDE_DIR NUMACTL_LIBRARY )
    set(NUMACTL_LIBRARIES ${NUMACTL_LIBRARY} )
    get_filename_component(NUMACTL_LIB_DIR ${NUMACTL_LIBRARY} DIRECTORY)
    set(NUMACTL_INCLUDE_DIRS ${NUMACTL_INCLUDE_DIR} )
  ENDIF( NUMACTL_LIBRARY )
ENDIF( NUMACTL_INCLUDE_DIR )

IF( NOT NUMACTL_FOUND )
  MESSAGE("NUMACTL installation was not found. Please provide NUMACTL_DIR:")
  MESSAGE("  - through the GUI when working with ccmake, ")
  MESSAGE("  - as a command line argument when working with cmake e.g. ")
  MESSAGE("    cmake .. -DNUMACTL_DIR:PATH=/usr/local/numactl ")
  MESSAGE("Note: the following message is triggered by cmake on the first ")
  MESSAGE("    undefined necessary PATH variable (e.g. NUMACTL_INCLUDE_DIR).")
  MESSAGE("    Providing NUMACTL_DIR (as above described) is probably the")
  MESSAGE("    simplest solution unless you have a really customized/odd")
  MESSAGE("    NUMACTL installation...")
  SET(NUMACTL_DIR "" CACHE PATH "Root of NUMACTL install tree." )
ENDIF( NOT NUMACTL_FOUND )
