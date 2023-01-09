#
# Find the PFM libraries and include dir
#

# PFM_INCLUDE_DIR  - Directories to include to use PFM
# PFM_LIBRARIES    - Files to link against to use PFM
# PFM_LIB_DIR      - The directory containing PFM_LIBRARIES
# PFM_FOUND        - When false, don't try to use PFM
#
# PFM_DIR can be used to make it simpler to find the various include
# directories and compiled libraries when PFM was not installed in the
# usual/well-known directories (e.g. because you made an in tree-source
# compilation or because you installed it in an "unusual" directory).
# Just set PFM_DIR it to your specific installation directory
#
FIND_PATH( PFM_INCLUDE_DIR perfmon/pfmlib_perf_event.h
  HINTS ${PFM_DIR}/include
  )

find_library(PFM_LIBRARY
  NAMES pfm
  HINTS ${PFM_DIR}/lib
  )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBXML2_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(pfm  DEFAULT_MSG
                                  PFM_LIBRARY PFM_INCLUDE_DIR)

IF( PFM_INCLUDE_DIR )
  IF( PFM_LIBRARY )
    SET( PFM_FOUND "YES" )
    MARK_AS_ADVANCED( PFM_DIR PFM_INCLUDE_DIR PFM_LIBRARY )
    set(PFM_LIBRARIES ${PFM_LIBRARY} )
    get_filename_component(PFM_LIB_DIR ${PFM_LIBRARY} DIRECTORY)
    set(PFM_INCLUDE_DIRS ${PFM_INCLUDE_DIR} )
  ENDIF( PFM_LIBRARY )
ENDIF( PFM_INCLUDE_DIR )

IF( NOT PFM_FOUND )
  MESSAGE("PFM installation was not found. Please provide PFM_DIR:")
  MESSAGE("  - through the GUI when working with ccmake, ")
  MESSAGE("  - as a command line argument when working with cmake e.g. ")
  MESSAGE("    cmake .. -DPFM_DIR:PATH=/usr/local/pfm ")
  MESSAGE("Note: the following message is triggered by cmake on the first ")
  MESSAGE("    undefined necessary PATH variable (e.g. PFM_INCLUDE_DIR).")
  MESSAGE("    Providing PFM_DIR (as above described) is probably the")
  MESSAGE("    simplest solution unless you have a really customized/odd")
  MESSAGE("    PFM installation...")
  SET(PFM_DIR "" CACHE PATH "Root of PFM install tree." )
ENDIF( NOT PFM_FOUND )
