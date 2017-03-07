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
STRING(REPLACE ";" " " NUMAP_LDFLAGS "${NUMAP_LDFLAGS}")
STRING(REPLACE ";" " " NUMAP_CFLAGS "${NUMAP_CFLAGS}")
STRING(REPLACE ";" " " NUMAP_CFLAGS_OTHER "${NUMAP_CFLAGS_OTHER}")
STRING(REPLACE ";" " " NUMAP_LDFLAGS_OTHER "${NUMAP_LDFLAGS_OTHER}")


