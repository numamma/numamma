configure_file (
  "${PROJECT_SOURCE_DIR}/scripts/create_blocks.in"
  "${PROJECT_BINARY_DIR}/scripts/create_blocks"
  )

list(APPEND SCRIPTS
  ${PROJECT_BINARY_DIR}/scripts/create_blocks
  ${PROJECT_SOURCE_DIR}/scripts/counters_to_binding.py
  )

install(PROGRAMS ${SCRIPTS} DESTINATION bin)
