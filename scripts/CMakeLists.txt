configure_file (
  "${PROJECT_SOURCE_DIR}/scripts/create_blocks.in"
  "${PROJECT_BINARY_DIR}/scripts/create_blocks"
  )

configure_file (
  "${PROJECT_SOURCE_DIR}/scripts/plot_timeline.in"
  "${PROJECT_BINARY_DIR}/scripts/plot_timeline"
  )



list(APPEND SCRIPTS
  ${PROJECT_BINARY_DIR}/scripts/create_blocks
  ${PROJECT_BINARY_DIR}/scripts/plot_timeline
  ${PROJECT_SOURCE_DIR}/scripts/counters_to_binding.py
  ${PROJECT_SOURCE_DIR}/scripts/plot_timeline.R
  ${PROJECT_SOURCE_DIR}/scripts/plot_interactive_timeline.py
  ${PROJECT_SOURCE_DIR}/scripts/plot_pages_matrix.R
  )

install(PROGRAMS ${SCRIPTS} DESTINATION bin)
