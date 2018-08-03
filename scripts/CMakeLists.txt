configure_file (
  "${PROJECT_SOURCE_DIR}/scripts/create_blocks.in"
  "${PROJECT_BINARY_DIR}/scripts/create_blocks"
  )


configure_file (
  "${PROJECT_SOURCE_DIR}/scripts/summary_to_plot.in"
  "${PROJECT_BINARY_DIR}/scripts/summary_to_plot"
  )

list(APPEND SCRIPTS
  ${PROJECT_BINARY_DIR}/scripts/create_blocks
  ${PROJECT_SOURCE_DIR}/scripts/counters_to_binding.py
  ${PROJECT_SOURCE_DIR}/scripts/plot_counters.sh
  ${PROJECT_SOURCE_DIR}/scripts/plot_timeline.R
  ${PROJECT_SOURCE_DIR}/scripts/plot_pages_matrix.R
  ${PROJECT_BINARY_DIR}/scripts/summary_to_plot
  )

install(PROGRAMS ${SCRIPTS} DESTINATION bin)
