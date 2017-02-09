add_library(numma SHARED
  mem_intercept.c
  mem_analyzer.c
  )
target_link_libraries(numma -ldl -lnumap)

configure_file (
  "${PROJECT_SOURCE_DIR}/src/mem_intercept.in"
  "${PROJECT_BINARY_DIR}/src/mem_intercept"
  )

list(APPEND SCRIPTS
  ${PROJECT_BINARY_DIR}/src/mem_intercept
  )

install(PROGRAMS ${SCRIPTS} DESTINATION bin)
install(TARGETS numma DESTINATION lib)
