add_library(numamma SHARED
  mem_intercept.c
  mem_tools.c
  mem_sampling.c
  mem_analyzer.c
  )
target_link_libraries(numamma ${NUMAP_LIBRARY} -lnumap -ldl -lpthread numamma-tools)

configure_file (
  "${PROJECT_SOURCE_DIR}/src/mem_intercept.in"
  "${PROJECT_BINARY_DIR}/src/mem_intercept"
  )

list(APPEND SCRIPTS
  ${PROJECT_BINARY_DIR}/src/mem_intercept
  )

install(PROGRAMS ${SCRIPTS} DESTINATION bin)
install(TARGETS numamma DESTINATION lib)
