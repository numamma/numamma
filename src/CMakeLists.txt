add_library(numamma SHARED
  mem_intercept.c
  mem_tools.c
  mem_sampling.c
  mem_analyzer.c
  )
target_link_libraries(numamma ${NUMAP_LIBRARY} -lbacktrace -lnumap -ldl -lpthread numamma-tools)

add_library(numa_run SHARED
  mem_run.c
  )
target_link_libraries(numa_run ${NUMAP_LIBRARY} -ldl -lpthread)

configure_file (
  "${PROJECT_SOURCE_DIR}/src/mem_intercept.in"
  "${PROJECT_BINARY_DIR}/src/mem_intercept"
  )

configure_file (
  "${PROJECT_SOURCE_DIR}/src/mem_run.in"
  "${PROJECT_BINARY_DIR}/src/mem_run"
  )

list(APPEND SCRIPTS
  ${PROJECT_BINARY_DIR}/src/mem_intercept
  ${PROJECT_BINARY_DIR}/src/mem_run
  )

install(PROGRAMS ${SCRIPTS} DESTINATION bin)
install(TARGETS numamma DESTINATION lib)
install(TARGETS numa_run DESTINATION lib)
