add_library(numamma SHARED
  mem_intercept.c
  mem_tools.c
  mem_sampling.c
  mem_analyzer.c
  )


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${NUMACTL_INCLUDE_DIRS}  ${NUMAP_CFLAGS} ${NUMAP_CFLAGS_OTHER} -I${BACKTRACE_INCLUDE_DIR}")

set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${NUMACTL_LIBRARIES}   ${NUMAP_LDFLAGS} ${NUMAP_LDFLAGS_OTHER}  -L${BACKTRACE_DIR}/lib -lbacktrace")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}  ${NUMACTL_LIBRARIES}   ${NUMAP_LDFLAGS} ${NUMAP_LDFLAGS_OTHER}  -L${BACKTRACE_DIR}/lib -lbacktrace")


target_link_libraries(numamma ${NUMAP_LIBRARY} -lbacktrace -lnumap -ldl -lpthread numamma-tools -lrt -lelf)

add_library(numa_run SHARED
  mem_run.c
  mem_tools.c
  )
target_link_libraries(numa_run ${NUMAP_LIBRARY} -lnuma -ldl -lpthread)

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
