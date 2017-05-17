add_library(numamma-tools SHARED
  hash.c
  )

add_library(count_events SHARED
  count_events.c
  )

configure_file (
  "${PROJECT_SOURCE_DIR}/tools/count_events.in"
  "${PROJECT_BINARY_DIR}/tools/count_events"
  )
list(APPEND SCRIPTS
  ${PROJECT_BINARY_DIR}/tools/count_events
  )


add_executable (hash_test hash_test.c)
target_link_libraries (hash_test LINK_PUBLIC numamma-tools)

add_test(hash_test hash_test)

list(APPEND TEST_PROGRAMS
  ${PROJECT_BINARY_DIR}/tools/hash_test
  )

install(PROGRAMS ${SCRIPTS} DESTINATION bin)
install(PROGRAMS ${TEST_PROGRAMS} DESTINATION bin)
install(TARGETS numamma-tools DESTINATION lib)
install(TARGETS count_events DESTINATION lib)
