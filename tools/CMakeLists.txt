add_library(numma-tools SHARED
  hash.c
  )
add_executable (hash_test hash_test.c)
target_link_libraries (hash_test LINK_PUBLIC numma-tools)

add_test(hash_test hash_test)

list(APPEND TEST_PROGRAMS
  ${PROJECT_BINARY_DIR}/tools/hash_test
  )

install(PROGRAMS ${TEST_PROGRAMS} DESTINATION bin)
install(TARGETS numma-tools DESTINATION lib)
