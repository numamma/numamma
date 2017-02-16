#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>

#include "numma.h"
#include "mem_tools.h"
#include "mem_intercept.h"

void print_backtrace(int backtrace_max_depth) {
  int j, nptrs;
  void *buffer[backtrace_max_depth];
  char **strings;

  nptrs = backtrace(buffer, backtrace_max_depth);
  printf("backtrace() returned %d addresses\n", nptrs);
  printf("-------------------\n");
  /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
     would produce similar output to the following: */

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }

  for (j = 0; j < nptrs; j++)
    printf("%s\n", strings[j]);
  printf("-------------------\n");

  free(strings);
}


#if HAVE_LIBBACKTRACE
__thread char current_frame[4096];

static void error_callback(void *data, const char *msg, int errnum)
{
  fprintf(stderr, "ERROR: %s (%d)", msg, errnum);
}

static int backtrace_callback (void *data, uintptr_t pc,
			       const char *filename, int lineno,
			       const char *function) {
  snprintf(current_frame, 4096, "%s:%d %s", filename, lineno, function);
  return 0;
}
#endif /* HAVE_LIBBACKTRACE */


char* get_caller_function(int depth) {
  int backtrace_depth=depth+1;
  void* buffer[backtrace_depth];
  /* get pointers to functions */

  int nb_calls = backtrace(buffer, backtrace_depth);

#if HAVE_LIBBACKTRACE
  struct backtrace_state *state = backtrace_create_state (NULL, BACKTRACE_SUPPORTS_THREADS,
							  error_callback, NULL);
#else
  char **functions;
  functions = backtrace_symbols(buffer, nb_calls);
#endif

  char* retval = NULL;
  if(nb_calls < depth) {
    retval = libmalloc(sizeof(char)*16);
    sprintf(retval, "???");
  }
#if HAVE_LIBBACKTRACE
    backtrace_pcinfo (state, (uintptr_t) buffer[depth],
		      backtrace_callback,
		      error_callback,
		      NULL);
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", current_frame);
#else
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", functions[depth]);
    free(functions);
#endif

  return retval;
}