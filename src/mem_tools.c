#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>

#include "numamma.h"
#include "mem_tools.h"
#include "mem_intercept.h"
#include "hash.h"

#define HAVE_LIBBACKTRACE 1
#if HAVE_LIBBACKTRACE
#include <backtrace.h>
#include <backtrace-supported.h>
#endif


struct ht_node* symbols=NULL;

void print_backtrace(int backtrace_max_depth) {
  if(!IS_RECURSE_SAFE)
    return;

  PROTECT_FROM_RECURSION;
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
  UNPROTECT_FROM_RECURSION;
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
  if(!function) {
    /* symbol can't be resolved */
    current_frame[0]='\0';
  } else {
    snprintf(current_frame, 4096, "%s:%d(%s)", filename, lineno, function);
  }
  return 0;
}
#endif /* HAVE_LIBBACKTRACE */

void** get_caller_rip(int depth, int* size_callstack, void** caller_rip) {
    static int max_depth = 20;
    int backtrace_depth=max_depth+1;
    void** buffer = (void**) malloc(sizeof(void*)*backtrace_depth);

    /* TODO: calling backtrace seems to be very expensive (~7.5 usec)
    * maybe we should implement it to make it faster
    */
    int nb_calls = backtrace(buffer, backtrace_depth);
    if(nb_calls < depth) {
        *size_callstack = 0;
        *caller_rip = NULL;
        free(buffer);
        return NULL;
    }

    *size_callstack = nb_calls;
    *caller_rip = buffer[depth];
    return buffer;
}

char* get_caller_function_from_rip(void* rip) {
  char* retval = NULL;

  /* check if the function corresponding to rip is already known */
  retval = ht_get_value(symbols, (uint64_t) rip);
  if(retval)
    return retval;

  if(!rip) {
    retval = libmalloc(sizeof(char)*16);
    sprintf(retval, "???");
    symbols = ht_insert(symbols, (uint64_t) rip, retval);
    return retval;
  }

#if HAVE_LIBBACKTRACE
  struct backtrace_state *state = backtrace_create_state (NULL, BACKTRACE_SUPPORTS_THREADS,
							  error_callback, NULL);

#endif
#if HAVE_LIBBACKTRACE
  backtrace_pcinfo (state, (uintptr_t) rip,
		    backtrace_callback,
		    error_callback,
		    NULL);
  if(current_frame[0] != '\0') {
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", current_frame);
    symbols = ht_insert(symbols, (uint64_t) rip, retval);
    return retval;
  }
#endif
  /* symbol can't be resolved by libbacktrace, use the symbol name */
  char **functions;
  functions = backtrace_symbols(&rip, 1);
  retval = libmalloc(sizeof(char)*4096);
  sprintf(retval, "%s", functions[0]);
  free(functions);
  symbols = ht_insert(symbols, (uint64_t) rip, retval);
  return retval;
}

char* get_caller_function(int depth) {
  int backtrace_depth=depth+1;
  void* buffer[backtrace_depth];
  /* get pointers to functions */

  int nb_calls = backtrace(buffer, backtrace_depth);

#if HAVE_LIBBACKTRACE
  struct backtrace_state *state = backtrace_create_state (NULL, BACKTRACE_SUPPORTS_THREADS,
							  error_callback, NULL);
#endif

  char* retval = NULL;
  if(nb_calls < depth) {
    retval = libmalloc(sizeof(char)*16);
    sprintf(retval, "???");
    return retval;
  }

#if HAVE_LIBBACKTRACE
  backtrace_pcinfo (state, (uintptr_t) buffer[depth],
		    backtrace_callback,
		    error_callback,
		    NULL);
  if(current_frame[0] != '\0') {
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", current_frame);
    return retval;
  }
#endif
  /* symbol can't be resolved by libbacktrace, use the symbol name */
  char **functions;
  functions = backtrace_symbols(buffer, nb_calls);
  retval = libmalloc(sizeof(char)*4096);
  sprintf(retval, "%s", functions[depth]);
  free(functions);

    return retval;
}
