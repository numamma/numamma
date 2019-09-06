#include <stdio.h>
#include <stdlib.h>

int lib_global_uninitialized_variable;
int lib_global_initialized_variable = 0;
_Thread_local int lib_thread_local_initialized_variable = 0;
_Thread_local int lib_thread_local_uninitialized_variable;
static int lib_static_global_variable = 0;

void lib_function() {
  static int lib_static_local_variable = 0;
  printf("@lib_global_uninitialized_variable = %p\n", &lib_global_uninitialized_variable);  
  printf("@lib_global_initialized_variable = %p\n", &lib_global_initialized_variable);
  printf("@lib_static_global_variable = %p\n", &lib_static_global_variable);
  printf("@lib_thread_local_initialized_variable = %p\n", &lib_thread_local_initialized_variable);
  printf("@lib_thread_local_uninitialized_variable = %p\n", &lib_thread_local_uninitialized_variable);
}
