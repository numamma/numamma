#include <stdio.h>
#include <stdlib.h>

int global_uninitialized_variable;
int global_initialized_variable = 0;
_Thread_local int thread_local_initialized_variable = 0;
_Thread_local int thread_local_uninitialized_variable;
static int static_global_variable = 0;

void lib_function();

int main(int argc, char**argv) {
  static int static_local_variable = 0;


  printf("@global_uninitialized_variable = %p\n", &global_uninitialized_variable);  
  printf("@global_initialized_variable = %p\n", &global_initialized_variable);
  printf("@static_global_variable = %p\n", &static_global_variable);
  printf("@thread_local_initialized_variable = %p\n", &thread_local_initialized_variable);
  printf("@thread_local_uninitialized_variable = %p\n", &thread_local_uninitialized_variable);

  lib_function();
  return 0;  
}
