#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define NITER 1000000


int main(int argc, char**argv) {
  int niter = NITER;
  struct timespec t1, t2;

  if(argc>1) {
    niter = atoi(argv[1]);
  }

  clock_gettime(CLOCK_MONOTONIC, &t1);

  void**array = malloc(sizeof(void*)*niter);
  for(int i=0; i<niter; i++) {
    array[i] = malloc(1);
  }
  for(int i=0; i<niter; i++) {
    free(array[i]);
  }
  free(array);

  clock_gettime(CLOCK_MONOTONIC, &t2);

  double duration = ((t2.tv_sec-t1.tv_sec)*1e9+(t2.tv_nsec-t1.tv_nsec));
  printf("%d malloc/free in %lf ns\n", niter, duration);
  printf("->%lf ns per iteration\n", duration/niter);
  return EXIT_SUCCESS;
}
