#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define TIME_DIFF(t1, t2)						\
        ((t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec))

/* Fake computation of usec microseconds */
char use_buffer(char* buffer, int buffer_size, int usec) {
  char res = 0;
  struct timeval tv1, tv2;
  gettimeofday(&tv1, NULL);
  do {
    int i;
    for(i=0; i<buffer_size; i++) {
      res = (res + buffer[i])%128;
      buffer[i] = res;
    }
    gettimeofday(&tv2, NULL);
  } while (TIME_DIFF(tv1, tv2) < usec);
  return res;
}


char* test_malloc(size_t buffer_size) {
  return malloc(buffer_size);
}


char* test_malloc1(size_t buffer_size) {
  return test_malloc(buffer_size);
}

char* test_malloc2(size_t buffer_size) {
  return test_malloc(buffer_size);
}

int main(int argc, char**argv) {

  int buffer_size = 4096*10;

  char* buffer1 = test_malloc1(buffer_size);
  char* buffer2 = test_malloc2(buffer_size);

  use_buffer(buffer1, buffer_size, 500000);
  use_buffer(buffer2, buffer_size, 500000);
  
  free(buffer1);
  free(buffer2);
}
