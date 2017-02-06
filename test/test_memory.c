/* -*- c-file-style: "GNU" -*- */
/*
 * Copyright (C) CNRS, INRIA, Université Bordeaux 1, Télécom SudParis
 * See COPYING in top-level directory.
 */

#include <sys/time.h>
#include <semaphore.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
/* Number of iterations */
#define ITER 10
/* Number of threads */
#define NTH 2

typedef union {
  unsigned long long tick;
  struct {
    unsigned low;
    unsigned high;
  };
} tick_t;

int fd[2][2];
sem_t thread_ready;

#define TICK_DIFF(t1, t2) \
           ((t2).tick - (t1).tick)

#define TIME_DIFF(t1, t2) \
        ((t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec))

// Debugging part, print out only if debugging level of the system is verbose or more
int _debug = -77;

void debug(char *fmt, ...) {
  if (_debug == -77) {
    char *buf = getenv("DEBUG_LEVEL");
    if (buf == NULL)
      _debug = 0;
    else
      _debug = atoi(buf);
  }
  if (_debug >= 2) { // debug verbose mode
    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    va_end(va);
  }
}
// end of debugging part

/* Fake computation of usec microseconds */
void compute(int usec) {
  struct timeval tv1, tv2;
  gettimeofday(&tv1, NULL);
  do {
    gettimeofday(&tv2, NULL);
  } while (TIME_DIFF(tv1, tv2) < usec);
}

void test_malloc() {
  int i, j;
  char*buffer[ITER];

  for (i = 0; i < ITER; i++) {
    int alloc_size = (1 + i) * 1024;
    debug("\tloop %d/%d: allocating %d bytes\n", i, ITER, alloc_size);

    buffer[i] = malloc(alloc_size*sizeof(char));
    for (j = 0; j < alloc_size; j++) {
      buffer[i][j] = 'a';
    }

    printf("buffer[%d][%d] = %p\n", i, alloc_size-1, &buffer[i][alloc_size-1]);
    /* compute for 1ms */
    compute(50000);
    free(buffer[i]);
    compute(10000);
  }
}

void test_realloc() {
  int i, j;
  char*buffer[ITER];
  for (i = 0; i < ITER; i++) {
    int alloc_size = (1 + i) * 1024;
    debug("\tloop %d/%d: allocating %d bytes\n", i, ITER, alloc_size);
    buffer[i] = malloc(alloc_size);
    for (j = 0; j < (1 + i) * 1024; j++) {
      buffer[i][j] = 'a';
    }

    /* compute for 1ms */
    compute(20000);

    alloc_size *= 2;
    debug("\t\tloop %d/%d: reallocating %d bytes\n", i, ITER, alloc_size);
    buffer[i] = realloc(buffer[i], alloc_size);

    compute(20000);

    free(buffer[i]);
    compute(10000);
  }
}

void test_calloc() {
  int i, j;
  char*buffer[ITER];

  for (i = 0; i < ITER; i++) {
    int alloc_size = (1 + i) * 1024;
    debug("\tloop %d/%d: allocating %d bytes\n", i, ITER, alloc_size);

    buffer[i] = calloc(alloc_size, sizeof(uint8_t));
    for (j = 0; j < (1 + i) * 1024; j++) {
      buffer[i][j] = 'a';
    }

    /* compute for 1ms */
    compute(50000);
    free(buffer[i]);
    compute(10000);
  }
}

int main(int argc, char**argv) {
  char* buffer[ITER];
  int i, j;
  fprintf(stderr, "PLOP\n");
  debug("Testing malloc\n");
  test_malloc();
  debug("1/2 done\n");
  compute(100000);

  test_malloc();
  debug("2/2 done\n");

  compute(100000);
  debug("Testing realloc\n");
  test_realloc();
  debug("realloc done\n");

  compute(100000);
  debug("Testing calloc\n");
  test_calloc();
  debug("calloc done\n");

  return 0;
}

