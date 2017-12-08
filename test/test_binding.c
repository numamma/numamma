#define _GNU_SOURCE  

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/syscall.h>

#define NTH 4
static inline int getcpu() {
  int cpu, status;
  status = syscall(SYS_getcpu, &cpu, NULL, NULL);
  return (status == -1) ? status : cpu;
}

pthread_barrier_t barrier;

void* pthread_func(void* argv) {
  int my_id=*(int*)argv;
  pthread_barrier_wait(&barrier);
  int my_cpu = getcpu();
  printf("I'm thread %d, I'm on cpu %d\n", my_id, my_cpu);
  return NULL;
}

int main(int argc,char**argv) {
  pthread_t tid[NTH];
  pthread_barrier_init(&barrier, NULL, 2);
  for(int i=0; i< NTH; i++) {
    pthread_create(&tid[i], NULL, pthread_func, &i);
    pthread_barrier_wait(&barrier);
  }
  printf("All the threads were created\n");
  sleep(1);
  for(int i=0; i< NTH; i++) {
    pthread_join (tid[i], NULL);
  }
  return 0;
}

