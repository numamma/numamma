#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#define N 500
double A[N][N];
double B[N][N];
double C[N][N];

void mat_mul(double A[N][N], double B[N][N], double C[N][N]) {
  int i, j, k;
  for(i=0; i<N; i++) {
    for(j=0; j<N; j++) {
      C[i][j] = 0;
      for(k=0; k<N; k++) {
	C[i][j] += A[i][k] * B[k][j];
      }
    }
  }
}

void init_mat(double A[N][N]) {
  int i, j;
  for(i=0; i<N; i++) {
    for(j=0; j<N; j++) {
      A[i][j] = (i+j)%10;
    }
  }
}

void print_mat(double C[N][N]) {
#if 0
  int i, j;
  for(i=0; i<N; i++) {
    for(j=0; j<N; j++) {
      printf("%lf ", C[i][j]);
    }
    printf("\n");
  }
#endif
}

int main(int argc, char** argv) {
  int i, j;
  int n = N;
  printf("@A=%p\n", A);
  printf("@B=%p\n", B);
  printf("@C=%p\n", C);
  printf("Matrix size: %d\n", n);
  init_mat(A);
  init_mat(B);

  printf("Start computing\n");
  struct timespec t1, t2;
  clock_gettime(CLOCK_REALTIME, &t1);
  mat_mul(A, B, C);
  clock_gettime(CLOCK_REALTIME, &t2);
  double duration = ((t2.tv_sec-t1.tv_sec)*1e9+(t2.tv_nsec-t1.tv_nsec))/1e9;
  printf("Computation took %lf s\n", duration);

  print_mat(C);
  //print_mat(B, n);

  return 0;
}
