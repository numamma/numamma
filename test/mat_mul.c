#include <stdio.h>
#include <time.h>
#include <stdlib.h>

static int plop = 0;

int var_globale[1024];

void mat_mul(double**A, double**B, double**C, int n) {
  int i, j, k;
  var_globale[0]++;
#pragma omp parallel for
  for(int i=0; i<n; i++) {
    for(int j=0; j<n; j++) {
      C[i][j] = 0;
      for(int k=0; k<n; k++) {
	C[i][j] += A[i][k] * B[k][j];
      }
    }
  }
}

double** alloc_matrix(int size) {
  double**res = malloc(sizeof(double*)*size);
  int i;
  for(i=0; i<size; i++)
    res[i] = malloc(sizeof(double)*size);
  return res;
}

void free_mat(double**mat, int n) {
  int i;
  for(i=0; i<n; i++) {
    free(mat[i]);
  }
  free(mat);
}

void init_mat(double**A, int n) {
  int i, j;
  for(i=0; i<n; i++) {
    for(j=0; j<n; j++) {
      A[i][j] = (i+j)%10;
    }
  }
}

void print_mat(double** C, int n) {
#if 0
  int i, j;
  for(i=0; i<n; i++) {
    for(j=0; j<n; j++) {
      printf("%lf ", C[i][j]);
    }
    printf("\n");
  }
#endif
}
int main(int argc, char** argv) {
  int i;
  int n = 100;
  if(argc>1) {
    n = atoi(argv[1]);
  }
  printf("Matrix size: %d\n", n);

#if 1
  double **A = malloc(sizeof(double*)*n);
  for(i=0; i<n; i++)
    A[i] = malloc(sizeof(double)*n);

  double **B = malloc(sizeof(double*)*n);
  for(i=0; i<n; i++)
    B[i] = malloc(sizeof(double)*n);

  double **C = malloc(sizeof(double*)*n);
  for(i=0; i<n; i++)
    C[i] = malloc(sizeof(double)*n);

#else
  double **A = alloc_matrix(n);
  double **B = alloc_matrix(n);
  double **C = alloc_matrix(n);
#endif

  init_mat(A, n);
  init_mat(B, n);

  printf("Start computing\n");
  struct timespec t1, t2;
  clock_gettime(CLOCK_REALTIME, &t1);
  mat_mul(A, B, C, n);
  clock_gettime(CLOCK_REALTIME, &t2);
  double duration = ((t2.tv_sec-t1.tv_sec)*1e9+(t2.tv_nsec-t1.tv_nsec))/1e9;
  printf("Computation took %lf s\n", duration);

  print_mat(C, n);
  //print_mat(B, n);

  free_mat(A, n);
  free_mat(B, n);
  free_mat(C, n);
  return 0;
}
