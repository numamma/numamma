#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "hash.h"

struct list {
  uint64_t key;
  struct list *next;
};

int nb_item = 0;
struct list *values = NULL;

struct ht_node* insert_random_value(struct ht_node* root) {
  uint64_t key = lrand48();

  if(ht_get_value(root, key)) {
    /* the key is already in the hashtable */
    return insert_random_value(root);
  }

  struct list* value = malloc(sizeof(struct list));
  value->next = values;
  value->key = key;
  values = value;
  nb_item++;
  root = ht_insert(root, key, value);

  int nval= ht_size(root);
  if(nval != nb_item) {
    printf("Error after inserting %llx: the tree contains %d item instead of %d\n",
	   key, nval, nb_item);
    ht_print(root);

    abort();
  }

  return root;
}

struct ht_node* delete_random_value(struct ht_node* root) {
  if(!nb_item)
    return root;

  unsigned id  = lrand48() % nb_item;
  nb_item--;
  struct list* l = values;
  struct list* prev = NULL;

  /* find the id_th item of the list */
  for(int i=0; i<id; i++) {
    prev = l;
    l = l->next;
  }

  /* remove l from the list */
  if(prev) {
    prev->next = l->next;
  } else {
    values = l->next;
  }

  root = ht_remove_key(root, l->key);

  int nval= ht_size(root);
  if(nval != nb_item) {
    printf("Error after deleting %llx: the tree contains %d item instead of %d\n",
	   l->key, nval, nb_item);

    ht_print(root);

    abort();
  }

  free(l);
  return root;
}


/* Code de test des fonctions ci-dessus */
int main(int argc, char**argv) {
  int seed= 1;
  if(argc>1)
    seed=atoi(argv[1]);
  struct ht_node *root = NULL;
  srand48(seed);
  int i;

  struct timeval t1, t2;
  gettimeofday(&t1, NULL);
  int nb_op = 0;
  int nb_insert=0;
  int nb_delete=0;
  for(i=0; i<10000; i++) {

    if( lrand48() % 10 > 3) {
      /* insert a value */
      nb_insert++;
      root = insert_random_value(root);
    } else {
      /* delete a value */
      nb_delete++;
      root = delete_random_value(root);
   }

    ht_check(root);
    if(ht_size(root) != nb_item) {
      printf("Error: the hashtablme contains %d values. It should contain %d\n", ht_size(root), nb_item);
      abort();
    }
  }
  gettimeofday(&t2, NULL);
  nb_op = nb_insert + nb_delete;
  double duration = ((t2.tv_sec-t1.tv_sec)*1e6 + (t2.tv_usec-t1.tv_usec))/1e6;
  printf("%d insert + %d delete (total: %d) operation performed in %lf s (%lf us per operation)\n",
	 nb_insert, nb_delete, nb_op, duration, (duration*1e6)/nb_op);

  /* Liberation */
  ht_release(root);
  return 0;
}
