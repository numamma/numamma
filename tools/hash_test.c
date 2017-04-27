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

struct Node* insert_random_value(struct Node* root) {
  uint64_t key = lrand48();

  if(get(root, key)) {
    /* the key is already in the hashtable */
    return insert_random_value(root);
  }

  struct list* value = malloc(sizeof(struct list));
  value->next = values;
  value->key = key;
  values = value;
  nb_item++;
  printf("Inserting %llx (nb_item = %d)\n", key, nb_item);
  root = insert(root, key, value);

  int nval= nb_values(root);
  if(nval != nb_item) {
    printf("Error after inserting %llx: the tree contains %d item instead of %d\n",
	   key, nval, nb_item);
    print_hash_table(root, 0);

    abort();
  }
  
  return root;
}

struct Node* delete_random_value(struct Node* root) {
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

  printf("Removing %llx (nb_item = %d)\n", l->key, nb_item);

  root = remove_key(root, l->key);

  int nval= nb_values(root);
  if(nval != nb_item) {
    printf("Error after deleting %llx: the tree contains %d item instead of %d\n",
	   l->key, nval, nb_item);

    print_hash_table(root, 0);

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
  struct Node *root = NULL;
  srand48(seed);
  int i;

  for(i=0; i<10000; i++) {
    printf("\n\nLoop %d\n", i);

    if( lrand48() % 10 > 3) {
      /* insert a value */
      printf("Inserting stuff\n");
      root = insert_random_value(root);
    } else {
      /* delete a value */
      printf("Deleting stuff\n");
      root = delete_random_value(root);
   }

    //    print_hash_table(root, 0);
    check_table(root);
    if(nb_values(root) != nb_item) {
      printf("Error: the hashtablme contains %d values. It should contain %d\n", nb_values(root), nb_item);
      abort();
    }
  }

  /* Liberation */
  release(root);
  return 0;
}
