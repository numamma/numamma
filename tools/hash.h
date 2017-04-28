#ifndef HASH_H
#define HASH_H
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

struct ht_node {
  /* todo: make this parametric */
  uint64_t key;
  struct ht_node *parent;
  struct ht_node *left;
  struct ht_node *right;
  int height;
  void *value;
};


/* insert a (key, value) in the subtree node
 * returns the new root of this tree
 */
struct ht_node* ht_insert(struct ht_node* node, uint64_t key, void* value);

/* remove a key from the hashtable */
struct ht_node* ht_remove_key(struct ht_node* node, uint64_t key);


/* Free a subtree */
void ht_release(struct ht_node *node);


/* return the value associated with key */
void *ht_get_value(struct ht_node *node, uint64_t key);

/* return 1 if the hash table contains the key */
int ht_contains_key(struct ht_node* node, uint64_t key);

/* return 1 if the hash table contains at least one key that is mapped to value */
int ht_contains_value(struct ht_node* node, void* value);



/* return the number of values stored in the hashtable */
int ht_size(struct ht_node* node);

/* return the height of a node */
int ht_height(struct ht_node *node);

/* print the (key, value) stored in a hash table */
void ht_print(struct ht_node *node);

/* check if a hashtable is consistent */
void ht_check(struct ht_node *node);

#endif /* HASH_H */
