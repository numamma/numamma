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


static struct ht_node* __ht_min_node(struct ht_node *node) {
  if(!node)
    return NULL;
  if(node->left)
    return  __ht_min_node(node->left);
  return node;
}

static struct ht_node* __ht_next_node(struct ht_node *node) {
  if(node) {
    if(node->right) {
      return __ht_min_node(node->right);
    }

    /* browse the tree from the bottom to the top */
    while(node->parent && node->parent->right == node) {
      node = node->parent;
    }
    /* after the loop, node points to a subtree that was completed processed */

    return node->parent;
  }
  return NULL;
}

#define FOREACH_HASH(root, iter)			\
  for(iter = __ht_min_node(root);	\
      iter;						\
      iter = __ht_next_node(iter))			\

/* insert a (key, value) in the subtree node
 * return the new root of this tree
 */
struct ht_node* ht_insert(struct ht_node* node, uint64_t key, void* value);

/* remove a key from the hashtable
 * return the new root of this tree
 */
struct ht_node* ht_remove_key(struct ht_node* node, uint64_t key);


/* Free a subtree */
void ht_release(struct ht_node *node);


/* return the value associated with key */
void *ht_get_value(struct ht_node *node, uint64_t key);

/* return 1 if the hash table contains the key */
int ht_contains_key(struct ht_node* node, uint64_t key);

/* return 1 if the hash table contains at least one key that is mapped to value */
int ht_contains_value(struct ht_node* node, void* value);

/* return the node whose key is lower or equal to key */
struct ht_node* ht_lower_key(struct ht_node* node, uint64_t key);



/* return the number of values stored in the hashtable */
int ht_size(struct ht_node* node);

/* return the height of a node */
int ht_height(struct ht_node *node);

void ht_print(struct ht_node *node);

/* check if a hashtable is consistent */
void ht_check(struct ht_node *node);

#endif /* HASH_H */
