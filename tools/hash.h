#ifndef HASH_H
#define HASH_H
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

struct Node {
  /* todo: make this parametric */
  uint64_t key;
  struct Node *parent;
  struct Node *left;
  struct Node *right;
  int height;
  void *value;
};

#define max(a, b) (((a) > (b))? (a) : (b))

/* return the height of a node */
int height(struct Node *node);

/* return the node whose key is key */
struct Node *getNode(struct Node *node, uint64_t key);

/* return the value associated with key */
void *get(struct Node *node, uint64_t key);
/* allocate and initialize a node */
struct Node* newNode(uint64_t key, void *value);

/* insert a (key, value) in the subtree node
 * returns the new root of this treee
 */
struct Node* insert(struct Node* node, uint64_t key, void* value);

/* print the (key, value) stored in a hash table */
void print_hash_table(struct Node *node, int depth);

/* Free a subtree */
void release(struct Node *node);

void check_table(struct Node *node);

/* remove a key from the hashtable */
struct Node* remove_key(struct Node* node, uint64_t key);

/* return the number of values stored in the hashtable */
int nb_values(struct Node* node);

/* update the height of a node based on its children height */
static void update_height(struct Node *node);
static struct Node *right_rotate(struct Node *z);
static struct Node *left_rotate(struct Node *z);
struct Node* balance_tree(struct Node *node);


#endif /* HASH_H */
