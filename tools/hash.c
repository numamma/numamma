#include "hash.h"

// return the height of a node
int height(struct Node *node) {
  if (!node)
    return 0;
  return node->height;
}

/* return the node whose key is key */
struct Node *getNode(struct Node *node, uint64_t key) {
  if(!node)
    return NULL;
  if(node->key > key) {
    return getNode(node->left, key);
  } else if(node->key < key) {
    return getNode(node->right, key);
  } else {
    return node;
  }
}

/* return the value associated with key */
void *get(struct Node *node, uint64_t key) {
  struct Node*n = getNode(node, key);
  if(n)
    return n->value;
  return NULL;
}

/* allocate and initialize a node */
struct Node* newNode(uint64_t key, void *value) {
  struct Node* n = malloc(sizeof(struct Node));
  n->key = key;
  n->value = value;
  n->left = NULL;
  n->parent = NULL;
  n->right = NULL;
  n->height = 1;
  return n;
}

/* update the height of a node based on its children height */
static void update_height(struct Node *node) {
  if(node) {
    node->height = max(height(node->left), height(node->right));
    node->height++;
  }
}

static struct Node *right_rotate(struct Node *z) {
  struct Node *y = z->left;
  y->parent = z->parent;
  z->parent = y;
  z->left = y->right;
  y->right = z;
  update_height(z);
  update_height(y);
  return y;
}

static struct Node *left_rotate(struct Node *z) {
  struct Node *y = z->right;
  z->right = y->left;
  y->left = z;
  y->parent = z->parent;
  z->parent = y;
  update_height(z);
  update_height(y);
  return y;
}

struct Node* balance_tree(struct Node*node ) {
  if(!node)
    return node;
  int balance = height(node->left)-height(node->right);
  struct Node *y, *z;
  if(balance < -1 || balance > 1) {
    z = node;

    if(height(node->left) > height(node->right)) {
      /* case 1 or 3 */
      y = node->left;
      if(height(y->left) > height(y->right)) {
	// case 1
	z = right_rotate(z);
      } else {
	// case 3
	z->left = left_rotate(y);
	z = right_rotate(z);
      }
    } else {
      /* case 2 or 4 */
      y = node->right;
      if(height(y->left) < height(y->right)) {
	// case 2
	z = left_rotate(z);
      } else {
	/* case 4 */
	z->right = right_rotate(y);
	z = left_rotate(z);
      }
    }
    node = z;
  }
  return node;
}

/* insert a (key, value) in the subtree node
 * returns the new root of this treee
 */
struct Node* insert(struct Node* node, uint64_t key, void* value) {
  if(!node) {
    return newNode(key, value);
  }

  if(node->key > key){
    /* insert on the left */
    node->left = insert(node->left, key, value);
    node->left->parent = node;
  } else if (node->key < key){
    /* insert on the right */
    node->right = insert(node->right, key, value);
    node->right->parent = node;
  } else {
    /* replace the value of the current node */
    node->value = value;
    return node;
  }

  node = balance_tree(node);
  update_height(node);
  return node;
}

void connect_nodes(struct Node* parent,
		   struct Node* to_remove,
		   struct Node* child) {
#if 0
  printf("While removing %llx: connecting %llx and %llx\n",
	 to_remove->key, parent->key, child?child->key:NULL);
#endif
  if(parent->right == to_remove)
    parent->right = child;
  else
    parent->left = child;
  if(child)
    child->parent = parent;
}


/* todo:
   bug when running ./plop 12346
 */

/* remove key from the hash table
 * return the new root of the hash table
 */
struct Node* remove_key(struct Node* node, uint64_t key) {
  struct Node *to_remove = node;
  struct Node *parent = NULL;
  struct Node *n=NULL;
  while(to_remove) {
    if(to_remove->key < key) {
      parent = to_remove;
      to_remove = to_remove->right;
    } else if(to_remove->key > key) {
      parent = to_remove;
      to_remove = to_remove->left;
    } else {
      /* we found the node to remove */
      break;
    }
  }
  n = parent;
  if(!to_remove) {
    /* key not found */
    return node;
  }

  if(!to_remove->right  && !to_remove->left) {
    /* to_remove is a leaf */
    //    printf("Removing a leaf\n");
    if(parent) {
      connect_nodes(parent, to_remove, NULL);
    } else {
      /* removing the root */
      node = NULL;
    }
    free(to_remove);
    /* todo: balance the tree */
  } else if (!to_remove->right || !to_remove->left) {
    /* to_remove has 1 child */

    //    printf("Removing a node with 1 child\n");

    if(parent) {
      if(to_remove->right) {
	connect_nodes(parent, to_remove, to_remove->right);
      } else {
	connect_nodes(parent, to_remove, to_remove->left);
      }
    } else {
      /* removing the root -> right/left node becomes the new root */
      if(to_remove->right)
	node = to_remove->right;
      else
	node = to_remove->left;
    }
    //    update_height(parent);
    free(to_remove);
  } else {
    /* to_remove has 2 children */
    struct Node* succ = to_remove->right;
    struct Node* succ_parent = to_remove;
    while(succ->left) {
      succ_parent = succ;
      succ = succ->left;
    }

    n = succ_parent;

    /* copy succ to to_remove and connect succ child */
    to_remove->key = succ->key;
    to_remove->value = succ->value;
    connect_nodes(succ_parent, succ, succ->right);
    /* free succ (that has being copied to to_remove */
    free(succ);
  }

  struct Node* new_root = node;
#if 1
#if 0
  if(n)
    printf("About to balance starting from %p (%llx)\n", n, n->key);
#endif
  struct Node* nbis = n;
  while (nbis) {
    update_height(n);
    nbis = nbis->parent;
  }
#if 0
  printf("Before balancing: \n");
  print_hash_table(new_root, 0);
  printf("\n\n");
#endif
  n = n;
  while (n) {
    //    printf("\nBalancing %p (key %llx)\n", n, n->key);
    if(n->parent) {
      if(n->parent->left == n)
	n->parent->left = balance_tree(n);
      else if(n->parent->right == n)
	n->parent->right = balance_tree(n);
    } else {
      break;
    }
    //    print_hash_table(new_root, 0);
    n = n->parent;
  }
  new_root = balance_tree(new_root);

#endif
  return new_root;
}


static void print_tabs(int nb_tabs) {
  for(int i = 0; i<nb_tabs; i++) printf("  ");
}

/* print the (key, value) stored in a hash table */
void print_hash_table(struct Node *node, int depth) {
  if (node) {
    print_tabs(depth);
    printf("Height %d : \"%llx\" value: %p. node=%p\n", node->height, node->key, node->value, node);

    print_tabs(depth);
    printf("left of \"%llx\"\n", node->key);
    print_hash_table(node->left, depth+1);

    print_tabs(depth);
    printf("right of \"%llx\"\n", node->key);
    print_hash_table(node->right, depth+1);
  }
}

/* Free a subtree */
void release(struct Node *node) {
  if(node) {
    release(node->left);
    release(node->right);
    free(node);
  }
}

void check_table(struct Node*node) {
  if(node) {
    if(node->left) {
      if(node->left->key > node->key) {
	printf("Found a violation in the binary search tree\n");
	abort();
      }
      check_table(node->left);
    }
    if(node->right) {
      if(node->right->key < node->key) {
	printf("Found a violation in the binary search tree\n");
	abort();
      }
      check_table(node->right);
    }

#if 0
    int balance = height(node->left)-height(node->right);
    if(balance < -1 || balance > 1) {
      printf("the tree is not balanced !\n");
      abort();
    }
#endif
#if 0
    if(node->key > 10000) {
      printf("Key %llx is way too big !\n", node->key);
      abort();
    }
#endif
  }
}

int nb_values(struct Node* node) {
  if(!node)
    return 0;
  return nb_values(node->left)+nb_values(node->right)+1;
}
