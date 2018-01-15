#ifndef MEM_INTERCEPT_H
#define MEM_INTERCEPT_H

#include <stdint.h>
#include <stdlib.h>
#include "numamma.h"

extern void* (*libcalloc)(size_t nmemb, size_t size);
extern void* (*libmalloc)(size_t size);
extern void (*libfree)(void *ptr);
extern void* (*librealloc)(void *ptr, size_t size);
int  (*libpthread_create) (pthread_t * thread, const pthread_attr_t * attr,
			   void *(*start_routine) (void *), void *arg);
void (*libpthread_exit) (void *thread_return);

#define CANARY_PATTERN 0xdeadbeefdeadbeef

typedef uint64_t canary_t;

/* when a buffer is allocated, it has the following pattern:
 * PADDING BLOCK_INFO USER_BLOCK CANARY
 * block_info has to be right-aligned because of calloc.
 * the address should be a multiple of 8 bytes in order to avoid bugs
 * (if not aligned, some weird bugs may happen when using -O3)
 */
enum __memory_type {
  MEM_TYPE_MALLOC, MEM_TYPE_HAND_MADE_MALLOC, MEM_TYPE_INTERNAL_MALLOC
};


/* this block is located right after the user buffer */
struct mem_tail_block {
  canary_t canary;
};


/* todo: we could add information like:
 * - date of malloc
 * - thread id that allocated the block
 * - NUMA node ?
 */
struct mem_block_info {
  void* u_ptr; /* address of the user block */
  void* p_ptr; /* address of the padding */

  enum __memory_type mem_type;

  size_t total_size; /* size allocated (including this structure) */
  size_t size; /* size of the buffer (not including this structure) */

  struct mem_tail_block* tail_block;
  void* record_info;

  /* todo: add the possibility to change the size of the canary
   *   (eg. array of canaries)
   */
  /* WARNING: this must be the last field of the structure */
  canary_t canary; /* this is used for checking that we malloc'ed the buffer */
} __attribute__ ((aligned (16)));

/* size of the padding + mem_info structure */
#define HEADER_SIZE     (sizeof(struct mem_block_info))
#define TAIL_SIZE       (sizeof(struct mem_tail_block))

//#define CANARY_OK(u_ptr) ((*(canary_t*)((u_ptr) - sizeof(canary_t))) == CANARY_PATTERN)
#define CANARY_OK(u_ptr) (((struct mem_block_info*)((u_ptr) - (void*)sizeof(struct mem_block_info)))->canary == CANARY_PATTERN)
#define TAIL_CANARY_OK(b_info) ((b_info)->tail_block->canary == CANARY_PATTERN)

#define ERASE_CANARY(u_ptr) (memset(&((struct mem_block_info*)((u_ptr) - (void*)sizeof(struct mem_block_info)))->canary, 0x00, sizeof(CANARY_PATTERN)))


/* converts a pointer to a user_block into a pointer to the block info */
#define USER_PTR_TO_BLOCK_INFO(u_ptr, b_ptr)				\
  do {									\
    if(! CANARY_OK(u_ptr)) {						\
      /* we didn't malloc this buffer */				\
      (b_ptr) = NULL;							\
      break;								\
    }									\
    b_ptr = (void*)(ptr - (void*)sizeof(struct mem_block_info));	\
  }while(0)

/* converts a pointer to a user_block into a pointer to the padding */
#define USER_PTR_TO_PADDING(u_ptr, p_ptr)	\
  do {						\
    struct mem_block_info *b_ptr;		\
    USER_PTR_TO_BLOCK_INFO(u_ptr, b_ptr);	\
    if(!b_ptr) {				\
      (p_ptr) = NULL;				\
      break;					\
    }						\
    (p_ptr) = b_ptr->p_ptr;			\
  } while(0)

/* fill a mem_info structure
 * @param p_mem the mem_info* structure to fill
 * @param ptr the address returned by (m,c,re)alloc
 * @param nmemb the number of elements
 * @param block_size the size of 1 element
 */
#define INIT_MEM_INFO(p_mem, ptr, nmemb, block_size)		\
  do {								\
    unsigned int nb_memb_header = HEADER_SIZE / block_size;	\
    if(block_size*nb_memb_header < HEADER_SIZE)			\
      nb_memb_header++;						\
    void* u_ptr = ptr + (block_size*nb_memb_header);		\
    p_mem = u_ptr - sizeof(struct mem_block_info);		\
    p_mem->p_ptr = ptr;						\
    p_mem->total_size = (nmemb + nb_memb_header) * block_size;	\
    p_mem->size = nmemb * block_size;				\
    p_mem->tail_block = u_ptr + p_mem->size;			\
    p_mem->tail_block->canary = CANARY_PATTERN;			\
    p_mem->record_info = NULL;					\
    p_mem->u_ptr = u_ptr;					\
    p_mem->canary = CANARY_PATTERN;				\
  } while(0)

#endif	/* MEM_INTERCEPT_H */
