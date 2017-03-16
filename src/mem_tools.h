#ifndef MEM_TOOLS_H
#define MEM_TOOLS_H
#include "mem_intercept.h"

char* get_caller_function(int depth);
void print_backtrace(int backtrace_max_depth);

struct mem_allocator {
  struct mem_allocator* next_mem; /* next block of memory */
  void* first_block; /* first available block */
  void* buffer_addr; /* address of the buffer as returned by malloc */
  size_t block_size; /* size of each block */
  unsigned long nb_allocated; /* number of blocks allocated in this buffer */
  unsigned long nb_free; /* number of available blocks */
};

static void mem_allocator_init(struct mem_allocator **mem,
			       size_t block_size,
			       unsigned long nb_blocks) {
  *mem = libmalloc(sizeof(struct mem_allocator));
  (*mem)->next_mem = NULL;
  (*mem)->buffer_addr = libmalloc(block_size * nb_blocks);
  (*mem)->first_block = (*mem)->buffer_addr;
  (*mem)->block_size = block_size;
  (*mem)->nb_allocated = nb_blocks;
  (*mem)->nb_free = nb_blocks;
  int i;
  void**ptr = (*mem)->first_block;
  /* create a linked list of blocks */
  for(i=0; i<nb_blocks-1; i++) {
    *ptr = ((uint8_t*)ptr) + block_size;
    ptr = *ptr;
  }
  *ptr = NULL;
}

static void mem_allocator_finalize(struct mem_allocator *mem) {
  if(mem) {
    mem_allocator_finalize(mem->next_mem);
    libfree(mem->buffer_addr);
    free(mem);
  }
}

static void* mem_allocator_alloc(struct mem_allocator *mem) {
  while(mem->nb_free == 0) {
    /* find a mem block with available blocks */
    if(mem->next_mem == NULL) {
      /* no more blocks in the current mem block, allocate a new one */
      mem_allocator_init(&mem->next_mem, mem->block_size, mem->nb_allocated);
      return mem_allocator_alloc(mem->next_mem);
    }
    mem = mem->next_mem;
  }

  /* return the first available block */
  assert(mem);
  assert(mem->nb_free > 0);
  assert(mem->first_block);
  void* retval = mem->first_block;
  mem->first_block = *(void**)mem->first_block;
  mem->nb_free--;
  return retval;
}

static void mem_allocator_free(struct mem_allocator *mem, void* ptr) {
  assert(mem);
  *(void**)ptr = mem->first_block;
  mem->first_block = ptr;
  mem->nb_free++;
}

#endif
