#include <stdio.h>
#include <assert.h>
#include "mem_analyzer.h"
#include "numap.h"

//#define USE_NUMAP 1

struct memory_info_list*mem_list = NULL;
struct numap_sampling_measure sm;

extern void* (*libcalloc)(size_t nmemb, size_t size);
extern void* (*libmalloc)(size_t size);
extern void (*libfree)(void *ptr);
extern void* (*librealloc)(void *ptr, size_t size);

void ma_init() {
#if USE_NUMAP
  int sampling_rate = 1000;
  int res = numap_sampling_init_measure(&sm, 2, sampling_rate, 64);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  // Start memory read access sampling
  printf("\nStarting memory read sampling");
  res = numap_sampling_read_start(&sm);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_start error : %s\n", numap_error_message(res));
    abort();
  }
#endif
}

static uint64_t new_date() {
#ifdef __x86_64__
  // This is a copy of rdtscll function from asm/msr.h
#define ticks(val) do {                                         \
    uint32_t __a,__d;                                           \
    asm volatile("rdtsc" : "=a" (__a), "=d" (__d));             \
    (val) = ((uint64_t)__a) | (((uint64_t)__d)<<32);      \
  } while(0)

#elif defined(__i386)

#define ticks(val)                              \
  __asm__ volatile("rdtsc" : "=A" (val))

#else
  ERROR_TIMER_NOT_AVAILABLE();
#define ticks(val) (val) = -1
#endif

  uint64_t time;
  ticks(time);

  return time;
}


void ma_record_malloc(struct mem_block_info* info) {
  struct memory_info_list * p_node = libmalloc(sizeof(struct memory_info_list));

  /* todo: make this thread-safe */
  p_node->next = mem_list;
  mem_list = p_node;

  p_node->mem_info.alloc_date = new_date();
  p_node->mem_info.free_date = 0;
  p_node->mem_info.initial_buffer_size = info->size;
  p_node->mem_info.buffer_size = info->size;
  p_node->mem_info.buffer_addr = info->u_ptr;
}

void ma_update_buffer_address(void *old_addr, void *new_addr) {
  struct memory_info_list * p_node = mem_list;
  while(p_node) {
    if(p_node->mem_info.buffer_addr == old_addr  &&
       p_node->mem_info.free_date == 0) {
      break;
    }
    p_node = p_node->next;
  }
  assert(p_node);
  p_node->mem_info.buffer_addr = new_addr;
}

void ma_record_free(struct mem_block_info* info) {
  struct memory_info_list * p_node = mem_list;
  while(p_node) {
    if(p_node->mem_info.buffer_addr == info->u_ptr  &&
       p_node->mem_info.free_date == 0) {
      break;
    }
    p_node = p_node->next;
  }
  assert(p_node);
  p_node->mem_info.buffer_size = info->size;
  p_node->mem_info.free_date = new_date();
}


void ma_finalize() {
  printf("---------------------------------\n");
  printf("         MEM ANALYZER\n");
  printf("---------------------------------\n");

#if USE_NUMAP
  // Stop memory read access sampling
  int res = numap_sampling_read_stop(&sm);
  if(res < 0) {
    printf("numap_sampling_stop error : %s\n", numap_error_message(res));
    abort();
  }

  // Print memory read sampling results
  printf("\nMemory read sampling results\n");
  numap_sampling_read_print(&sm, 0);
#endif
  struct memory_info_list * p_node = mem_list;
  while(p_node) {
    printf("buffer %p (%lu - %lu bytes) allocated at %x, freed at %x (duration =%lu ticks)\n",
	   p_node->mem_info.buffer_addr,
	   p_node->mem_info.initial_buffer_size,
	   p_node->mem_info.buffer_size,
	   p_node->mem_info.alloc_date,
	   p_node->mem_info.free_date,
	   p_node->mem_info.free_date-p_node->mem_info.alloc_date);
    p_node = p_node->next;
  }
}
