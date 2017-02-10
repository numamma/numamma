#ifndef MEM_ANALYZER_H
#define MEM_ANALYZER_H

#include <stdint.h>
#include "mem_intercept.h"

typedef uint64_t date_t;

struct memory_info {
  date_t alloc_date;
  date_t free_date;

  size_t initial_buffer_size;	/* size of the buffer at the first malloc */
  size_t buffer_size;		/* size of the buffer when it was freed */

  void* buffer_addr;
  /* TODO: numa node ? thread that allocates */
  uint32_t read_access;
};

struct memory_info_list {
  struct memory_info_list* next;
  struct memory_info mem_info;
};

void ma_init();
void ma_record_malloc(struct mem_block_info* info);
void ma_update_buffer_address(void *old_addr, void*new_addr);
void ma_record_free(struct mem_block_info* info);

void ma_thread_init();
void ma_thread_finalize();
void ma_finalize();
#endif	/* MEM_ANALYZER */
