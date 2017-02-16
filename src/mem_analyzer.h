#ifndef MEM_ANALYZER_H
#define MEM_ANALYZER_H

#include <stdint.h>
#include "mem_intercept.h"

typedef uint64_t date_t;

struct mem_counters {
  unsigned total_count;
  unsigned na_miss_count;
  unsigned cache1_count;
  unsigned cache2_count;
  unsigned cache3_count;
  unsigned lfb_count;
  unsigned memory_count;
  unsigned remote_memory_count;
  unsigned remote_cache_count;
};

enum access_type {
  ACCESS_READ,
  ACCESS_WRITE,
  ACCESS_MAX
};

struct memory_info {
  date_t alloc_date;
  date_t free_date;

  size_t initial_buffer_size;	/* size of the buffer at the first malloc */
  size_t buffer_size;		/* size of the buffer when it was freed */

  void* buffer_addr;
  char* caller;
  /* TODO: numa node ? thread that allocates */
  struct mem_counters count[ACCESS_MAX];
  //  struct mem_counters write_count;
};

struct memory_info_list {
  struct memory_info_list* next;
  struct memory_info mem_info;
};

/**
 * Structure collecting statistics on samples
 */
struct mem_sampling_stat {
  uint64_t head;
  struct perf_event_header *header;
  uint64_t consumed;
};


void ma_init();
void ma_record_malloc(struct mem_block_info* info);
void ma_update_buffer_address(void *old_addr, void*new_addr);
void ma_record_free(struct mem_block_info* info);

void ma_thread_init();
void ma_thread_finalize();
void ma_finalize();
#endif	/* MEM_ANALYZER */
