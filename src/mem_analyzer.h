#ifndef MEM_ANALYZER_H
#define MEM_ANALYZER_H

#include <stdint.h>
#include "mem_intercept.h"

typedef uint64_t date_t;

struct mem_counters {
  unsigned total_count;
  unsigned total_weight;
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

extern __thread unsigned thread_rank;
extern unsigned next_thread_rank;

struct block_info {
  unsigned block_id;
  struct mem_counters counters[ACCESS_MAX];
  struct block_info *next;
};

struct memory_info {
  date_t alloc_date;
  date_t free_date;

  size_t initial_buffer_size;	/* size of the buffer at the first malloc */
  size_t buffer_size;		/* size of the buffer when it was freed */

  void* buffer_addr;
  void* caller_rip;		/* adress of the instruction that called malloc */
  char* caller;			/* callsite (function name+line) of the instruction that called malloc */
  /* TODO: numa node ? thread that allocates */
  struct block_info **blocks;
  //  struct mem_counters count[MAX_THREADS][ACCESS_MAX];
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
void ma_get_global_variables();
void ma_record_malloc(struct mem_block_info* info);
void ma_update_buffer_address(struct mem_block_info* info, void *old_addr, void *new_addr);
void ma_record_free(struct mem_block_info* info);

void ma_thread_init();
void ma_thread_finalize();
void ma_finalize();

void ma_allocate_counters(struct memory_info* mem_info);
void ma_init_counters(struct memory_info* mem_info);

/* return the block that contains ptr in a mem_info */
struct block_info* ma_get_block(struct memory_info* mem_info, int thread_rank, uintptr_t ptr);

struct memory_info* ma_find_mem_info_from_addr(uint64_t ptr);
struct memory_info* ma_find_past_mem_info_from_addr(uint64_t ptr,
						    date_t start_date,
						    date_t stop_date);


void ma_print_current_buffers();
void ma_print_past_buffers();
void ma_print_mem_info(struct memory_info*mem);

#endif	/* MEM_ANALYZER */
