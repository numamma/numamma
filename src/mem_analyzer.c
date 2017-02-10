#include <stdio.h>
#include <assert.h>
#include "mem_analyzer.h"
#include "numap.h"

#define USE_NUMAP 1

static int  __record_infos = 0;
struct memory_info_list*mem_list = NULL;
struct numap_sampling_measure sm;

extern void* (*libcalloc)(size_t nmemb, size_t size);
extern void* (*libmalloc)(size_t size);
extern void (*libfree)(void *ptr);
extern void* (*librealloc)(void *ptr, size_t size);

void collect_samples();
void start_sampling();

/* todo:
 * - intercept thread creation and run numap_sampling_init_measure for each thread
 * - set an alarm every 1ms to collect the sampling info
 * - choose the buffer size
 * - collect read/write accesses
 */
void ma_init() {
#if USE_NUMAP
  int sampling_rate = 10000;
  char* sampling_rate_str = getenv("SAMPLING_RATE");
  if(sampling_rate_str)
    sampling_rate=atoi(sampling_rate_str);
  printf("Sampling rate: %d\n", sampling_rate);
  numap_init();
  int res = numap_sampling_init_measure(&sm, 1, sampling_rate, 64);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  /* for now, only collect info on the current thread */
  sm.tids[0] = syscall(SYS_gettid);
  start_sampling();
#endif
  __record_infos = 1;
  ma_thread_init();
}

static int is_sampling=0;
void start_sampling() {
#if USE_NUMAP
  int previous_state = __record_infos;
  __record_infos = 0;
  printf("-------------- Start sampling %d\n", is_sampling);

  if(is_sampling) {
    printf("is_sampling = %d !\n", is_sampling);
    abort();
  }
  is_sampling=1;
  // Start memory read access sampling
  int res = numap_sampling_read_start(&sm);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_start error : %s\n", numap_error_message(res));
    abort();
  }
  __record_infos = previous_state;
#endif
}

void collect_samples() {
#if USE_NUMAP
  int previous_state = __record_infos;
  __record_infos = 0;

  printf("-------------- Collect samples %d\n", is_sampling);

  if(!is_sampling) {
    printf("is_sampling = %d !\n", is_sampling);
    abort();
  }
  is_sampling = 0;

  // Stop memory read access sampling
  int res = numap_sampling_read_stop(&sm);
  if(res < 0) {
    printf("numap_sampling_stop error : %s\n", numap_error_message(res));
    abort();
  }

  // Print memory read sampling results
  //  numap_sampling_read_print(&sm, 1);
  __analyze_sampling(&sm);
  __record_infos = previous_state;
#endif
}

void ma_thread_init() {
  pid_t tid = syscall(SYS_gettid);
  printf("New thread: %d\n", tid);
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

int is_address_in_buffer(uint64_t addr, struct memory_info *buffer){
  void* addr_ptr = (void*)addr;
  if(buffer->buffer_addr <= addr_ptr &&
     addr_ptr < buffer->buffer_addr + buffer->buffer_size)
    return 1;
  return 0;
}

struct memory_info_list* find_mem_info_from_addr(uint64_t ptr) {

  struct memory_info_list * p_node = mem_list;
  while(p_node) {
    if(is_address_in_buffer(ptr, &p_node->mem_info))
      return p_node;
    p_node = p_node->next;
  }
  return NULL;
}

void ma_record_malloc(struct mem_block_info* info) {
  if(! __record_infos)
    return;
  struct memory_info_list * p_node = libmalloc(sizeof(struct memory_info_list));

  /* todo: make this thread-safe */
  p_node->next = mem_list;
  mem_list = p_node;

  p_node->mem_info.alloc_date = new_date();
  p_node->mem_info.free_date = 0;
  p_node->mem_info.initial_buffer_size = info->size;
  p_node->mem_info.buffer_size = info->size;
  p_node->mem_info.buffer_addr = info->u_ptr;
  p_node->mem_info.read_access = 0;
}

void ma_update_buffer_address(void *old_addr, void *new_addr) {
  if(! __record_infos)
    return;
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
  if(! __record_infos)
    return;
  collect_samples();
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
  start_sampling();
}

void ma_thread_finalize() {
  pid_t tid = syscall(SYS_gettid);
  printf("End of thread: %d\n", tid);
}

void __analyze_sampling(struct numap_sampling_measure *sm) {
  int thread;
  struct numap_sampling_read_stat p_stat[sm->nb_threads];

  for (thread = 0; thread < sm->nb_threads; thread++) {
    struct perf_event_mmap_page *metadata_page = sm->metadata_pages_per_tid[thread];
    p_stat[thread].head = metadata_page -> data_head;
    rmb();
    p_stat[thread].header = (struct perf_event_header *)((char *)metadata_page + sm->page_size);

    p_stat[thread].consumed = 0;
    p_stat[thread].na_miss_count = 0;
    p_stat[thread].cache1_count = 0;
    p_stat[thread].cache2_count = 0;
    p_stat[thread].cache3_count = 0;
    p_stat[thread].lfb_count = 0;
    p_stat[thread].memory_count = 0;
    p_stat[thread].remote_memory_count = 0;
    p_stat[thread].remote_cache_count = 0;
    p_stat[thread].total_count = 0;

    while (p_stat[thread].consumed < p_stat[thread].head) {
      if (p_stat[thread].header->size == 0) {
  	fprintf(stderr, "Error: invalid header size = 0\n");
  	abort();
      }
      if (p_stat[thread].header -> type == PERF_RECORD_SAMPLE) {
  	struct read_sample *sample = (struct read_sample *)((char *)(p_stat[thread].header) + 8);
	if (is_served_by_local_NA_miss(sample->data_src)) {
  	  p_stat[thread].na_miss_count++;
  	}
	if (is_served_by_local_cache1(sample->data_src)) {
  	  p_stat[thread].cache1_count++;
	}
	if (is_served_by_local_cache2(sample->data_src)) {
  	  p_stat[thread].cache2_count++;
	}
	if (is_served_by_local_cache3(sample->data_src)) {
  	  p_stat[thread].cache3_count++;
	}
	if (is_served_by_local_lfb(sample->data_src)) {
  	  p_stat[thread].lfb_count++;
	}
  	if (is_served_by_local_memory(sample->data_src)) {
  	  p_stat[thread].memory_count++;
  	}
  	if (is_served_by_remote_memory(sample->data_src)) {
  	  p_stat[thread].remote_memory_count++;
  	}
  	if (is_served_by_remote_cache_or_local_memory(sample->data_src)) {
  	  p_stat[thread].remote_cache_count++;
  	}
  	p_stat[thread].total_count++;


#if 0
	printf("pc=%" PRIx64 ", @=%" PRIx64 ", src level=%s, latency=%" PRIu64 "\n", sample->ip, sample->addr, get_data_src_level(sample->data_src), sample->weight);
#endif
	struct memory_info_list* p_node = find_mem_info_from_addr(sample->addr);
	if(p_node) {
	  p_node->mem_info.read_access++;
#if 0
	  printf("\tin buffer %p (read hits=%d)\n", p_node, p_node->mem_info.read_access);
#endif
	}
      }
      p_stat[thread].consumed += p_stat[thread].header->size;
      p_stat[thread].header = (struct perf_event_header *)((char *)p_stat[thread].header + p_stat[thread].header -> size);
    }
  }

  for (thread = 0; thread < sm->nb_threads; thread++) {

    printf("\n");
    printf("head = %" PRIu64 " compared to max = %zu\n", p_stat[thread].head, sm->mmap_len);
    printf("Thread %d: %-8d samples\n", thread, p_stat[thread].total_count);
    if(p_stat[thread].cache1_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].cache1_count, "local cache 1", (100.0 * p_stat[thread].cache1_count / p_stat[thread].total_count));
    if(p_stat[thread].cache2_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].cache2_count, "local cache 2", (100.0 * p_stat[thread].cache2_count / p_stat[thread].total_count));
    if(p_stat[thread].cache3_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].cache3_count, "local cache 3", (100.0 * p_stat[thread].cache3_count / p_stat[thread].total_count));
    if(p_stat[thread].lfb_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].lfb_count, "local cache LFB", (100.0 * p_stat[thread].lfb_count / p_stat[thread].total_count));
    if(p_stat[thread].memory_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].memory_count, "local memory", (100.0 * p_stat[thread].memory_count / p_stat[thread].total_count));
    if(p_stat[thread].remote_cache_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].remote_cache_count, "remote cache or local memory", (100.0 * p_stat[thread].remote_cache_count / p_stat[thread].total_count));
    if(p_stat[thread].remote_memory_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].remote_memory_count, "remote memory", (100.0 * p_stat[thread].remote_memory_count / p_stat[thread].total_count));
    if(p_stat[thread].na_miss_count > 0)
      printf("Thread %d: %-8d %-30s %0.3f%%\n", thread, p_stat[thread].na_miss_count, "unknown l3 miss", (100.0 * p_stat[thread].na_miss_count / p_stat[thread].total_count));
  }
}


void ma_finalize() {
  ma_thread_finalize();
  __record_infos=0;

  printf("---------------------------------\n");
  printf("         MEM ANALYZER\n");
  printf("---------------------------------\n");
  collect_samples();

  struct memory_info_list * p_node = mem_list;
  while(p_node) {
    uint64_t duration = p_node->mem_info.free_date?
      p_node->mem_info.free_date-p_node->mem_info.alloc_date:
      0;
    printf("buffer %p (%lu - %lu bytes) allocated at %x, freed at %x (duration =%lu ticks). %d read accesses\n",
	   p_node->mem_info.buffer_addr,
	   p_node->mem_info.initial_buffer_size,
	   p_node->mem_info.buffer_size,
	   p_node->mem_info.alloc_date,
	   p_node->mem_info.free_date,
	   duration,
	   p_node->mem_info.read_access);
    p_node = p_node->next;
  }
}
