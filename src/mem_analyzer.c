#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <execinfo.h>
#include <errno.h>
#include <pthread.h>
#include "mem_intercept.h"
#include "mem_analyzer.h"
#include "mem_tools.h"
#include "mem_sampling.h"

//static __thread  int  __record_infos = 0;
static struct memory_info_list*mem_list = NULL;
static pthread_mutex_t mem_list_lock;

static __thread int is_record_safe = 1;
#define IS_RECORD_SAFE (is_record_safe)

#define PROTECT_RECORD do {			\
    assert(is_record_safe !=0);		\
    is_record_safe = 0;				\
  } while(0)

#define UNPROTECT_RECORD do {		\
    assert(is_record_safe == 0);		\
    is_record_safe = 1;			\
  } while(0)

/* todo:
 * - intercept thread creation and run numap_sampling_init_measure for each thread
 * - set an alarm every 1ms to collect the sampling info
 * - choose the buffer size
 * - collect read/write accesses
 */
void ma_init() {
  PROTECT_RECORD;
  pthread_mutex_init(&mem_list_lock, NULL);

  mem_sampling_init();
  ma_thread_init();
  UNPROTECT_RECORD;
}

void ma_thread_init() {
  mem_sampling_thread_init();
}

void ma_thread_finalize() {
  PROTECT_RECORD;
  mem_sampling_thread_finalize();
  pid_t tid = syscall(SYS_gettid);
  printf("End of thread: %d\n", tid);
  UNPROTECT_RECORD;
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

static
int is_address_in_buffer(uint64_t addr, struct memory_info *buffer){
  void* addr_ptr = (void*)addr;
  if(buffer->buffer_addr <= addr_ptr &&
     addr_ptr < buffer->buffer_addr + buffer->buffer_size)
    return 1;
  return 0;
}

struct memory_info_list*
ma_find_mem_info_from_addr(uint64_t ptr) {
  struct memory_info_list* retval = NULL;

  pthread_mutex_lock(&mem_list_lock);
  struct memory_info_list * p_node = mem_list;
  while(p_node) {
    if(is_address_in_buffer(ptr, &p_node->mem_info)) {
      retval = p_node;
      goto out;
    }
    p_node = p_node->next;
  }

 out:
  pthread_mutex_unlock(&mem_list_lock);
  return retval;
}

void ma_record_malloc(struct mem_block_info* info) {
  if(!IS_RECORD_SAFE)
    return;
  PROTECT_RECORD;

  mem_sampling_collect_samples();
  struct memory_info_list * p_node = libmalloc(sizeof(struct memory_info_list));

  p_node->mem_info.alloc_date = new_date();
  p_node->mem_info.free_date = 0;
  p_node->mem_info.initial_buffer_size = info->size;
  p_node->mem_info.buffer_size = info->size;
  p_node->mem_info.buffer_addr = info->u_ptr;

  /* the current backtrace looks like this:
   * 0 - get_caller_function()
   * 1 - ma_record_malloc()
   * 2 - malloc()
   * 3 - caller_function()
   *
   * So, we need to get the name of the function in frame 3.
   */
  p_node->mem_info.caller = get_caller_function(3);
  int i;
  for(i=0; i<ACCESS_MAX; i++) {
    p_node->mem_info.count[i].total_count = 0;

    p_node->mem_info.count[i].na_miss_count = 0;
    p_node->mem_info.count[i].cache1_count = 0;
    p_node->mem_info.count[i].cache2_count = 0;
    p_node->mem_info.count[i].cache3_count = 0;
    p_node->mem_info.count[i].lfb_count = 0;
    p_node->mem_info.count[i].memory_count = 0;
    p_node->mem_info.count[i].remote_memory_count = 0;
    p_node->mem_info.count[i].remote_cache_count = 0;
  }

  debug_printf("[%lu] [%lx] malloc(%lu bytes) -> u_ptr=%p\n",
	       p_node->mem_info.alloc_date,
	       pthread_self(),
	       p_node->mem_info.initial_buffer_size,
	       p_node->mem_info.buffer_addr);
  pthread_mutex_lock(&mem_list_lock);
  p_node->next = mem_list;
  mem_list = p_node;
  pthread_mutex_unlock(&mem_list_lock);

  mem_sampling_start();
  UNPROTECT_RECORD;
}

void ma_update_buffer_address(void *old_addr, void *new_addr) {
  if(!IS_RECORD_SAFE)
    return;
  PROTECT_RECORD;

  mem_sampling_collect_samples();
  /* todo: do we really need the lock here ?
   * when this list is modified, it is only for inserting new nodes, so browsing the list could
   * be done without holding the lock ?
   */
  pthread_mutex_lock(&mem_list_lock);
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
  pthread_mutex_unlock(&mem_list_lock);
  mem_sampling_start();
  UNPROTECT_RECORD;
}

void ma_record_free(struct mem_block_info* info) {
  if(!IS_RECORD_SAFE)
    return;
  PROTECT_RECORD;
  mem_sampling_collect_samples();

  pthread_mutex_lock(&mem_list_lock);
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
  debug_printf("[%lu] [%lx] free(%p)\n",
	       p_node->mem_info.free_date,
	       pthread_self(),
	       p_node->mem_info.buffer_addr);

  pthread_mutex_unlock(&mem_list_lock);

  mem_sampling_start();
  UNPROTECT_RECORD;
}


void ma_finalize() {
  ma_thread_finalize();
  PROTECT_RECORD;
  
  printf("---------------------------------\n");
  printf("         MEM ANALYZER\n");
  printf("---------------------------------\n");
  //  collect_samples();

  pthread_mutex_lock(&mem_list_lock);

  struct memory_info_list * p_node = mem_list;
  while(p_node) {
    uint64_t duration = p_node->mem_info.free_date?
      p_node->mem_info.free_date-p_node->mem_info.alloc_date:
      0;
    if(p_node->mem_info.count[ACCESS_WRITE].total_count > 0 ||
       p_node->mem_info.count[ACCESS_READ].total_count > 0) {

      double r_access_frequency;
      if(p_node->mem_info.count[ACCESS_READ].total_count)
	r_access_frequency = (duration/sampling_rate)/p_node->mem_info.count[ACCESS_READ].total_count;
      else
	r_access_frequency = 0;
      double w_access_frequency;
      if(p_node->mem_info.count[ACCESS_WRITE].total_count)
	w_access_frequency = (duration/sampling_rate)/p_node->mem_info.count[ACCESS_WRITE].total_count;
      else
	w_access_frequency = 0;

      debug_printf("buffer %p (%lu bytes) duration =%lu ticks. %d write accesses, %d read accesses. allocated : %s. read operation every %lf ticks\n",
		   p_node->mem_info.buffer_addr,
		   p_node->mem_info.initial_buffer_size,
		   duration,
		   p_node->mem_info.count[ACCESS_WRITE].total_count,
		   p_node->mem_info.count[ACCESS_READ].total_count,
		   p_node->mem_info.caller,
		   r_access_frequency);
    }
    p_node = p_node->next;
  }
  if(_dump) {
    fclose(dump_file);
  }
  pthread_mutex_unlock(&mem_list_lock);
  UNPROTECT_RECORD;
}
