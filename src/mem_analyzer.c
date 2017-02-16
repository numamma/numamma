#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <execinfo.h>
#include <errno.h>
#include "mem_analyzer.h"
#include "numap.h"

#define HAVE_LIBBACKTRACE 1
#if HAVE_LIBBACKTRACE
#include <libbacktrace/backtrace.h>
#include <libbacktrace/backtrace-supported.h>
#endif

#define USE_NUMAP 1

static int  __record_infos = 0;
static int sampling_rate = 10000;
static int _verbose = 0;

struct memory_info_list*mem_list = NULL;
__thread struct numap_sampling_measure sm;
__thread struct numap_sampling_measure sm_wr;

extern void* (*libcalloc)(size_t nmemb, size_t size);
extern void* (*libmalloc)(size_t size);
extern void (*libfree)(void *ptr);
extern void* (*librealloc)(void *ptr, size_t size);

void collect_samples();
void start_sampling();
void __analyze_sampling(struct numap_sampling_measure *sm,
			enum access_type access_type);

struct timespec t_init;
double get_cur_date() {
  struct timespec t1;
  clock_gettime(CLOCK_REALTIME, &t1);
  double duration = ((t1.tv_sec-t_init.tv_sec)*1e9+(t1.tv_nsec-t_init.tv_nsec))/1e9;
}

/* todo:
 * - intercept thread creation and run numap_sampling_init_measure for each thread
 * - set an alarm every 1ms to collect the sampling info
 * - choose the buffer size
 * - collect read/write accesses
 */
void ma_init() {
#if USE_NUMAP
  clock_gettime(CLOCK_REALTIME, &t_init);

  char* sampling_rate_str = getenv("SAMPLING_RATE");
  if(sampling_rate_str)
    sampling_rate=atoi(sampling_rate_str);
  printf("Sampling rate: %d\n", sampling_rate);

  char* verbose_str = getenv("NUMMA_VERBOSE");
  if(verbose_str) {
    if(strcmp(verbose_str, "0")!=0) {
      _verbose = 1;
      printf("Verbose mode enabled\n");
    }
  }

  numap_init();
#endif
  ma_thread_init();
  __record_infos = 1;
}

static __thread int is_sampling=0;
void start_sampling() {
#if USE_NUMAP
  int previous_state = __record_infos;
  __record_infos = 0;
  if(_verbose)
    printf("[%d][%lf] -------------- Start sampling %d\n", syscall(SYS_gettid), get_cur_date(), is_sampling);

  if(is_sampling) {
    printf("is_sampling = %d !\n", is_sampling);
    abort();
  }
  is_sampling=1;
  // Start memory read access sampling
  int res = numap_sampling_read_start(&sm);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_start error : %s\n", numap_error_message(res));
    if(res ==  ERROR_PERF_EVENT_OPEN && errno == EACCES) {
      fprintf(stderr, "try running 'echo 1 > /proc/sys/kernel/perf_event_paranoid' to fix the problem\n");
    }
    abort();
  }

#if 0
  res = numap_sampling_write_start(&sm_wr);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_start error : %s\n", numap_error_message(res));
    abort();
  }
#endif
__record_infos = previous_state;
#endif
}

void collect_samples() {
#if USE_NUMAP
  int previous_state = __record_infos;
  __record_infos = 0;

  if(_verbose) {
    printf("[%d][%lf] -------------- Collect samples %d\n", syscall(SYS_gettid), get_cur_date(), is_sampling);
  }
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
  __analyze_sampling(&sm, ACCESS_READ);


#if 0
  res = numap_sampling_write_stop(&sm_wr);
  if(res < 0) {
    printf("numap_sampling_stop error : %s\n", numap_error_message(res));
    abort();
  }

  // Print memory read sampling results
  //  numap_sampling_read_print(&sm, 1);
  __analyze_sampling(&sm_wr, ACCESS_WRITE);
#endif

  __record_infos = previous_state;
#endif
}

void ma_thread_init() {
  pid_t tid = syscall(SYS_gettid);
  printf("New thread: %d\n", tid);
  int res = numap_sampling_init_measure(&sm, 1, sampling_rate, 64);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  res = numap_sampling_init_measure(&sm_wr, 1, sampling_rate, 64);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  /* for now, only collect info on the current thread */
  sm.tids[0] = tid;
  start_sampling();

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

#if HAVE_LIBBACKTRACE
__thread char current_frame[4096];

static void error_callback(void *data, const char *msg, int errnum)
{
  fprintf(stderr, "ERROR: %s (%d)", msg, errnum);
}

int backtrace_callback (void *data, uintptr_t pc,
			const char *filename, int lineno,
			const char *function) {
  //  printf("[%p] in %s:%d %s\n", pc, filename, lineno, function);
  char buffer[4096];
  snprintf(current_frame, 4096, "%s:%d %s", filename, lineno, function);
  return 0;
}
#endif /* HAVE_LIBBACKTRACE */


char* get_caller_function() {
  int backtrace_depth=15;
  void* buffer[backtrace_depth];
  /* get pointers to functions */

  int nb_calls = backtrace(buffer, backtrace_depth);
  //  assert(nb_calls>=backtrace_depth);

#if HAVE_LIBBACKTRACE
  struct backtrace_state *state = backtrace_create_state (NULL, BACKTRACE_SUPPORTS_THREADS,
							  error_callback, NULL);
#else
  char **functions;
  functions = backtrace_symbols(buffer, nb_calls);
#endif

  /* the current backtrace looks like this:
   * 0 - get_caller_function()
   * 1 - ma_record_malloc()
   * 2 - malloc()
   * 3 - caller_function()
   *
   * So, we need to get the name of the function in frame 2.
   */
  int frame_number = 3;
  char* retval = NULL;
  if(nb_calls < frame_number) {
    retval = libmalloc(sizeof(char)*16);
    sprintf(retval, "???");
  }
#if HAVE_LIBBACKTRACE
    backtrace_pcinfo (state, (uintptr_t) buffer[frame_number],
		      backtrace_callback,
		      error_callback,
		      NULL);
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", current_frame);
#else
    //    printf("func name is ... %s and nb_calls = %d\n", functions[frame_number], nb_calls);
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", functions[frame_number]);
#endif

#if ! HAVE_LIBBACKTRACE
  free(functions);
#endif

  return retval;
#if 0
  char nb_frames[15];
  sprintf(nb_frames, "%d", nb_calls);
  int i;
  for (i = 0; i < nb_calls; i++) {
#if HAVE_LIBBACKTRACE
    backtrace_pcinfo (state, (uintptr_t) buffer[i],
		      backtrace_callback,
		      error_callback,
		      NULL);
#else
    printf("func name is ... %s and nb_calls = %d\n", functions[i], nb_calls);
#endif
  }
  printf("\n");
#endif
#if ! HAVE_LIBBACKTRACE
  free(functions);
#endif
  //  eztrace_record_backtrace(15);
  return NULL;
}

void ma_record_malloc(struct mem_block_info* info) {
  if(! __record_infos)
    return;
  collect_samples();
  struct memory_info_list * p_node = libmalloc(sizeof(struct memory_info_list));

  /* todo: make this thread-safe */
  p_node->next = mem_list;
  mem_list = p_node;

  p_node->mem_info.alloc_date = new_date();
  p_node->mem_info.free_date = 0;
  p_node->mem_info.initial_buffer_size = info->size;
  p_node->mem_info.buffer_size = info->size;
  p_node->mem_info.buffer_addr = info->u_ptr;
  p_node->mem_info.caller = get_caller_function();
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
  start_sampling();
}

void ma_update_buffer_address(void *old_addr, void *new_addr) {
  if(! __record_infos)
    return;

  collect_samples();
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
  start_sampling();
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

void __analyze_sampling(struct numap_sampling_measure *sm,
			enum access_type access_type) {
  int thread;
  int nb_samples = 0;
  int found_samples = 0;
  for (thread = 0; thread < sm->nb_threads; thread++) {

    struct mem_sampling_stat p_stat;
    struct perf_event_mmap_page *metadata_page = sm->metadata_pages_per_tid[thread];
    p_stat.head = metadata_page -> data_head;
    rmb();
    p_stat.header = (struct perf_event_header *)((char *)metadata_page + sm->page_size);
    p_stat.consumed = 0;
    while (p_stat.consumed < p_stat.head) {
      if (p_stat.header->size == 0) {
  	fprintf(stderr, "Error: invalid header size = 0\n");
  	abort();
      }
      if (p_stat.header -> type == PERF_RECORD_SAMPLE) {
  	struct read_sample *sample = (struct read_sample *)((char *)(p_stat.header) + 8);
	nb_samples++;
	struct memory_info_list* p_node = find_mem_info_from_addr(sample->addr);
	if(p_node) {
	  found_samples++;

	  p_node->mem_info.count[access_type].total_count++;

	  if (is_served_by_local_NA_miss(sample->data_src)) {
	    p_node->mem_info.count[access_type].na_miss_count++;
	  }
	  if (is_served_by_local_cache1(sample->data_src)) {
	    p_node->mem_info.count[access_type].cache1_count++;
	  }
	  if (is_served_by_local_cache2(sample->data_src)) {
	    p_node->mem_info.count[access_type].cache2_count++;
	  }
	  if (is_served_by_local_cache3(sample->data_src)) {
	    p_node->mem_info.count[access_type].cache3_count++;
	  }
	  if (is_served_by_local_lfb(sample->data_src)) {
	    p_node->mem_info.count[access_type].lfb_count++;
	  }
	  if (is_served_by_local_memory(sample->data_src)) {
	    p_node->mem_info.count[access_type].memory_count++;
	  }
	  if (is_served_by_remote_memory(sample->data_src)) {
	    p_node->mem_info.count[access_type].remote_memory_count++;
	  }
	  if (is_served_by_remote_cache_or_local_memory(sample->data_src)) {
	    p_node->mem_info.count[access_type].remote_cache_count++;
	  }
	}
#if 1
	//	if(_verbose) {
	if(1) {
	  printf("[%d]  pc=%" PRIx64 ", @=%" PRIx64 ", src level=%s, latency=%" PRIu64 "\n",
		 syscall(SYS_gettid), sample->ip, sample->addr, get_data_src_level(sample->data_src),
		 sample->weight);
	}
#endif
      }

      p_stat.consumed += p_stat.header->size;
      p_stat.header = (struct perf_event_header *)((char *)p_stat.header + p_stat.header->size);
    }
  }

#if 0
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
#endif
  if(nb_samples>0)
    printf("[%lf] \tnb_samples = %d (including %d mem blocks)\n", get_cur_date(), nb_samples, found_samples);
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

      printf("buffer %p (%lu bytes) duration =%lu ticks. %d write accesses, %d read accesses. allocated : %s. read operation every %lf ticks\n",
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
}
