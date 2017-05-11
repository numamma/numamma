#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "mem_sampling.h"
#include "mem_analyzer.h"

int sampling_rate = 10000;

unsigned nb_samples_total = 0;
unsigned nb_found_samples_total = 0;

/* set to 1 if we are currently sampling memory accesses */
static __thread int is_sampling = 0;

/* set to 1 once the thread was finalized */
static __thread int status_finalized = 0;

struct timespec t_init;

double get_cur_date() {
  struct timespec t1;
  clock_gettime(CLOCK_REALTIME, &t1);
  double duration = ((t1.tv_sec-t_init.tv_sec)*1e9+(t1.tv_nsec-t_init.tv_nsec))/1e9;
  return duration;
}

__thread struct numap_sampling_measure sm;
__thread struct numap_sampling_measure sm_wr;


/* base address of the buffer where we store samples */
void* sample_buffer = NULL;
/* address of the next free slot in the buffer */
void* sample_buffer_offset = NULL;
/* allocated size of the buffer */
size_t sample_buffer_size = 0;
/* available size of the buffer */
size_t sample_remaining_size = 0;


/* if set to 1, samples are copied to a buffer at runtime and analyzed after the
 * end of the application. -> low overlead, high memory consumption
 * if set to 0, samples are analyzed at runtime. -> high overhead, low memory consumption.
 */
static int offline_analysis = 0;

static void __analyze_sampling(struct numap_sampling_measure *sm,
			       enum access_type access_type);
static void __copy_samples(struct numap_sampling_measure *sm,
			   enum access_type access_type);

void mem_sampling_init() {

#if USE_NUMAP
  clock_gettime(CLOCK_REALTIME, &t_init);

  char* sampling_rate_str = getenv("SAMPLING_RATE");
  if(sampling_rate_str)
    sampling_rate=atoi(sampling_rate_str);
  printf("Sampling rate: %d\n", sampling_rate);

  numap_init();

  char* str=getenv("OFFLINE_ANALYSIS");
  if(str) {
    printf("Memory access will be analyzed offline\n");
    offline_analysis=1;
  }
#endif
}

void mem_sampling_thread_init() {
  pid_t tid = syscall(SYS_gettid);
  int res = numap_sampling_init_measure(&sm, 1, sampling_rate, 32);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  res = numap_sampling_init_measure(&sm_wr, 1, sampling_rate, 32);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  /* for now, only collect info on the current thread */
  sm.tids[0] = tid;
  mem_sampling_start();
}

void mem_sampling_thread_finalize() {
  mem_sampling_collect_samples();
  status_finalized = 1;
}

void mem_sampling_statistics() {
  printf("%d samples (including %d samples that match a known memory buffer)\n",
	 nb_samples_total, nb_found_samples_total);
  if(offline_analysis) {
    printf("Buffer size for sample: %llu bytes\n", sample_buffer_size);
  }
}

/* make sure this function is not called by collect_samples or start_sampling.
 * This could be the case if one of these functions fail and calls exit
 */
static __thread int setting_sampling_stuff=0;

void mem_sampling_start() {
#if USE_NUMAP
  if(status_finalized)
    return;

  debug_printf("[%lx][%lf] Start sampling %d\n", syscall(SYS_gettid), get_cur_date(), is_sampling);

  if(is_sampling) {
    printf("[%lx]is_sampling = %d !\n", syscall(SYS_gettid), is_sampling);
    abort();
  }
  is_sampling=1;

  /* make sure this function is not called by collect_samples or start_sampling.
   * This could be the case if one of these functions fail and calls exit
   */
  if(setting_sampling_stuff)
    return;
  setting_sampling_stuff=1;

  // Start memory read access sampling
  int res = numap_sampling_read_start(&sm);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_start error : %s\n", numap_error_message(res));
    if(res ==  ERROR_PERF_EVENT_OPEN && errno == EACCES) {
      fprintf(stderr, "try running 'echo 1 > /proc/sys/kernel/perf_event_paranoid' to fix the problem\n");
    }
    abort();
  }

  res = numap_sampling_write_start(&sm_wr);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_start error : %s\n", numap_error_message(res));
    abort();
  }
  setting_sampling_stuff=0;
#endif	/* USE_NUMAP */
}

void mem_sampling_collect_samples() {
#if USE_NUMAP
  if(status_finalized)
    return;

  debug_printf("[%lx][%lf] Collect samples %d\n", syscall(SYS_gettid), get_cur_date(), is_sampling);

  if(!is_sampling) {
    printf("[%lx] Trying to collect sampling data, but sampling has not started !\n", syscall(SYS_gettid));
    abort();
  }
  is_sampling = 0;

  /* make sure this function is not called by collect_samples or start_sampling.
   * This could be the case if one of these functions fail and calls exit
   */
  if(setting_sampling_stuff)
    return;
  setting_sampling_stuff=1;

  // Stop memory read access sampling
  int res = numap_sampling_read_stop(&sm);
  if(res < 0) {
    printf("numap_sampling_stop error : %s\n", numap_error_message(res));
    abort();
  }
  debug_printf("read_stop done\n");
  // Print memory read sampling results
  __analyze_sampling(&sm, ACCESS_READ);
  debug_printf("analyze done\n");
  res = numap_sampling_write_stop(&sm_wr);
  if(res < 0) {
    printf("numap_sampling_stop error : %s\n", numap_error_message(res));
    abort();
  }

  // Print memory read sampling results
  __analyze_sampling(&sm_wr, ACCESS_WRITE);
  setting_sampling_stuff=0;
#endif	/* USE_NUMAP */
}


/* copy the samples to a buffer so that they can be analyzed later */
static void __copy_samples(struct numap_sampling_measure *sm,
			   enum access_type access_type) {

  /* well, sm->nb_threads should be 1, but let's make things generic */
  int thread;
  for (thread = 0; thread < sm->nb_threads; thread++) {
    size_t sample_size = 0;
    struct mem_sampling_stat p_stat;
    struct perf_event_mmap_page *metadata_page = sm->metadata_pages_per_tid[thread];

    char* start_addr = (char *)metadata_page+metadata_page->data_offset;
    /* where the data begins */
    p_stat.head = metadata_page -> data_head;
    /* On SMP-capable platforms, after reading the data_head value,
     * user space should issue an rmb().
     */
    rmb();
    p_stat.header = (struct perf_event_header *)((char *)metadata_page + sm->page_size);
    sample_size =  p_stat.head;

    debug_printf("about to copy %d bytes starting at %p (or is it %p ?)\n", sample_size,
	   start_addr, p_stat.header);

    p_stat.consumed = 0;
    while (p_stat.consumed < p_stat.head) {
      if (p_stat.header->size == 0) {
  	fprintf(stderr, "Error: invalid header size = 0\n");
  	abort();
      }
      p_stat.consumed += p_stat.header->size;
      p_stat.header = (struct perf_event_header *)((char *)p_stat.header + p_stat.header->size);
    }
    sample_size = (char*)p_stat.header-start_addr;
	   
    p_stat.header = (struct perf_event_header *)((char *)metadata_page + sm->page_size);
    p_stat.consumed = 0;

    while(sample_size > sample_remaining_size) {
      /* allocate the buffer */
            if(sample_buffer_size == 0) {
	/* first allocation */
	sample_buffer_size = 4096*1024; /* allocate 4MB */
	sample_remaining_size = sample_buffer_size;
      } else {
	/* double the size of the buffer */
	sample_remaining_size += sample_buffer_size;
	sample_buffer_size += sample_buffer_size;
      }
      void* ptr = librealloc(sample_buffer, sample_buffer_size);
      if(!ptr) {
	fprintf(stderr, "realloc failed !\n");
	abort();
      }
      sample_buffer = ptr;
    }

    //    memcpy(next_sample_buffer, (void*)p_stat.head, sample_size);
    void* dest_addr = (uintptr_t)sample_buffer + (uintptr_t)sample_buffer_offset;
#if 1
    memcpy(dest_addr, start_addr, sample_size);
#endif
    sample_buffer_offset += sample_size;
    sample_remaining_size -= sample_size;

  
    //    p_stat.header = (struct perf_event_header *)((char *)metadata_page + sm->page_size);
    //    p_stat.consumed = 0;
    p_stat.consumed = sample_size;
    p_stat.header = (struct perf_event_header *)((char *)p_stat.header + sample_size);

    debug_printf("[%d] copied %llu bytes\n", thread_rank, sample_size);
  }
}

void __analyze_sampling(struct numap_sampling_measure *sm,
			enum access_type access_type) {
  if(offline_analysis) {
    __copy_samples(sm, access_type);
    return;
  }
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
	struct sample *sample = (struct sample *)((char *)(p_stat.header) + 8);
	nb_samples++;
	struct memory_info* mem_info = ma_find_mem_info_from_addr(sample->addr);
	if(mem_info) {
	  found_samples++;

	  mem_info->count[thread_rank][access_type].total_count++;

	  if (is_served_by_local_NA_miss(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].na_miss_count++;
	  }
	  if (is_served_by_local_cache1(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].cache1_count++;
	  }
	  if (is_served_by_local_cache2(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].cache2_count++;
	  }
	  if (is_served_by_local_cache3(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].cache3_count++;
	  }
	  if (is_served_by_local_lfb(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].lfb_count++;
	  }
	  if (is_served_by_local_memory(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].memory_count++;
	  }
	  if (is_served_by_remote_memory(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].remote_memory_count++;
	  }
	  if (is_served_by_remote_cache_or_local_memory(sample->data_src)) {
	    mem_info->count[thread_rank][access_type].remote_cache_count++;
	  }
	}

	if(_dump) {
	  fprintf(dump_file, "[%lx]  pc=%" PRIx64 ", @=%" PRIx64 ", src level=%s, latency=%" PRIu64 " -- node=%p\n",
		  syscall(SYS_gettid), sample->ip, sample->addr, get_data_src_level(sample->data_src),
		  sample->weight, mem_info);
	}
      }

      p_stat.consumed += p_stat.header->size;
      p_stat.header = (struct perf_event_header *)((char *)p_stat.header + p_stat.header->size);
    }
  }

  if(nb_samples>0) {
    debug_printf("[%lf] \tnb_samples = %d (including %d mem blocks)\n", get_cur_date(), nb_samples, found_samples);
    nb_samples_total += nb_samples;
    nb_found_samples_total += found_samples;
  }
}
