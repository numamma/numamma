#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "mem_sampling.h"
#include "mem_analyzer.h"

int sampling_rate = 10000;

/* set to 1 if we are currently sampling memory accesses */
static __thread int is_sampling = 0;

struct timespec t_init;

double get_cur_date() {
  struct timespec t1;
  clock_gettime(CLOCK_REALTIME, &t1);
  double duration = ((t1.tv_sec-t_init.tv_sec)*1e9+(t1.tv_nsec-t_init.tv_nsec))/1e9;
  return duration;
}

__thread struct numap_sampling_measure sm;
__thread struct numap_sampling_measure sm_wr;

void mem_sampling_init() {

#if USE_NUMAP
  clock_gettime(CLOCK_REALTIME, &t_init);

  char* sampling_rate_str = getenv("SAMPLING_RATE");
  if(sampling_rate_str)
    sampling_rate=atoi(sampling_rate_str);
  printf("Sampling rate: %d\n", sampling_rate);

  numap_init();
#endif
}

void mem_sampling_thread_init() {
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
  mem_sampling_start();
}

void mem_sampling_thread_finalize() {
  mem_sampling_collect_samples();
}


void mem_sampling_start() {
#if USE_NUMAP
  debug_printf("[%lx][%lf] Start sampling %d\n", syscall(SYS_gettid), get_cur_date(), is_sampling);

  if(is_sampling) {
    printf("[%lx]is_sampling = %d !\n", syscall(SYS_gettid), is_sampling);
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

  res = numap_sampling_write_start(&sm_wr);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_start error : %s\n", numap_error_message(res));
    abort();
  }
#endif	/* USE_NUMAP */
}

void mem_sampling_collect_samples() {
#if USE_NUMAP
  debug_printf("[%lx][%lf] Collect samples %d\n", syscall(SYS_gettid), get_cur_date(), is_sampling);

  if(!is_sampling) {
    printf("[%lx] is_sampling = %d !\n", syscall(SYS_gettid), is_sampling);
    abort();
  }
  is_sampling = 0;

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

#endif	/* USE_NUMAP */
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
	struct sample *sample = (struct sample *)((char *)(p_stat.header) + 8);
	nb_samples++;
	struct memory_info_list* p_node = ma_find_mem_info_from_addr(sample->addr);
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

	if(_dump) {
	  fprintf(dump_file, "[%lx]  pc=%" PRIx64 ", @=%" PRIx64 ", src level=%s, latency=%" PRIu64 "\n",
		  syscall(SYS_gettid), sample->ip, sample->addr, get_data_src_level(sample->data_src),
		  sample->weight);
	}
      }

      p_stat.consumed += p_stat.header->size;
      p_stat.header = (struct perf_event_header *)((char *)p_stat.header + p_stat.header->size);
    }
  }

  if(nb_samples>0)
    debug_printf("[%lf] \tnb_samples = %d (including %d mem blocks)\n", get_cur_date(), nb_samples, found_samples);
}
