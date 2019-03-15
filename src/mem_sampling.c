#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#include "mem_sampling.h"
#include "mem_analyzer.h"
#include "mem_tools.h"

int sampling_rate = 10000;

/* if set to one, numamma won't search for the buffer that match a sample */
int drop_samples=0;

unsigned nb_samples_total = 0;
unsigned nb_found_samples_total = 0;

/* set to 1 if we are currently sampling memory accesses */
static __thread volatile int is_sampling = 0;

/* set to 1 once the thread was finalized */
static __thread int status_finalized = 0;

struct timespec t_init;

struct mem_counters global_counters[2];
double get_cur_date() {
  struct timespec t1;
  clock_gettime(CLOCK_REALTIME, &t1);
  double duration = ((t1.tv_sec-t_init.tv_sec)*1e9+(t1.tv_nsec-t_init.tv_nsec))/1e9;
  return duration;
}

__thread struct numap_sampling_measure sm;
__thread struct numap_sampling_measure sm_wr;
__thread date_t start_date;

/* base address of the buffer where we store samples */
void* sample_buffer = NULL;
/* address of the next free slot in the buffer */
void* sample_buffer_offset = NULL;
/* allocated size of the buffer */
size_t sample_buffer_size = 0;
/* available size of the buffer */
size_t sample_remaining_size = 0;

/* memory allocator for copying samples */
struct mem_allocator *sample_mem = NULL;

struct sample_list {
  struct sample_list*next;
  void* buffer;
  size_t buffer_size;
  enum access_type access_type;
  date_t start_date;
  date_t stop_date;
  unsigned thread_rank;
};
struct sample_list *samples = NULL;
static int nb_sample_buffers = 0;

/* if set to 1, samples are copied to a buffer at runtime and analyzed after the
 * end of the application. -> low overlead, high memory consumption
 * if set to 0, samples are analyzed at runtime. -> high overhead, low memory consumption.
 */
int offline_analysis = 1;

static void __analyze_sampling(struct numap_sampling_measure *sm,
			       enum access_type access_type);
static void __copy_samples(struct numap_sampling_measure *sm,
			   enum access_type access_type);

static void __analyze_buffer(struct sample_list* samples,
			     int *nb_samples,
			     int *found_samples);

static void __print_samples(struct sample_list* samples,
			    int *nb_samples,
			    int *found_samples);

void sig_handler(int signal) {
  if(IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    if(is_sampling) {
      mem_sampling_collect_samples();
      mem_sampling_resume();
    }
    UNPROTECT_FROM_RECURSION;
  }
}

/*  in ns */
long __alarm_interval = 10 * 1000000;
int alarm_enabled = 0;
__thread int alarm_set = 0;

void __set_alarm() {
  if(__alarm_interval>=0 && alarm_enabled && (! alarm_set)) {
    alarm_set = 1;
    struct sigevent sevp;
    sevp.sigev_notify=SIGEV_THREAD_ID | SIGEV_SIGNAL;
    sevp.sigev_signo=SIGALRM;
    sevp.sigev_value.sival_int=0;
    sevp.sigev_notify_function = NULL;
    sevp.sigev_notify_attributes=NULL;
    sevp._sigev_un._tid = syscall(SYS_gettid);
    
    timer_t *t = malloc(sizeof(timer_t));
    int ret = timer_create(CLOCK_REALTIME, &sevp, t);      
    if(ret != 0){
      perror("timer create failed");
      abort();
    }
    struct itimerspec new_value, old_value;
    new_value.it_interval.tv_sec=0;
    new_value.it_interval.tv_nsec=__alarm_interval;
    
    new_value.it_value.tv_sec=0;
    new_value.it_value.tv_nsec=__alarm_interval;
    
    ret = timer_settime(*t,0, &new_value, &old_value);
      
    if(ret != 0){
      perror("timer settime failed");
      abort();
    }
  }
}

void mem_sampling_init() {
#if USE_NUMAP
  clock_gettime(CLOCK_REALTIME, &t_init);

  char* sampling_rate_str = getenv("SAMPLING_RATE");
  if(sampling_rate_str)
    sampling_rate=atoi(sampling_rate_str);
  printf("Sampling rate: %d\n", sampling_rate);

  char* drop_samples_str=getenv("DROP_SAMPLES");
  if(drop_samples_str) {
    drop_samples=1;
  }

  int err = numap_init();
  if(err != 0) {
    fprintf(stderr, "Error while initializing numap: %s\n", numap_error_message(err));
    abort();
  }

  char* str=getenv("OFFLINE_ANALYSIS");
  if(str) {
    printf("Memory access will be analyzed offline\n");
    offline_analysis = 1;
    mem_allocator_init(&sample_mem, sizeof(struct sample_list), 1024);
  }

  str=getenv("NUMAMMA_ALARM");
  if(str) {
    long interval=atol(str);
    printf("Setting an alarm every %ld ms\n", interval);
    
    __alarm_interval = interval* 1000000;
    alarm_enabled=1;
    offline_analysis = 1;
    mem_allocator_init(&sample_mem, sizeof(struct sample_list), 1024);
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


  struct sigaction s;  
  s.sa_handler = sig_handler;  
  int signo=SIGALRM;
  int ret = sigaction(signo, &s, NULL);
  if(ret<0) {  
    perror("sigaction failed");  
    abort();  
  }

  __set_alarm();
  mem_sampling_start();
}

extern uint64_t avg_pos;
void print_counters(struct mem_counters* counters) {
  for(int i=0; i< ACCESS_MAX; i++){
    if(i==ACCESS_READ) {
      printf("--------------------------------------\n");
      printf("Summary of all the read memory access:\n");
    } else {
      printf("--------------------------------------\n");
      printf("Summary of all the write memory access:\n");
    }
#define PERCENT(__c) (100.*counters[i].__c/counters[i].total_count)
    printf("Total count          : \t %ld\n", counters[i].total_count);
    printf("Total weigh          : \t %ld\n", counters[i].total_weight);
    printf("N/A                  : \t %ld (%f %%)\n", counters[i].na_miss_count, PERCENT(na_miss_count));
    printf("L1 Hit               : \t %ld (%f %%)\n", counters[i].cache1_hit_count, PERCENT(cache1_hit_count));	  
    printf("L2 Hit               : \t %ld (%f %%)\n", counters[i].cache2_hit_count, PERCENT(cache2_hit_count));	  
    printf("L3 Hit               : \t %ld (%f %%)\n", counters[i].cache3_hit_count, PERCENT(cache3_hit_count));	  
    printf("LFB Hit              : \t %ld (%f %%)\n", counters[i].lfb_hit_count, PERCENT(lfb_hit_count));	     	  
    printf("Local RAM Hit        : \t %ld (%f %%)\n", counters[i].local_ram_hit_count, PERCENT(local_ram_hit_count));	     
    printf("Remote RAM Hit       : \t %ld (%f %%)\n", counters[i].remote_ram_hit_count, PERCENT(remote_ram_hit_count));     	  
    printf("Remote cache Hit     : \t %ld (%f %%)\n", counters[i].remote_cache_hit_count, PERCENT(remote_cache_hit_count));   	  
    printf("IO memory Hit        : \t %ld (%f %%)\n", counters[i].io_memory_hit_count, PERCENT(io_memory_hit_count));	     
    printf("Uncached memory Hit  : \t %ld (%f %%)\n", counters[i].uncached_memory_hit_count, PERCENT(uncached_memory_hit_count));

    printf("\n");

    printf("L1 Miss              : \t %ld (%f %%)\n", counters[i].cache1_miss_count, PERCENT(cache1_miss_count));
    printf("L2 Miss              : \t %ld (%f %%)\n", counters[i].cache2_miss_count, PERCENT(cache2_miss_count));
    printf("L3 Miss              : \t %ld (%f %%)\n", counters[i].cache3_miss_count, PERCENT(cache3_miss_count));
    printf("LFB Miss             : \t %ld (%f %%)\n", counters[i].lfb_miss_count, PERCENT(lfb_miss_count));
    printf("Local RAM Miss       : \t %ld (%f %%)\n", counters[i].local_ram_miss_count, PERCENT(local_ram_miss_count));
    printf("Remote RAM Miss      : \t %ld (%f %%)\n", counters[i].remote_ram_miss_count,  PERCENT(remote_ram_miss_count));
    printf("Remote cache Miss    : \t %ld (%f %%)\n", counters[i].remote_cache_miss_count, PERCENT(remote_cache_miss_count));
    printf("IO Memory Miss       : \t %ld (%f %%)\n", counters[i].io_memory_miss_count, PERCENT(io_memory_miss_count));
    printf("Uncached memory Miss : \t %ld (%f %%)\n", counters[i].uncached_memory_miss_count, PERCENT(uncached_memory_miss_count));
  }
}

void mem_sampling_finalize() {
  printf("%s offline_analysis=%s\n", __FUNCTION__, offline_analysis ? "true" : "false");
  if(offline_analysis) {
    /* analyze the samples that were copied at runtime */
    ma_register_stack();

    printf("Analyzing %d sample buffers\n", nb_sample_buffers);
    start_tick(offline_sample_analysis);
    int nb_blocks = 0;
    size_t total_buffer_size = 0;
    while(samples) {
      int nb_samples = 0;
      int found_samples = 0;
      if(nb_blocks % 10 == 0) {
	fflush(stdout);
	printf("\rAnalyzing sample buffer %d/%d [%lx - %lx]. Total samples so far: %d",
	       nb_blocks, nb_sample_buffers,
	       samples->start_date, samples->stop_date, nb_samples_total);
     }
      __analyze_buffer(samples, &nb_samples, &found_samples);
      nb_samples_total += nb_samples;
      nb_found_samples_total += found_samples;
      total_buffer_size += samples->buffer_size;
      struct sample_list *prev = samples;
      samples = samples->next;
      nb_blocks++;
      free(prev->buffer);
      free(prev);
    }
    printf("\n");
    printf("Total: %d samples including %d matches in %d blocks (%lu bytes)\n", nb_samples_total, nb_found_samples_total, nb_blocks, total_buffer_size);
    printf("avg position: %" PRIu64 "\n", avg_pos/nb_samples_total);
    stop_tick(offline_sample_analysis);
    printf("Offline analysis took %lf s\n",tick_duration(offline_sample_analysis)/1e9);
  }

  print_counters(global_counters);
}

void mem_sampling_thread_finalize() {
  mem_sampling_collect_samples();
  numap_sampling_end(&sm);
  numap_sampling_end(&sm_wr);
  status_finalized = 1;
}

void mem_sampling_statistics() {
  float percent = 100.0*(nb_samples_total-nb_found_samples_total)/nb_samples_total;
  printf("%d samples (including %d samples that do not match a known memory buffer / %f%%)\n",
	 nb_samples_total, nb_samples_total-nb_found_samples_total, percent);
  if(offline_analysis) {
    printf("Buffer size for sample: %zu bytes\n", sample_buffer_size);
  }
}

/* make sure this function is not called by collect_samples or start_sampling.
 * This could be the case if one of these functions fail and calls exit
 */
static __thread int setting_sampling_stuff=0;

void mem_sampling_resume() {
#if USE_NUMAP
  if(status_finalized)
    return;

  debug_printf("in %s : [tid=%lx][cur_date=%lf] Resume sampling %d\n",
	       __FUNCTION__,
	       syscall(SYS_gettid), get_cur_date(), is_sampling);

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

  start_date = new_date();

  // Resume read sampling
  int res = numap_sampling_resume(&sm);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_resume error : %s\n", numap_error_message(res));
    if(res ==  ERROR_PERF_EVENT_OPEN && errno == EACCES) {
      fprintf(stderr, "try running 'echo 1 > /proc/sys/kernel/perf_event_paranoid' to fix the problem\n");
    }
    abort();
  }

  // Resume write sampling if needed
  if (numap_sampling_write_supported()) {
    res = numap_sampling_resume(&sm_wr);
    if(res < 0) {
      fprintf(stderr, "numap_sampling_resume error : %s\n", numap_error_message(res));
      abort();
    }
  }

  setting_sampling_stuff=0;
#endif	/* USE_NUMAP */
}

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

  start_date = new_date();
  //  clock_gettime(CLOCK_MONOTONIC, &start_date);
  // Start memory read access sampling

  /* TODO: implement numap_sampling_read_resume(&sm)
   * this function would only call ioctl (there's no need to call perf_event_open, mmap, etc. again
   */
  int res = numap_sampling_read_start_generic(&sm, SAMPLING_TYPE);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_read_start error : %s\n", numap_error_message(res));
    if(res ==  ERROR_PERF_EVENT_OPEN && errno == EACCES) {
      fprintf(stderr, "try running 'echo 1 > /proc/sys/kernel/perf_event_paranoid' to fix the problem\n");
    }
    abort();
  }

  // Start write sampling only if supported
  if (numap_sampling_write_supported()) {
    res = numap_sampling_write_start_generic(&sm_wr, SAMPLING_TYPE);
    if(res < 0) {
      fprintf(stderr, "numap_sampling_write_start error : %s\n", numap_error_message(res));
      abort();
    }
  }
  setting_sampling_stuff=0;
#endif	/* USE_NUMAP */
}

void mem_sampling_collect_samples() {
#if USE_NUMAP
  if(status_finalized)
    return;

  debug_printf("in %s : [tid=%lx][cur_date=%lf] Collect samples %d\n",
	       __FUNCTION__,
	       syscall(SYS_gettid), get_cur_date(), is_sampling);

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

  start_tick(pause_sampling);
  // Stop memory read access sampling
  int res = numap_sampling_read_stop(&sm);
  if(res < 0) {
    printf("numap_sampling_stop error : %s\n", numap_error_message(res));
    abort();
  }

  // Stop memory write access sampling if needed
  if (numap_sampling_write_supported()) {
    res = numap_sampling_write_stop(&sm_wr);
    if(res < 0) {
      printf("numap_sampling_stop error : %s\n", numap_error_message(res));
      abort();
    }
  }
  stop_tick(pause_sampling);

  // Analyze samples
  start_tick(analyze_samples);
  __analyze_sampling(&sm, ACCESS_READ);
  if (numap_sampling_write_supported()) {
    __analyze_sampling(&sm_wr, ACCESS_WRITE);
  }
  debug_printf("analyze done\n");
  stop_tick(analyze_samples);

  setting_sampling_stuff=0;
#endif	/* USE_NUMAP */
}

/* copy the samples to a buffer so that they can be analyzed later */
static void __copy_samples(struct numap_sampling_measure *sm,
			   enum access_type access_type) {

  /* well, sm->nb_threads should be 1, but let's make things generic */
  int thread;
  for (thread = 0; thread < sm->nb_threads; thread++) {
    start_tick(rmb);
    size_t sample_size = 0;
    struct mem_sampling_stat p_stat;
    struct perf_event_mmap_page *metadata_page = sm->metadata_pages_per_tid[thread];

    uint8_t* start_addr = (uint8_t *)metadata_page+metadata_page->data_offset;
    /* where the data begins */
    p_stat.head = metadata_page -> data_head;
    /* On SMP-capable platforms, after reading the data_head value,
     * user space should issue an rmb().
     */
    rmb();
    p_stat.header = (struct perf_event_header *)((char *)metadata_page + sm->page_size);
    sample_size =  p_stat.head;

    struct sample_list* new_sample_buffer = malloc(sizeof(struct sample_list));
    //    struct sample_list* new_sample_buffer = mem_allocator_alloc(sample_mem);
    new_sample_buffer->buffer = malloc(sample_size);
    new_sample_buffer->access_type = access_type;
    new_sample_buffer->buffer_size = sample_size;

    start_tick(memcpy_samples);
    memcpy(new_sample_buffer->buffer, start_addr, sample_size);
    new_sample_buffer->start_date = start_date;
    new_sample_buffer->stop_date = new_date();
    new_sample_buffer->thread_rank = thread_rank;

    /* todo: make this thread-safe */
    new_sample_buffer->next = samples;
    samples = new_sample_buffer;
    nb_sample_buffers++;

    stop_tick(memcpy_samples);

    debug_printf("[%d] copied %zu bytes\n", thread_rank, sample_size);
    stop_tick(rmb);
  }
}

extern date_t origin_date;
#define DATE(d) ((d)-origin_date)

void update_counters(struct mem_counters* counters,
		     struct mem_sample *sample) {

  counters[samples->access_type].total_count++;
  counters[samples->access_type].total_weight += sample->weight;

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_NA) {
    counters[samples->access_type].na_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_L1) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].cache1_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].cache1_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_L2) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].cache2_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].cache2_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_L3) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].cache3_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].cache3_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_LFB) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].lfb_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].lfb_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_LOC_RAM) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].local_ram_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].local_ram_miss_count++;
  }

  if((sample->data_src.mem_lvl & PERF_MEM_LVL_REM_RAM1) ||
     (sample->data_src.mem_lvl & PERF_MEM_LVL_REM_RAM2)) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].remote_ram_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].remote_ram_miss_count++;
  }

  if((sample->data_src.mem_lvl & PERF_MEM_LVL_REM_CCE1) ||
     (sample->data_src.mem_lvl & PERF_MEM_LVL_REM_CCE2)) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].remote_cache_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].remote_cache_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_IO) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].io_memory_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].io_memory_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_UNC) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      counters[samples->access_type].uncached_memory_hit_count++;
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      counters[samples->access_type].uncached_memory_miss_count++;
  }
}

/* This function analyzes a set of samples
 * @param samples : a buffer that contains samples
 * @return nb_samples : the number of samples that were in the buffer
 * @return found_samples :  the number of samples that were matched to a memory object
 */
static void __analyze_buffer(struct sample_list* samples,
			     int *nb_samples,
			     int *found_samples) {

  size_t consumed = 0;
  struct perf_event_header *event = samples->buffer;

  if(_dump) {
    fprintf(dump_file, "%d Analyze samples %p (size=%d), start: %lu stop: %lu -- duration: %llu\n",
	    samples->thread_rank,
	    samples,
	    samples->buffer_size,
	    samples->start_date,
	    samples->stop_date,
	    samples->stop_date-samples->start_date);
  }

  /* browse the buffer and process each sample */
  while(consumed < samples->buffer_size) {
    if(event->size == 0) {
      fprintf(stderr, "Error: invalid header size = 0\n");
      abort();
    }
    if (event->type == PERF_RECORD_SAMPLE) {
      struct mem_sample *sample = (struct mem_sample *)((char *)(event) + 8); /* todo: remplace 8 with sizeof(ptr) ? */
      (*nb_samples)++;
      if(drop_samples) {
	/* no need to search for a match */
	goto next_sample;
      }

      update_counters(global_counters, sample);
      /* find the memory object that corresponds to the sample*/
      struct memory_info* mem_info = ma_find_mem_info_from_sample(sample);

      if(!mem_info) {
	/* no buffer matches sample->addr */
      } else {

	/* we found a memory object that corresponds to the sample */
	if(!mem_info->blocks) {
	  /* this is the first time a sample matches this object, initialize a few things */
	  ma_allocate_counters(mem_info);
	  ma_init_counters(mem_info);
	}

	(*found_samples)++;

	/* find the memory pages in the object that corresponds to the sample address */
	struct block_info *block = ma_get_block(mem_info, samples->thread_rank, sample->addr);
	/* update counters */
	update_counters(block->counters, sample);
      }

      if(_dump) {
	/* dump mode is activated, write to content of the sample to a file */

	if(mem_info) {
	  /* compute the offset of the sample adress in the memory object */
	  uintptr_t offset=(uintptr_t)sample->addr - (uintptr_t)mem_info->buffer_addr;

	  if(!mem_info->caller) {
	    /* search for the function that allocated the memory object */
	    mem_info->caller = get_caller_function_from_rip(mem_info->caller_rip);
	  }

	  if(mem_info->mem_type != stack) {
	    /* write the content of the sample to a file */
	    fprintf(dump_file,
		    "%d %" PRIu64 " %" PRIu64 " %" PRId64 " %s %" PRIu64 " %s\n",
		    samples->thread_rank,
		    sample->timestamp,
		    sample->addr,
		    offset,
		    get_data_src_level(sample->data_src),
		    sample->weight,
		    mem_info?mem_info->caller:"", mem_info->buffer_addr);
	  }
	}
      }
    }
  next_sample:
    /* go to the next sample */
    consumed += event->size;
    event = (struct perf_event_header *)((uint8_t *)event + event->size);
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
    struct perf_event_mmap_page *metadata_page = sm->metadata_pages_per_tid[thread];
    rmb();

    struct sample_list samples = {
      .next = NULL,
      .buffer = (uint8_t *)metadata_page+metadata_page->data_offset,
      .buffer_size = metadata_page -> data_head,
      .access_type = access_type,
      .start_date = start_date,
      .stop_date = new_date(),
      .thread_rank = thread_rank,
    };

    __analyze_buffer(&samples, &nb_samples, &found_samples);
  }

  if(nb_samples>0) {
    debug_printf("[%lf] \tnb_samples = %d (including %d in mem blocks)\n", get_cur_date(), nb_samples, found_samples);
    nb_samples_total += nb_samples;
    nb_found_samples_total += found_samples;
  }
}
