#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <linux/version.h>
#include <pthread.h>
#include <dlfcn.h>
#include <link.h>

#include "mem_sampling.h"
#include "mem_analyzer.h"
#include "mem_tools.h"

// if > 0, ma_get_*_variables functions are called before analysis, and do_get_at_analysis is decremented
int do_get_at_analysis = 0;

/* number of memory pages for numap buffer  */
size_t numap_page_count = 32;

uint64_t nb_samples_total = 0;
uint64_t nb_found_samples_total = 0;

static FILE* dump_all_file = NULL;

/* set to 1 if we are currently sampling memory accesses */
static __thread volatile int is_sampling = 0;

/* set to 1 once the thread was finalized */
static __thread int status_finalized = 0;
static __thread int status_initialized = 0;

struct timespec t_init;

struct mem_counters global_counters[2];
void init_mem_counter(struct mem_counters* counters);

static double get_cur_date() {
  struct timespec t1;
  clock_gettime(CLOCK_REALTIME, &t1);
  double duration =  (t1.tv_sec-t_init.tv_sec)+((t1.tv_nsec-t_init.tv_nsec)/1e9);
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
  struct perf_event_header *buffer;
  uint64_t data_tail;
  uint64_t data_head;
  size_t buffer_size;
  enum access_type access_type;
  date_t start_date;
  date_t stop_date;
  unsigned thread_rank;
};
struct sample_list *samples = NULL;
pthread_mutex_t sample_list_lock;
static int nb_sample_buffers = 0;


struct thread_info {
  struct numap_sampling_measure *sm;
  struct numap_sampling_measure* sm_wr;
  pid_t tid;
  int rank;
};

struct thread_info *thread_ranks = NULL;
_Atomic int nthreads = 0;
int allocated_threads = 0;

static struct thread_info * get_thread_info(pid_t pid) {
  for(int i=0; i<nthreads; i++)
    if(thread_ranks[i].tid == pid)
      return &thread_ranks[i];
  return NULL;
}

static void register_thread_pid(pid_t pid,
				struct numap_sampling_measure *sm,
				struct numap_sampling_measure *sm_wr) {
  if(allocated_threads == 0) {
    thread_ranks = malloc(sizeof(struct thread_info)* 128);
    allocated_threads = 128;
  }
  while(nthreads >= allocated_threads) {
    allocated_threads *= 2;
    thread_ranks = realloc(thread_ranks, sizeof(struct thread_info)*allocated_threads);
  }
  int rank = nthreads++;
  thread_ranks[rank].tid = pid;
  thread_ranks[rank].rank = rank;
  thread_ranks[rank].sm = sm;
  thread_ranks[rank].sm_wr = sm_wr;
}

/* called at runtime when the sample buffer has to be emptied
 * depending on the settings, it either calls __copy_buffer, or __analyze_buffer
 */
static void __process_samples(struct numap_sampling_measure *sm,
			      enum access_type access_type);

static void __analyze_buffer(struct sample_list* samples,
			     int *nb_samples,
			     int *found_samples);
static void __copy_buffer(struct sample_list* samples,
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

  int err = numap_init();
  if(err != 0) {
    fprintf(stderr, "Error while initializing numap: %s\n", numap_error_message(err));
    abort();
  }

  if(settings.alarm) {   
    __alarm_interval = settings.alarm* 1000000;
    alarm_enabled=1;
  }

  char* str = getenv("NUMAMMA_GET_AT_ANALYSIS");
  if (str) {
    do_get_at_analysis = atoi(str);
  }

  settings.buffer_size *= 1024;
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  if(settings.buffer_size % page_size != 0) {
    printf("[NumaMMA] buffer_size must be a multiple of %zu !\n", page_size);
    settings.buffer_size -= settings.buffer_size % page_size;
    printf("[NumaMMA]\tadjusting buffer_size to %zu !\n", settings.buffer_size);
  }

  numap_page_count = settings.buffer_size / page_size;

  pthread_mutex_init(&sample_list_lock, NULL);

  mem_allocator_init(&sample_mem, sizeof(struct sample_list), 1024);
  init_mem_counter(&global_counters[0]);
  init_mem_counter(&global_counters[1]);
    
  assert(global_counters[1].cache1_hit.min_weight != 0);
#endif
}

_Thread_local size_t copied_size = 0;
void numap_generic_handler(struct numap_sampling_measure *m,
			   int fd,
			   enum access_type access_type) {
  if(IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    pid_t tid =  syscall(SYS_gettid);
    debug_printf("[%d] [%lf] %s starts\n", get_thread_info(tid)->rank, get_cur_date(), __func__);
#if 1
    /* collect samples for all the threads */
    for(int i=0; i<nthreads; i++) {
      size_t read_size, write_size;
      copied_size = 0;
      numap_sampling_read_stop(thread_ranks[i].sm);
      __process_samples(thread_ranks[i].sm, ACCESS_READ);
      read_size = copied_size;
      numap_sampling_resume(thread_ranks[i].sm);


      copied_size = 0;
      numap_sampling_write_stop(thread_ranks[i].sm_wr);
      __process_samples(thread_ranks[i].sm_wr, ACCESS_WRITE);
      numap_sampling_resume(thread_ranks[i].sm_wr);

      write_size = copied_size;
      debug_printf("\tThread %d: %zu bytes read, %zu bytes write\n", i, read_size, write_size);
    }
#else
    /* collect samples from the buffer that was signaled */
    numap_sampling_read_stop(m);
    __process_samples(m, access_type);
    numap_sampling_resume(m);
    debug_printf("\tThread %d: %llu bytes read\n", get_thread_info(m->tids[0])->rank, copied_size);
    copied_size = 0;
#endif
    UNPROTECT_FROM_RECURSION;
  }
}

void numap_read_handler(struct numap_sampling_measure *m, int fd) {
  numap_generic_handler(m, fd, ACCESS_READ);
}

void numap_write_handler(struct numap_sampling_measure *m, int fd) {
  numap_generic_handler(m, fd, ACCESS_WRITE);
}

void mem_sampling_thread_init() {
  pid_t tid = syscall(SYS_gettid);
  register_thread_pid(tid, &sm, &sm_wr);

  int res = numap_sampling_init_measure(&sm, 1, settings.sampling_rate, numap_page_count);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  res = numap_sampling_init_measure(&sm_wr, 1, settings.sampling_rate, numap_page_count);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  /* for now, only collect info on the current thread */
  sm.tids[0] = tid;
  sm_wr.tids[0] = tid;

  if(settings.flush) {
    struct sigaction s;  
    s.sa_handler = sig_handler;  
    int signo=SIGALRM;
    int ret = sigaction(signo, &s, NULL);
    if(ret<0) {  
      perror("sigaction failed");  
      abort();  
    }

    int page_size=4096;
    /* number of samples that fit in one sample buffer */
    int nsamples = numap_page_count * page_size / (sizeof(struct mem_sample)+sizeof(struct perf_event_header));
    if(numap_sampling_set_measure_handler(&sm, numap_read_handler, nsamples) != 0)
      printf("numap_sampling_set_measure_handler failed\n");
    if(numap_sampling_set_measure_handler(&sm_wr, numap_write_handler, nsamples) != 0)
      printf("numap_sampling_set_measure_handler failed\n");
  }

  status_initialized = 1;
  __set_alarm();
  mem_sampling_start();
}


void mem_sampling_finalize() {

  if(!settings.online_analysis) {
    if (do_get_at_analysis > 0) {
      ma_get_variables();
      do_get_at_analysis--;
    }
    /* analyze the samples that were copied at runtime */
    ma_register_stack();

    printf("Analyzing %d sample buffers\n", nb_sample_buffers);
    int nb_blocks = 0;
    size_t total_buffer_size = 0;
    while(samples) {
      int nb_samples = 0;
      int found_samples = 0;
      if(nb_blocks % 10 == 0) {
        fflush(stdout);
        printf("\rAnalyzing sample buffer %d/%d. Total samples so far: %zu",
	       nb_blocks, nb_sample_buffers,
	       nb_samples_total);
      }
      __analyze_buffer(samples, &nb_samples, &found_samples);
      nb_samples_total += nb_samples;
      nb_found_samples_total += found_samples;
      total_buffer_size += samples->buffer_size;
      struct sample_list *prev = samples;
      samples = samples->next;
      nb_blocks++;
      free(prev->buffer);
      mem_allocator_free(sample_mem, prev);
    }
    printf("\n");
    printf("%zu bytes processed\n", total_buffer_size);
  }
}

void mem_sampling_thread_finalize() {
  if(!status_initialized)
    return;
  mem_sampling_collect_samples();
  numap_sampling_end(&sm);
  numap_sampling_end(&sm_wr);
  status_finalized = 1;
}

void mem_sampling_statistics() {
  float percent = 100.0*(nb_samples_total-nb_found_samples_total)/nb_samples_total;
  printf("%"PRIu64" samples (including %"PRIu64" samples that do not match a known memory buffer / %f%%)\n",
	 nb_samples_total, nb_samples_total-nb_found_samples_total, percent);
}

/* make sure this function is not called by collect_samples or start_sampling.
 * This could be the case if one of these functions fail and calls exit
 */
static __thread int setting_sampling_stuff=0;

void mem_sampling_resume() {
#if USE_NUMAP
  if(status_finalized)
    return;

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

  if(!is_sampling) {
    printf("[%lx] Trying to collect sampling data, but sampling has not started !\n", syscall(SYS_gettid));
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
  __process_samples(&sm, ACCESS_READ);
  if (numap_sampling_write_supported()) {
    __process_samples(&sm_wr, ACCESS_WRITE);
  }
  stop_tick(analyze_samples);

  setting_sampling_stuff=0;
#endif	/* USE_NUMAP */
}

extern date_t origin_date;
#define DATE(d) ((d)-origin_date)

#define UPDATE_COUNTER(counter, sample) do {	\
    counter.count++;				\
    if(sample->weight < counter.min_weight)	\
      counter.min_weight = sample->weight;	\
    if(sample->weight > counter.max_weight)	\
      counter.max_weight = sample->weight;	\
    counter.sum_weight += sample->weight;	\
  } while(0)

void update_counters(struct mem_counters* counters,
		     struct mem_sample *sample,
		     enum access_type access_type) {

  counters[access_type].total_count++;
  counters[access_type].total_weight += sample->weight;

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_NA) {
    counters[access_type].na_miss_count++;
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_L1) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].cache1_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].cache1_miss, sample);
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_L2) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].cache2_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].cache2_miss, sample);
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_L3) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].cache3_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].cache3_miss, sample);
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_LFB) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].lfb_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].lfb_miss, sample);
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_LOC_RAM) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].local_ram_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].local_ram_miss, sample);
  }

  if((sample->data_src.mem_lvl & PERF_MEM_LVL_REM_RAM1) ||
     (sample->data_src.mem_lvl & PERF_MEM_LVL_REM_RAM2)) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].remote_ram_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].remote_ram_miss, sample);
  }

  if((sample->data_src.mem_lvl & PERF_MEM_LVL_REM_CCE1) ||
     (sample->data_src.mem_lvl & PERF_MEM_LVL_REM_CCE2)) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].remote_cache_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].remote_cache_miss, sample);
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_IO) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].io_memory_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].io_memory_miss, sample);
  }

  if(sample->data_src.mem_lvl & PERF_MEM_LVL_UNC) {
    if (sample->data_src.mem_lvl & PERF_MEM_LVL_HIT)
      UPDATE_COUNTER(counters[access_type].uncached_memory_hit, sample);
    else if (sample->data_src.mem_lvl & PERF_MEM_LVL_MISS)
      UPDATE_COUNTER(counters[access_type].uncached_memory_miss, sample);
  }
}

static struct memory_info* __match_sample(struct mem_sample *sample,
					  enum access_type access_type,
					  int thread_rank) {
  /* find the memory object that corresponds to the sample*/
  struct memory_info* mem_info = ma_find_mem_info_from_sample(sample);

  if(!mem_info) {
    /* no buffer matches sample->addr */
    if (settings.dump_unmatched) {
      int found=0;
      char line[1024];
      char maps_path[1024];
      sprintf(maps_path, "/proc/%d/maps", getpid());

      static int maps_read = 0;	/* only read the maps file once */
      if(!maps_read) {
	// trying to find where the address is located in maps file
	FILE *maps = fopen(maps_path, "r");
	if (maps == NULL)	{
	  fprintf(stderr, "Could not read %s\n", maps_path);
	  abort();
	}
	fprintf(dump_unmatched_file, "# %s content:\n", maps_path);
	void *addr = (void*)sample->addr;
	while (!feof(maps)) {
	  fgets(line, sizeof(line), maps);
	  fprintf(dump_unmatched_file, "# %s", line);
#if 0
	  char cut_line[1024];
	  strncpy(cut_line, line, sizeof(cut_line));
	  void *begin = NULL;
	  void *end = NULL;
	  sscanf(strtok(cut_line, " "), "%p-%p", &begin, &end);
	  if (addr >= begin && addr <= end)
	    found = 1;
#endif
	}
	fclose(maps);
	fprintf(dump_unmatched_file, "#\n#\n#\n");

	maps_read = 1;

	fprintf(dump_unmatched_file,
		"#thread_rank timestamp address mem_level access_weight access_type\n");
      }
      
      /* write the content of the sample to a file */
      fprintf(dump_unmatched_file,
	      // thread_rank timestamp address mem_level access_weight access_type
	      "%u %" PRIu64 " 0x%"PRIxPTR" %s %" PRIu64 " %c\n",
		  samples->thread_rank,
		  sample->timestamp,
		  sample->addr,
		  get_data_src_level(sample->data_src),
		  sample->weight,
		  access_type==ACCESS_READ?'r':'w');
    }
  } else {

    /* we found a memory object that corresponds to the sample */
    if(!mem_info->blocks) {
      /* this is the first time a sample matches this object, initialize a few things */
      ma_allocate_counters(mem_info);
      ma_init_counters(mem_info);
    }

    /* find the memory pages in the object that corresponds to the sample address */
    struct block_info *block = ma_get_block(mem_info, thread_rank, sample->addr);
    /* update counters */
    update_counters(block->counters, sample, access_type);

    if(!mem_info->call_site) {
      mem_info->call_site = find_call_site(mem_info);
      if(!mem_info->call_site) {
	mem_info->call_site = new_call_site(mem_info);
      }
    }
  }
  return mem_info;
}

static void __copy_buffer(struct sample_list* sample_list,
			  int *nb_samples,
			  int *found_samples) {  
  enum access_type access_type = sample_list->access_type;

  if(sample_list->data_head == sample_list->data_tail)
    /* nothing to do */
    return;
  
  struct sample_list* new_sample_buffer = mem_allocator_alloc(sample_mem);
  size_t buffer_size = sample_list->data_head - sample_list->data_tail;
  
  if(sample_list->data_head < sample_list->data_tail) {
    /* the buffer is a ring buffer and we need to explore both parts of the "ring": */
    // ------------------------------------------------------
    // | second_block   |                  |first_block      |
    // -------------------------------------------------------
    //               data_head          data_tail        buffer_size
    buffer_size = sample_list->buffer_size - sample_list->data_tail + sample_list->data_head;
  }

  new_sample_buffer->buffer = malloc(buffer_size);
  new_sample_buffer->access_type = sample_list->access_type;
  new_sample_buffer->buffer_size = buffer_size;

  new_sample_buffer->data_tail = 0;
  new_sample_buffer->data_head = buffer_size;

  start_tick(memcpy_samples);
  if(sample_list->data_head < sample_list->data_tail) {
    /* copy the first block */
    size_t first_block_size = sample_list->buffer_size - sample_list->data_tail;
    uintptr_t start_addr = (uintptr_t)sample_list->buffer +(uintptr_t)sample_list->data_tail;
    memcpy(new_sample_buffer->buffer, (void*)start_addr, first_block_size);

    size_t second_block_size = sample_list->data_head;
    start_addr = (uintptr_t)new_sample_buffer->buffer + (uintptr_t)first_block_size;
    memcpy((void*)start_addr, &sample_list->buffer[0], second_block_size);
    
  } else {
    /* data is already contiguous */
    uintptr_t start_addr = (uintptr_t)sample_list->buffer +(uintptr_t)sample_list->data_tail;
    memcpy(new_sample_buffer->buffer, (void*)start_addr, buffer_size);
  }

  struct perf_event_header *event = (struct perf_event_header*) (new_sample_buffer->buffer);
  assert(event->type < PERF_RECORD_MAX);
  assert(event->size > 0);
  
  new_sample_buffer->start_date = sample_list->start_date;
  new_sample_buffer->stop_date = sample_list->stop_date;
  new_sample_buffer->thread_rank = sample_list->thread_rank;

  pthread_mutex_lock(&sample_list_lock);
  new_sample_buffer->next = samples;
  samples = new_sample_buffer;
  nb_sample_buffers++;
  pthread_mutex_unlock(&sample_list_lock);

  stop_tick(memcpy_samples);

  stop_tick(rmb);
  copied_size = buffer_size;
}

static void _dump_mem_info(struct mem_sample *sample,
			   enum access_type access_type,
			   struct memory_info* mem_info,
			   uintptr_t offset) {
  if(settings.dump_all && mem_info->mem_type != stack) {
    if(!dump_all_file) {
      char filename[4096];
      char file_basename[STRING_LEN];
      snprintf(file_basename, STRING_LEN, "all_memory_accesses.dat");
      create_log_filename(file_basename, filename, 4096);
      dump_all_file=fopen(filename, "w");
      if(!dump_all_file) {
	fprintf(stderr, "failed to open %s for writing: %s\n", filename, strerror(errno));
	abort();
      }

      /* write the content of the sample to a file */
      fprintf(dump_all_file,
	      "#thread_rank timestamp object_id offset mem_level access_weight access_type\n");
    }

    /* write the content of the sample to a file */
    fprintf(dump_all_file,
	    "%u %" PRIu64 " %u %" PRIu64 " %s %" PRIu64 " %c\n",
	    samples->thread_rank,
	    sample->timestamp,
	    mem_info->id,
	    offset,
	    get_data_src_level(sample->data_src),
	    sample->weight,
	    access_type==ACCESS_READ?'r':'w');

  }
}

static void _dump_call_site(struct mem_sample *sample,
			    enum access_type access_type,
			    struct memory_info* mem_info,
			    uintptr_t offset) {
  if(mem_info && mem_info->call_site && mem_info->mem_type != stack) {
    if(!mem_info->call_site->dump_file) {
      char filename[4096];
      char file_basename[STRING_LEN];
      snprintf(file_basename, STRING_LEN, "callsite_dump_%d.dat", mem_info->call_site->id);
      create_log_filename(file_basename, filename, 4096);
      mem_info->call_site->dump_file=fopen(filename, "w");
      if(!mem_info->call_site->dump_file) {
	fprintf(stderr, "failed to open %s for writing: %s\n", filename, strerror(errno));
	abort();
      }

      /* write the content of the sample to a file */
      fprintf(mem_info->call_site->dump_file,
	      "#thread_rank timestamp offset mem_level access_weight access_type\n");
    }
	  
    /* write the content of the sample to a file */
    fprintf(mem_info->call_site->dump_file,
	    "%u %" PRIu64 " %" PRIuPTR " %s %" PRIu64 " %c\n",
	    samples->thread_rank,
	    sample->timestamp,
	    offset,
	    get_data_src_level(sample->data_src),
	    sample->weight,
	    access_type==ACCESS_READ?'r':'w');

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

  if (do_get_at_analysis > 0) {
    ma_get_lib_variables();
    ma_get_global_variables();
    do_get_at_analysis = 0;
  }

  start_tick(sample_analysis);

  if(samples->data_tail ==  samples->data_head)
    /* nothing to do */
    return;

  unsigned start_cpt = samples->data_tail;
  unsigned stop_cpt = samples->data_head;
  uintptr_t reset_cpt = samples->buffer_size;
  unsigned cur_cpt = start_cpt;

  enum access_type access_type = samples->access_type;
  if(stop_cpt < start_cpt) {
    /* the buffer is a ring buffer and we need to explore both parts of the "ring": */

    // ------------------------------------------------------
    // | second_block   |                  |first_block      |
    // -------------------------------------------------------
    //               stop_cpt            start_cpt         reset_cpt

    /* in order to make the while condition easier to understand, let's first analyze
     * the first block. When the end of the buffer is reached, we reset counters so that
     * the second block is analyzed
     */
    stop_cpt = reset_cpt;
  }
    
  /* browse the buffer and process each sample */
  while(cur_cpt < stop_cpt) {

    struct perf_event_header *event = (struct perf_event_header*) ((uintptr_t)samples->buffer + cur_cpt);

    if(event->size == 0) {
      fprintf(stderr, "Error: invalid header size = 0. %p\n", samples);
      abort();
    }

    if (event->type == PERF_RECORD_SAMPLE) {
      struct mem_sample *sample = (struct mem_sample *)((char *)(event) + sizeof(struct perf_event_header));

      uint8_t frontier_buffer[event->size];
      if(cur_cpt + event->size > reset_cpt) {
	// we reached the end of the buffer. The event is split in two parts:
	// ------------------------------------------------------
	// | second_part    |                  | first_part      |
	// -------------------------------------------------------
	//                                   cur_cpt         reset_cpt
	size_t first_part_size = reset_cpt-cur_cpt;
	size_t second_part_size = event->size -first_part_size;

	// copy the event in a contiguous buffer
	memcpy(frontier_buffer, sample, first_part_size);// copy the first part
	memcpy(&frontier_buffer[first_part_size], samples->buffer, second_part_size);
	sample = (struct mem_sample *)frontier_buffer;
      }

      (*nb_samples)++;
      update_counters(global_counters, sample, access_type);

      struct memory_info* mem_info = NULL;
      struct call_site* call_site = NULL;

      if(settings.match_samples) {
	/* search for the object that correspond to this memory sample */
	mem_info = __match_sample(sample, access_type, samples->thread_rank);
	if(mem_info) {
	  (*found_samples)++;
	}
      }

      if(settings.dump || settings.dump_all) {
	/* dump mode is activated, write to content of the sample to a file */

	uintptr_t offset=0;
	if(mem_info) {
	  /* compute the offset of the sample adress in the memory object */
	  offset = (uintptr_t)sample->addr - (uintptr_t)mem_info->buffer_addr;

	  if(!mem_info->caller) {
	    /* search for the function that allocated the memory object */
	    mem_info->caller = get_caller_function_from_rip(mem_info->caller_rip);
	  }

	  /* if needed, write the sample into files */
	  _dump_mem_info(sample, access_type, mem_info, offset);
	  _dump_call_site(sample, access_type, mem_info, offset);
	}
      }
    }
  next_sample:
    /* go to the next sample */
    cur_cpt += event->size;

    if(cur_cpt >= reset_cpt && reset_cpt != samples->data_head) {
      cur_cpt -= reset_cpt;
      stop_cpt = samples->data_head;
    }
  }
  
  stop_tick(sample_analysis);
}

void __process_samples(struct numap_sampling_measure *sm,
			enum access_type access_type) {
  int thread;
  int nb_samples = 0;
  int found_samples = 0;
  for (thread = 0; thread < sm->nb_threads; thread++) {
    struct perf_event_mmap_page *metadata_page = sm->metadata_pages_per_tid[thread];
    uint64_t data_head = metadata_page->data_head % metadata_page->data_size;
    rmb();

    int rank = get_thread_info(sm->tids[thread])->rank;
    assert(rank >=0);
    struct sample_list samples = {
      .next = NULL,
      .buffer = (struct perf_event_header *)((uint8_t *)metadata_page+metadata_page->data_offset),
      .data_tail = metadata_page->data_tail,
      .data_head = data_head,
      .buffer_size = metadata_page -> data_size,
      .access_type = access_type,
      .start_date = start_date,
      .stop_date = new_date(),
      .thread_rank = rank,
    };

    if(settings.online_analysis) {
      __analyze_buffer(&samples, &nb_samples, &found_samples);
    } else {
      __copy_buffer(&samples, &nb_samples, &found_samples);
    }
    metadata_page -> data_tail = data_head;
  }

  if(nb_samples>0) {
    debug_printf("[%lf] \tnb_samples = %d (including %d in mem blocks)\n", get_cur_date(), nb_samples, found_samples);
    nb_samples_total += nb_samples;
    nb_found_samples_total += found_samples;
  }
}
