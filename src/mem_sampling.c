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

/* set to 1 if we are currently sampling memory accesses */
static __thread volatile int is_sampling = 0;

/* set to 1 once the thread was finalized */
static __thread int status_finalized = 0;
static __thread int status_initialized = 0;

struct timespec t_init;

struct mem_counters global_counters[2];
void init_mem_counter(struct mem_counters* counters);

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
  struct perf_event_header *buffer;
  size_t buffer_size;
  enum access_type access_type;
  date_t start_date;
  date_t stop_date;
  unsigned thread_rank;
};
struct sample_list *samples = NULL;
pthread_mutex_t sample_list_lock;
static int nb_sample_buffers = 0;


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
    printf("[NumaMMA] buffer_size must be a multiple of %lu !\n", page_size);
    settings.buffer_size -= settings.buffer_size % page_size;
    printf("[NumaMMA]\tadjusting buffer_size to %lu !\n", settings.buffer_size);
  }

  numap_page_count = settings.buffer_size / page_size;

  pthread_mutex_init(&sample_list_lock, NULL);

  mem_allocator_init(&sample_mem, sizeof(struct sample_list), 1024);
  init_mem_counter(&global_counters[0]);
  init_mem_counter(&global_counters[1]);
    
  assert(global_counters[1].cache1_hit.min_weight != 0);
#endif
}

void numap_generic_handler(struct numap_sampling_measure *m,
			   int fd,
			   enum access_type access_type) {
  if(IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    __process_samples(m, access_type);      
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

  if(settings.flush) {
    struct sigaction s;  
    s.sa_handler = sig_handler;  
    int signo=SIGALRM;
    int ret = sigaction(signo, &s, NULL);
    if(ret<0) {  
      perror("sigaction failed");  
      abort();  
    }
    printf("flush\n");
    if(numap_sampling_set_measure_handler(&sm, numap_read_handler, 1000) != 0)
      printf("numap_sampling_set_measure_handler failed\n");
    if(numap_sampling_set_measure_handler(&sm_wr, numap_write_handler, 1000) != 0)
      printf("numap_sampling_set_measure_handler failed\n");
  }

  status_initialized = 1;
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

#define _PERCENT(c) (100.*c / counters[i].total_count)
#define PERCENT(__c) (_PERCENT(counters[i].__c.count))
#define MIN_COUNT(__c) (counters[i].__c.min_weight)
#define MAX_COUNT(__c) (counters[i].__c.max_weight)
#define AVG_COUNT(__c) (counters[i].__c.count? counters[i].__c.sum_weight / counters[i].__c.count : 0)
#define WEIGHT(__c) (counters[i].__c.sum_weight)
#define PERCENT_WEIGHT(__c) (counters[i].total_weight?100.*counters[i].__c.sum_weight/counters[i].total_weight:0)
    
#define PRINT_COUNTER(__c, str) \
    if(counters[i].__c.count) printf("%s\t: %ld (%f %%) \tmin: %llu cycles\tmax: %llu cycles\t avg: %llu cycles\ttotal weight: % "PRIu64" (%f %%)\n", \
				     str, counters[i].__c.count, PERCENT(__c), MIN_COUNT(__c), MAX_COUNT(__c), AVG_COUNT(__c), \
				     WEIGHT(__c), PERCENT_WEIGHT(__c))
    
    printf("Total count          : \t %"PRIu64"\n", counters[i].total_count);
    printf("Total weigh          : \t %"PRIu64"\n", counters[i].total_weight);
    if(counters[i].na_miss_count)
      printf("N/A                  : \t %"PRIu64" (%f %%)\n", counters[i].na_miss_count, _PERCENT(counters[i].na_miss_count));

    PRINT_COUNTER(cache1_hit, "L1 Hit");
    PRINT_COUNTER(cache2_hit, "L2 Hit");
    PRINT_COUNTER(cache3_hit, "L3 Hit");

    PRINT_COUNTER(lfb_hit, "LFB Hit");
    PRINT_COUNTER(local_ram_hit, "Local RAM Hit");
    PRINT_COUNTER(remote_ram_hit, "Remote RAM Hit");
    PRINT_COUNTER(remote_cache_hit, "Remote cache Hit");
    PRINT_COUNTER(io_memory_hit, "IO memory Hit");
    PRINT_COUNTER(uncached_memory_hit, "Uncached memory Hit");

    printf("\n");

    PRINT_COUNTER(lfb_miss, "LFB Miss");
    PRINT_COUNTER(local_ram_miss, "Local RAM Miss");
    PRINT_COUNTER(remote_ram_miss, "Remote RAM Miss");
    PRINT_COUNTER(remote_cache_miss, "Remote cache Miss");
    PRINT_COUNTER(io_memory_miss, "IO memory Miss");
    PRINT_COUNTER(uncached_memory_miss, "Uncached memory Miss");
  }
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
        printf("\rAnalyzing sample buffer %d/%d. Total samples so far: %d",
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
    printf("Total: %d samples including %d matches in %d blocks (%lu bytes)\n", nb_samples_total, nb_found_samples_total, nb_blocks, total_buffer_size);

  }

  print_counters(global_counters);
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
  if(!settings.online_analysis) {
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
      // trying to find where the address is located in maps file
      char maps_path[1024];
      sprintf(maps_path, "/proc/%d/maps", getpid());
      FILE *maps = fopen(maps_path, "r");
      if (maps == NULL)
	{
	  fprintf(stderr, "Could not read %s\n", maps_path);
	  abort();
	}
      char line[1024];
      int found=0;
      void *addr = (void*)sample->addr;
      while (!found && !feof(maps))
	{
	  fgets(line, sizeof(line), maps);
	  char cut_line[1024];
	  strncpy(cut_line, line, sizeof(cut_line));
	  void *begin = NULL;
	  void *end = NULL;
	  sscanf(strtok(cut_line, " "), "%p-%p", &begin, &end);
	  if (addr >= begin && addr <= end)
	    found = 1;
	}
      fclose(maps);

      fprintf(dump_unmatched_file, "%p ",sample->addr);
      if (found) {
	fprintf(dump_unmatched_file, "located in %s", strtok(line, "\n"));
      }
      else {
	fprintf(dump_unmatched_file, "matching no address range in %s", maps_path);
      }
      fprintf(dump_unmatched_file, "\n");
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
  size_t consumed = 0;
  struct perf_event_header *event = sample_list->buffer;
  enum access_type access_type = sample_list->access_type;

  struct sample_list* new_sample_buffer = mem_allocator_alloc(sample_mem);
  new_sample_buffer->buffer = malloc(sample_list->buffer_size);
  new_sample_buffer->access_type = sample_list->access_type;
  new_sample_buffer->buffer_size = sample_list->buffer_size;

  start_tick(memcpy_samples);

  memcpy(new_sample_buffer->buffer, sample_list->buffer, sample_list->buffer_size);

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

  size_t consumed = 0;
  struct perf_event_header *event = samples->buffer;
  enum access_type access_type = samples->access_type;

  /* browse the buffer and process each sample */
  while(consumed < samples->buffer_size) {
    if(event->size == 0) {
      fprintf(stderr, "Error: invalid header size = 0\n");
      abort();
    }
    if (event->type == PERF_RECORD_SAMPLE) {
      struct mem_sample *sample = (struct mem_sample *)((char *)(event) + 8); /* todo: remplace 8 with sizeof(ptr) ? */
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

      if(settings.dump) {
	/* dump mode is activated, write to content of the sample to a file */

	uintptr_t offset=0;
	if(mem_info) {
	  /* compute the offset of the sample adress in the memory object */
	  offset = (uintptr_t)sample->addr - (uintptr_t)mem_info->buffer_addr;

	  if(!mem_info->caller) {
	    /* search for the function that allocated the memory object */
	    mem_info->caller = get_caller_function_from_rip(mem_info->caller_rip);
	  }
	}

	if(mem_info && mem_info->call_site && mem_info->mem_type != stack) {
	  if(!mem_info->call_site->dump_file) {
	    char filename[4096];
	    char file_basename[STRING_LEN];
	    snprintf(file_basename, STRING_LEN, "callsite_%d", mem_info->call_site->id);
	    create_log_filename(file_basename, filename, 4096);
	    mem_info->call_site->dump_file=fopen(filename, "w");
	    if(!mem_info->call_site->dump_file) {
	      fprintf(stderr, "failed to open %s for writing: %s\n", filename, strerror(errno));
	      abort();
	    }
	  }
	  
	  /* write the content of the sample to a file */
	  fprintf(mem_info->call_site->dump_file,
		    "%d %" PRIu64 " %" PRIu64 " %" PRId64 " %s %" PRIu64 "\n",
		    samples->thread_rank,
		    sample->timestamp,
		    sample->addr,
		    offset,
		    get_data_src_level(sample->data_src),
		    sample->weight);

	}
      }
    }
  next_sample:
    /* go to the next sample */
    consumed += event->size;
    event = (struct perf_event_header *)((uint8_t *)event + event->size);
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
    rmb();

    struct sample_list samples = {
      .next = NULL,
      .buffer = (struct perf_event_header *)((uint8_t *)metadata_page+metadata_page->data_offset),
      .buffer_size = metadata_page -> data_head,
      .access_type = access_type,
      .start_date = start_date,
      .stop_date = new_date(),
      .thread_rank = thread_rank,
    };

    if(settings.online_analysis) {
      __analyze_buffer(&samples, &nb_samples, &found_samples);
    } else {
      __copy_buffer(&samples, &nb_samples, &found_samples);
    }
  }

  if(nb_samples>0) {
    debug_printf("[%lf] \tnb_samples = %d (including %d in mem blocks)\n", get_cur_date(), nb_samples, found_samples);
    nb_samples_total += nb_samples;
    nb_found_samples_total += found_samples;
  }
}
