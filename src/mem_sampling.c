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

int sampling_rate = 10000;
int get_lib_done = 0;

/* if set to one, numamma matches samples with memory objects */
int match_samples=1;

/* if set to 1, numamma registers a callback that is call each
   time the sample buffer is full. Otherwise, samples may be lost */
int sig_refresh_enabled=1;

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

/* if set to 1, samples are copied to a buffer at runtime and analyzed after the
 * end of the application. -> low overlead, high memory consumption
 * if set to 0, samples are analyzed at runtime. -> high overhead, low memory consumption.
 */
int offline_analysis = 1;

static void __analyze_sampling(struct numap_sampling_measure *sm,
			       enum access_type access_type);
static void __copy_samples_thread(struct numap_sampling_measure *sm,
			   enum access_type access_type,
			   int thread);
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

  char* dont_match_str = getenv("DONT_MATCH_SAMPLES");
  if(dont_match_str)
    match_samples=0;


  int err = numap_init();
  if(err != 0) {
    fprintf(stderr, "Error while initializing numap: %s\n", numap_error_message(err));
    abort();
  }

  char* str=getenv("ONLINE_ANALYSIS");
  if(str) {
    offline_analysis = 0;
  }

  str=getenv("NUMAMMA_ALARM");
  long interval = 0;
  if(str) {
    interval=atol(str);
    __alarm_interval = interval* 1000000;
    alarm_enabled=1;
  }

  str = getenv("NUMAMMA_NO_REFRESH");
  if(str) {
    sig_refresh_enabled=0;
  }
  
  str=getenv("NUMAMMA_BUFFER_SIZE");
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  long buffer_size = numap_page_count * page_size;
  if(str) {
    buffer_size=atol(str);
    if(buffer_size % page_size != 0) {
      printf("[NumaMMA] buffer_size must be a multiple of %lu !\n", page_size);
      buffer_size -= buffer_size % page_size;
      printf("[NumaMMA]\tadjusting buffer_size to %lu !\n", buffer_size);
    }

    numap_page_count = buffer_size / page_size;
  }
  pthread_mutex_init(&sample_list_lock, NULL);

  printf("NumaMMA settings:\n");
  printf("-----------------\n");
  printf("Sampling rate: %d\n", sampling_rate);
  printf("Match samples: %d\n", match_samples);
  printf("Buffer size: %lu\n", buffer_size);
  printf("Alarm interval: %ld ms\n", alarm_enabled?interval:0);
  printf("Memory access analysis: %s\n", offline_analysis?"offline":"online");
  printf("Refresh: %s\n", sig_refresh_enabled?"enabled":"disabled");
  printf("-----------------\n");

  mem_allocator_init(&sample_mem, sizeof(struct sample_list), 1024);
  init_mem_counter(&global_counters[0]);
  init_mem_counter(&global_counters[1]);
    
  assert(global_counters[1].cache1_hit.min_weight != 0);
#endif
}

void numap_generic_handler(struct numap_sampling_measure *m, int fd, enum access_type access_type)
{
  if(IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    int tid_i=-1; // search tid
    for (int i = 0 ; i < m->nb_threads ; i++)
    {
      if (m->fd_per_tid[i] == fd)
        tid_i = i;
    }
    if (tid_i == -1)
    {
      fprintf(stderr, "No tid associated with fd %d\n", fd);
      exit(EXIT_FAILURE);
    }
    __copy_samples_thread(m, access_type, tid_i);
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
  int res = numap_sampling_init_measure(&sm, 1, sampling_rate, numap_page_count);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  res = numap_sampling_init_measure(&sm_wr, 1, sampling_rate, numap_page_count);
  if(res < 0) {
    fprintf(stderr, "numap_sampling_init error : %s\n", numap_error_message(res));
    abort();
  }

  /* for now, only collect info on the current thread */
  sm.tids[0] = tid;

  if(sig_refresh_enabled) {
    struct sigaction s;  
    s.sa_handler = sig_handler;  
    int signo=SIGALRM;
    int ret = sigaction(signo, &s, NULL);
    if(ret<0) {  
      perror("sigaction failed");  
      abort();  
    }

    numap_sampling_set_measure_handler(&sm, numap_read_handler, 1000);
    numap_sampling_set_measure_handler(&sm_wr, numap_write_handler, 1000);
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
  printf("%s offline_analysis=%s\n", __FUNCTION__, offline_analysis ? "true" : "false");
  if(offline_analysis) {
    if (get_lib_done < 1) {
      fprintf(stderr, "test\n");
      ma_get_lib_variables();
      ma_get_global_variables();
      get_lib_done++;
    }
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
      mem_allocator_free(sample_mem, prev);
    }
    printf("\n");
    printf("Total: %d samples including %d matches in %d blocks (%lu bytes)\n", nb_samples_total, nb_found_samples_total, nb_blocks, total_buffer_size);
    if(nb_samples_total != 0)
      printf("avg position: %" PRIu64 "\n", avg_pos/nb_samples_total);
    stop_tick(offline_sample_analysis);
    printf("Offline analysis took %lf s\n",tick_duration(offline_sample_analysis)/1e9);
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

/* copy the samples to a buffer so that they can be analyzed later for a thread */
static void __copy_samples_thread(struct numap_sampling_measure *sm,
			   enum access_type access_type,
			   int thread) {
  start_tick(rmb);
  size_t sample_size = 0;
  struct perf_event_mmap_page *metadata_page = sm->metadata_pages_per_tid[thread];

  if(metadata_page->data_tail == metadata_page->data_head)
    /* nothing to do */
    return;
  
  uint8_t* buffer_addr = (uint8_t *)metadata_page;
  uint64_t tail = metadata_page->data_tail;
  uint64_t buffer_size = metadata_page->data_size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
  buffer_addr += metadata_page->data_offset;
#else
  static size_t page_size = 0;
  if(page_size == 0)
    page_size = (size_t)sysconf(_SC_PAGESIZE);
  buffer_addr += page_size;
#endif
  struct perf_event_header *header = (struct perf_event_header *)buffer_addr;
  uint64_t head = metadata_page -> data_head;

  /* where the data begins */
  if (head > buffer_size) {
    head = (head % buffer_size);
  }
  metadata_page -> data_head = head;
  /* On SMP-capable platforms, after reading the data_head value,
   * user space should issue an rmb().
   */
  rmb();

  if (head > tail) {
    sample_size =  head - tail;
  } else {
    sample_size = (buffer_size - tail) + head;
  }

  struct sample_list* new_sample_buffer = mem_allocator_alloc(sample_mem);
  new_sample_buffer->buffer = malloc(sample_size);
  new_sample_buffer->access_type = access_type;
  new_sample_buffer->buffer_size = sample_size;

  start_tick(memcpy_samples);
  if (head > tail) {
    memcpy(new_sample_buffer->buffer, &buffer_addr[tail], sample_size);
  } else {
    memcpy(new_sample_buffer->buffer, &buffer_addr[tail], (buffer_size - tail));
    memcpy(((uint8_t*)new_sample_buffer->buffer) + (buffer_size - tail),
	   &buffer_addr[0],
	   head);
  }

  metadata_page->data_tail = head;
  new_sample_buffer->start_date = start_date;
  new_sample_buffer->stop_date = new_date();
  new_sample_buffer->thread_rank = thread_rank;

  pthread_mutex_lock(&sample_list_lock);
  new_sample_buffer->next = samples;
  samples = new_sample_buffer;
  nb_sample_buffers++;
  pthread_mutex_unlock(&sample_list_lock);


  int nb_samples=0;
  int found_samples=0;
  __analyze_buffer(new_sample_buffer, &nb_samples, &found_samples);

  stop_tick(memcpy_samples);

  debug_printf("[%d] copied %zu bytes\n", thread_rank, sample_size);
  stop_tick(rmb);
}

/* calls __copy_samples_thread on each thread */
static void __copy_samples(struct numap_sampling_measure *sm,
			   enum access_type access_type) {

  /* well, sm->nb_threads should be 1, but let's make things generic */
  int thread;
  for (thread = 0; thread < sm->nb_threads; thread++) {
    __copy_samples_thread(sm, access_type, thread);
  }
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
  enum access_type access_type = samples->access_type;
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
      update_counters(global_counters, sample, access_type);
      if(! match_samples)
	goto next_sample;

      /* find the memory object that corresponds to the sample*/
      struct memory_info* mem_info = ma_find_mem_info_from_sample(sample);

      if(!mem_info) {
	/* no buffer matches sample->addr */
        if (_verbose) {
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
          FILE *debug_file = fopen("missed_samples.txt", "a+");
          fprintf(debug_file, "%p ",sample->addr);
          if (found)
          {
	    if (strstr(line, "lib") != NULL)
	    {
              // the sample has been located in a lib
	      strtok(NULL, " "); // cut_line : perm
	      strtok(NULL, " "); // cut_line : offset
	      strtok(NULL, " "); // cut_line : device
	      strtok(NULL, " "); // cut_line : inode
	      char *file = strtok(NULL, " "); // cut_line : file
              fprintf(debug_file, "located in %s", strtok(line, "\n"));
	      void *handle = NULL;
	      handle = dlopen(file, RTLD_NOW);
	      if (handle == NULL) {
                fprintf(debug_file, "\n\tcould not dlopen");
	      } else {
                Dl_info info;
		const ElfW(Sym) *extra_info = NULL;
		if (dladdr1(addr, &info, (void**)&extra_info, RTLD_DL_SYMENT) == 0) {
                  fprintf(debug_file,"\n\tdladdr1 did not work");
	        } else {
                  fprintf(debug_file, "\n\ttest");
                  fprintf(debug_file, "\n\tdli_sname : %s", info.dli_sname);
                  fprintf(debug_file, "\n\tdli_saddr : %p", info.dli_saddr);
		  if (extra_info != NULL) {
                    fprintf(debug_file, "\n\ttype : %d", ELF64_ST_TYPE(extra_info->st_info));
                    fprintf(debug_file, "\n\tbind : %d", ELF64_ST_BIND(extra_info->st_info));
		  }
		}
		dlclose(handle);
		handle = NULL;
	      }
	    } else {
              fprintf(debug_file, "located in %s", strtok(line, "\n"));
	    }
          }
          else {
            fprintf(debug_file, "matching no address range in %s", maps_path);
          }
          fprintf(debug_file, "\n");
          fclose(debug_file);
	}
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
	update_counters(block->counters, sample, access_type);
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
  if (get_lib_done < 1) {
    fprintf(stderr, "test\n");
    ma_get_lib_variables();
    ma_get_global_variables();
    get_lib_done++;
  }
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

    __analyze_buffer(&samples, &nb_samples, &found_samples);
  }

  if(nb_samples>0) {
    debug_printf("[%lf] \tnb_samples = %d (including %d in mem blocks)\n", get_cur_date(), nb_samples, found_samples);
    nb_samples_total += nb_samples;
    nb_found_samples_total += found_samples;
  }
}
