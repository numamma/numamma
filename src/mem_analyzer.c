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

static void __init_counters(struct memory_info_list* p_node) {
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
}

char null_str[]="";

/* get the list of global/static variables with their address and size */
void ma_get_global_variables() {
  debug_printf("Looking for global variables\n");
  /* get the filename of the program being run */
  char readlink_cmd[1024];
  sprintf(readlink_cmd, "readlink /proc/%d/exe", getpid());
  FILE* f = popen(readlink_cmd, "r");
  char program_file[4096];
  fgets(program_file, 4096, f);
  strtok(program_file, "\n"); // remove trailing newline
  fclose(f);

  debug_printf("  The program file is %s\n", program_file);
  /* get the address at which the program is mapped in memory */
  char cmd[4069];
  char line[4096];
  void *base_addr = NULL;
  void *end_addr = NULL;

  sprintf(cmd, "file \"%s\" |grep \"shared object\" > plop", program_file);
  int ret = system(cmd);
  if(WIFEXITED(ret)) {
    int exit_status= WEXITSTATUS(ret);
    if(exit_status == EXIT_SUCCESS) {
      /* process is compiled with -fPIE, thus, the addresses in the ELF are to be relocated */
      //      sprintf(cmd, "cat /proc/%d/maps |grep \"%s\" | grep  \" rw-p \"", getpid(), program_file);
      sprintf(cmd, "cat /proc/%d/maps |grep \"[heap]\"", getpid(), program_file);
      f = popen(cmd, "r");
      fgets(line, 4096, f);
      fclose(f);
      sscanf(line, "%lx-%lx", &base_addr, &end_addr);
      debug_printf("  This program was compiled with -fPIE. It is mapped at address %p\n", base_addr);
    } else {
    /* process is not compiled with -fPIE, thus, the addresses in the ELF are the addresses in the binary */
      base_addr= NULL;
      end_addr= NULL;
      debug_printf("  This program was not compiled with -fPIE. It is mapped at address %p\n", base_addr);
    }
  }

  /* get the list of global variables in the current binary */
  char nm_cmd[1024];
  sprintf(nm_cmd, "nm --defined-only -l -S %s", program_file);
  f = popen(nm_cmd, "r");

  while(!feof(f)) {
    if( ! fgets(line, 4096, f) ) {
      return;
    }

    /* each line is in the form:
       offset [size] section symbol [file]
     */
    char *addr = null_str;
    char *size_str = null_str;
    char *section = null_str;
    char *symbol = null_str;
    char *file = null_str;

    int nb_found;
    addr = strtok(line, " \t\n");
    assert(addr);
    size_str = strtok(NULL, " \t\n");
    assert(size_str);
    section = strtok(NULL, " \t\n");
    symbol = strtok(NULL, " \t\n");
    if(!symbol) {
      /* only 3 fields (addr section symbol) */
      nb_found = 3;
      symbol = section;
      section = size_str;
      size_str = null_str;
      /* this is not enough (we need the size), skip this one */
      continue;
    } else {
      nb_found = 4;
      /*  fields */
      file = strtok(NULL, " \t\n");
      if(!file) {
	file = null_str;
      } else {
	nb_found = 5;
      }
    }

    if(section[0]== 'b' || section[0]=='B' || /* BSS (uninitialized global vars) section */
       section[0]== 'd' || section[0]=='D' || /* initialized data section */
       section[0]== 'g' || section[0]=='G') { /* initialized data section for small objects */

      size_t size;
      sscanf(size_str, "%lx", &size);
      if(size) {
	struct memory_info_list * p_node = libmalloc(sizeof(struct memory_info_list));

	p_node->mem_info.alloc_date = 0;
	p_node->mem_info.free_date = 0;
	p_node->mem_info.initial_buffer_size = size;
	p_node->mem_info.buffer_size = p_node->mem_info.initial_buffer_size;

	/* addr is the offset within the binary. The actual address of the variable is located at
	 *  addr+base_addr
	 */
	size_t offset;
	sscanf(addr, "%lx", &offset);
	p_node->mem_info.buffer_addr = offset + (uint8_t*)base_addr;
	p_node->mem_info.caller = malloc(sizeof(char)*1024);
	snprintf(p_node->mem_info.caller, 1024, "%s in %s", symbol, file);
	__init_counters(p_node);

	debug_printf("Found a global variable: %s (defined at %s). base addr=%p, size=%d\n",
		     symbol, file, p_node->mem_info.buffer_addr, p_node->mem_info.buffer_size);
	/* todo: insert large buffers at the beginning of the list since
	 * their are more likely to be accessed often (this will speed
	 * up searching at runtime)
	 */
	pthread_mutex_lock(&mem_list_lock);
	p_node->next = mem_list;
	mem_list = p_node;
	pthread_mutex_unlock(&mem_list_lock);
      }
    }
  }
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
  info->record_info = &p_node->mem_info;

  /* the current backtrace looks like this:
   * 0 - get_caller_function()
   * 1 - ma_record_malloc()
   * 2 - malloc()
   * 3 - caller_function()
   *
   * So, we need to get the name of the function in frame 3.
   */
  p_node->mem_info.caller = get_caller_function(3);
  __init_counters(p_node);

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

void ma_update_buffer_address(struct mem_block_info* info, void *old_addr, void *new_addr) {
  if(!IS_RECORD_SAFE)
    return;
  if(!info->record_info)
    return;

  PROTECT_RECORD;

  mem_sampling_collect_samples();
  /* todo: do we really need the lock here ?
   * when this list is modified, it is only for inserting new nodes, so browsing the list could
   * be done without holding the lock ?
   */
  struct memory_info* mem_info = info->record_info;
  assert(mem_info);
  mem_info->buffer_addr = new_addr;

  mem_sampling_start();
  UNPROTECT_RECORD;
}

void ma_record_free(struct mem_block_info* info) {
  if(!IS_RECORD_SAFE)
    return;
  if(!info->record_info)
    return;

  PROTECT_RECORD;
  mem_sampling_collect_samples();

  struct memory_info* mem_info = info->record_info;
  assert(mem_info);
  mem_info->buffer_size = info->size;
  mem_info->free_date = new_date();
  debug_printf("[%lu] [%lx] free(%p)\n",
	       mem_info->free_date,
	       pthread_self(),
	       mem_info->buffer_addr);

  mem_sampling_start();
  UNPROTECT_RECORD;
}

struct call_site {
  char* caller;
  size_t buffer_size;
  unsigned nb_mallocs;
  struct memory_info mem_info;
  struct call_site *next;
};
struct call_site* call_sites = NULL;

struct call_site *find_call_site(struct memory_info_list* p_node) {
  struct call_site * cur_site = call_sites;
  while(cur_site) {
    if(cur_site->buffer_size == p_node->mem_info.initial_buffer_size &&
       strcmp(cur_site->caller, p_node->mem_info.caller) == 0) {
      return cur_site;
    }
    cur_site = cur_site->next;
  }
  return NULL;
}

struct call_site * new_call_site(struct memory_info_list* p_node) {
  struct call_site * site = malloc(sizeof(struct call_site));
  site->caller = malloc(sizeof(char)*strlen(p_node->mem_info.caller));
  strcpy(site->caller, p_node->mem_info.caller);
  site->buffer_size =  p_node->mem_info.initial_buffer_size;
  site->nb_mallocs = 0;

  site->mem_info.alloc_date = 0;
  site->mem_info.free_date = 0;
  site->mem_info.initial_buffer_size = p_node->mem_info.initial_buffer_size;
  site->mem_info.buffer_size = p_node->mem_info.buffer_size;
  site->mem_info.buffer_addr = p_node->mem_info.buffer_addr;
  site->mem_info.caller = site->caller;
  int i;
  for(i = 0; i<ACCESS_MAX; i++) {
    memset(&site->mem_info.count[i], 0, sizeof(struct mem_counters));
  }

  site->next = call_sites;
  call_sites = site;
  return site;
}

void update_call_sites(struct memory_info_list* p_node) {
  struct call_site* site = find_call_site(p_node);
  if(!site) {
    site = new_call_site(p_node);
  }

  site->nb_mallocs++;
  int i;
  for(i=0; i<ACCESS_MAX; i++) {
    site->mem_info.count[i].total_count         += p_node->mem_info.count[i].total_count;
    site->mem_info.count[i].na_miss_count       += p_node->mem_info.count[i].na_miss_count;
    site->mem_info.count[i].cache1_count        += p_node->mem_info.count[i].cache1_count;
    site->mem_info.count[i].cache2_count        += p_node->mem_info.count[i].cache2_count;
    site->mem_info.count[i].cache3_count        += p_node->mem_info.count[i].cache3_count;
    site->mem_info.count[i].lfb_count           += p_node->mem_info.count[i].lfb_count;
    site->mem_info.count[i].memory_count        += p_node->mem_info.count[i].memory_count;
    site->mem_info.count[i].remote_memory_count += p_node->mem_info.count[i].remote_memory_count;
    site->mem_info.count[i].remote_cache_count  += p_node->mem_info.count[i].remote_cache_count;
  }
}

void print_call_site_summary() {
  printf("Summary of the call sites:\n");
  printf("--------------------------\n");
  struct call_site* site = call_sites;
  while(site) {
    if(site->mem_info.count[ACCESS_READ].total_count || site->mem_info.count[ACCESS_WRITE].total_count) {
      printf("%s (size=%d) - %d buffers. %d read access. %d wr_access\n", site->caller, site->buffer_size, site->nb_mallocs, site->mem_info.count[ACCESS_READ].total_count, site->mem_info.count[ACCESS_WRITE].total_count);
      printf("\tREAD accesses:\n");
      printf("\tna_miss_count:	   %d\n", site->mem_info.count[ACCESS_READ].na_miss_count);
      printf("\tcache1_count:	   %d\n", site->mem_info.count[ACCESS_READ].cache1_count);
      printf("\tcache2_count:	   %d\n", site->mem_info.count[ACCESS_READ].cache2_count);
      printf("\tcache3_count:	   %d\n", site->mem_info.count[ACCESS_READ].cache3_count);
      printf("\tlfb_count:	   %d\n", site->mem_info.count[ACCESS_READ].lfb_count);
      printf("\tmemory_count:	   %d\n", site->mem_info.count[ACCESS_READ].memory_count);
      printf("\tremote_memory_count: %d\n", site->mem_info.count[ACCESS_READ].remote_memory_count);
      printf("\tremote_cache_count:  %d\n", site->mem_info.count[ACCESS_READ].remote_cache_count);
      printf("\n");
      printf("\tWRITE accesses:\n");
      printf("\tna_miss_count:	   %d\n",   site->mem_info.count[ACCESS_WRITE].na_miss_count);
      printf("\tcache1_count:	   %d\n",   site->mem_info.count[ACCESS_WRITE].cache1_count);
      printf("\tcache2_count:	   %d\n",   site->mem_info.count[ACCESS_WRITE].cache2_count);
      printf("\tcache3_count:	   %d\n",   site->mem_info.count[ACCESS_WRITE].cache3_count);
      printf("\tlfb_count:	   %d\n",   site->mem_info.count[ACCESS_WRITE].lfb_count);
      printf("\tmemory_count:	   %d\n",   site->mem_info.count[ACCESS_WRITE].memory_count);
      printf("\tremote_memory_count: %d\n", site->mem_info.count[ACCESS_WRITE].remote_memory_count);
      printf("\tremote_cache_count:  %d\n", site->mem_info.count[ACCESS_WRITE].remote_cache_count);
    }
    site = site->next;
  }
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
    update_call_sites(p_node);

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

  print_call_site_summary();

  if(_dump) {
    fclose(dump_file);
  }
  pthread_mutex_unlock(&mem_list_lock);
  UNPROTECT_RECORD;
}
