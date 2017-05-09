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

#define USE_HASHTABLE

//static __thread  int  __record_infos = 0;

#ifdef USE_HASHTABLE
#include "hash.h"
typedef struct ht_node* mem_info_node_t;
#else
struct memory_info_list {
  struct memory_info_list* next;
  struct memory_info mem_info;
};
typedef struct memory_info_list* mem_info_node_t;
#endif

static mem_info_node_t mem_list = NULL; // malloc'd buffers currently in use
static mem_info_node_t past_mem_list = NULL; // malloc'd buffers that were freed
static pthread_mutex_t mem_list_lock;

__thread unsigned thread_rank;
unsigned next_thread_rank = 0;

static __thread int is_record_safe = 1;
#define IS_RECORD_SAFE (is_record_safe)

#define PROTECT_RECORD do {			\
    assert(is_record_safe !=0);			\
    is_record_safe = 0;				\
  } while(0)

#define UNPROTECT_RECORD do {			\
    assert(is_record_safe == 0);		\
    is_record_safe = 1;				\
  } while(0)

struct mem_allocator* mem_info_allocator = NULL;
struct mem_allocator* string_allocator = NULL;

/* todo:
 * - set an alarm every 1ms to collect the sampling info
 * - choose the buffer size
 * - collect read/write accesses
 */
void ma_init() {
  PROTECT_RECORD;
  pthread_mutex_init(&mem_list_lock, NULL);

#ifdef USE_HASHTABLE
  mem_allocator_init(&mem_info_allocator,
		     sizeof(struct memory_info),
		     1024);
#else
  mem_allocator_init(&mem_info_allocator,
		     sizeof(struct memory_info_list),
		     1024);
#endif

  mem_allocator_init(&string_allocator,
		     sizeof(char)*1024,
		     1024);
  mem_sampling_init();
  ma_thread_init();
  UNPROTECT_RECORD;
}

void ma_thread_init() {
  thread_rank = __sync_fetch_and_add( &next_thread_rank, 1 );

  mem_sampling_thread_init();
}

void ma_thread_finalize() {
  PROTECT_RECORD;
  mem_sampling_thread_finalize();
  pid_t tid = syscall(SYS_gettid);
  UNPROTECT_RECORD;
}

static uint64_t new_date() {
#ifdef __x86_64__
  // This is a copy of rdtscll function from asm/msr.h
#define ticks(val) do {					\
    uint32_t __a,__d;					\
    asm volatile("rdtsc" : "=a" (__a), "=d" (__d));	\
    (val) = ((uint64_t)__a) | (((uint64_t)__d)<<32);	\
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


static mem_info_node_t
__ma_find_mem_info_from_addr_generic(mem_info_node_t list,
				     uint64_t ptr) {
  mem_info_node_t retval = NULL;
  int n=0;
  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  mem_info_node_t p_node =  ht_lower_key(list, ptr);
  if(p_node && is_address_in_buffer(ptr, p_node->value)) {
    retval = p_node;
  }
#else
  struct memory_info_list * p_node = list;
  while(p_node) {
    if(is_address_in_buffer(ptr, &p_node->mem_info)) {
      retval = p_node;
      goto out;
    }
    n++;
    p_node = p_node->next;
  }
#endif

 out:
  if(n > 100) {
    printf("%s: %d buffers\n", __FUNCTION__, n);
  }
  pthread_mutex_unlock(&mem_list_lock);
  return retval;
}


struct memory_info*
ma_find_mem_info_from_addr(uint64_t ptr) {
  mem_info_node_t ret = __ma_find_mem_info_from_addr_generic(mem_list, ptr);
  if(ret) {
#ifdef USE_HASHTABLE
    return ret->value;
#else
    return &ret->mem_info;
#endif
  }
  return NULL;
}

struct memory_info*
ma_find_past_mem_info_from_addr(uint64_t ptr) {
  mem_info_node_t ret = __ma_find_mem_info_from_addr_generic(past_mem_list, ptr);
  if(ret) {
#ifdef USE_HASHTABLE
    return ret->value;
#else
    return &ret->mem_info;
#endif
  }
  return NULL;
}


static void __init_counters(struct memory_info* mem_info) {
  int i, j;
  for(i=0; i<MAX_THREADS; i++) {
    for(j=0; j<ACCESS_MAX; j++) {
      mem_info->count[i][j].total_count = 0;
      mem_info->count[i][j].na_miss_count = 0;
      mem_info->count[i][j].cache1_count = 0;
      mem_info->count[i][j].cache2_count = 0;
      mem_info->count[i][j].cache3_count = 0;
      mem_info->count[i][j].lfb_count = 0;
      mem_info->count[i][j].memory_count = 0;
      mem_info->count[i][j].remote_memory_count = 0;
      mem_info->count[i][j].remote_cache_count = 0;
    }
  }
}
char null_str[]="";

/* unset LD_PRELOAD
 * this makes sure that forked processes will not be analyzed
 */
extern void unset_ld_preload();

/* set LD_PRELOAD so that future forked processes are analyzed
 *  you need to call unset_ld_preload before calling this function
 */
extern void reset_ld_preload();


/* get the list of global/static variables with their address and size */
void ma_get_global_variables() {
  /* make sure forked processes (eg nm, readlink, etc.) won't be analyzed */
  unset_ld_preload();

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
      goto out;
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
	struct memory_info * mem_info = NULL;
#ifdef USE_HASHTABLE
	mem_info = mem_allocator_alloc(mem_info_allocator);
#else
	struct memory_info_list * p_node = mem_allocator_alloc(mem_info_allocator);
	mem_info = &p_node->mem_info;
#endif

	mem_info->alloc_date = 0;
	mem_info->free_date = 0;
	mem_info->initial_buffer_size = size;
	mem_info->buffer_size = mem_info->initial_buffer_size;

	/* addr is the offset within the binary. The actual address of the variable is located at
	 *  addr+base_addr
	 */
	size_t offset;
	sscanf(addr, "%lx", &offset);
	mem_info->buffer_addr = offset + (uint8_t*)base_addr;
	mem_info->caller = mem_allocator_alloc(string_allocator);
	snprintf(mem_info->caller, 1024, "%s in %s", symbol, file);
	__init_counters(mem_info);

	debug_printf("Found a global variable: %s (defined at %s). base addr=%p, size=%d\n",
		     symbol, file, mem_info->buffer_addr, mem_info->buffer_size);
	pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
	mem_list = ht_insert(mem_list, (uint64_t) mem_info->buffer_addr, mem_info);
#else
	/* todo: insert large buffers at the beginning of the list since
	 * their are more likely to be accessed often (this will speed
	 * up searching at runtime)
	 */
	p_node->next = mem_list;
	mem_list = p_node;
#endif
	pthread_mutex_unlock(&mem_list_lock);
      }
    }
  }
 out:
  /* Restore LD_PRELOAD.
   * This is usefull when the program is run with gdb. gdb creates a process than runs bash -e prog arg1
   * Thus, the ld_preload affects bash. bash then calls execvp to execute the program.
   * If we unset ld_preload, the ld_preload will only affect bash (and not the programà
   * Hence, we need to restore ld_preload here.
   */
  reset_ld_preload();
}

void ma_record_malloc(struct mem_block_info* info) {
  if(!IS_RECORD_SAFE)
    return;
  PROTECT_RECORD;

  mem_sampling_collect_samples();

  struct memory_info * mem_info = NULL;
#ifdef USE_HASHTABLE
  mem_info = mem_allocator_alloc(mem_info_allocator);
#else
  struct memory_info_list * p_node = mem_allocator_alloc(mem_info_allocator);
  mem_info = &p_node->mem_info;
#endif

  mem_info->alloc_date = new_date();
  mem_info->free_date = 0;
  mem_info->initial_buffer_size = info->size;
  mem_info->buffer_size = info->size;
  mem_info->buffer_addr = info->u_ptr;
  info->record_info = mem_info;

  /* the current backtrace looks like this:
   * 0 - get_caller_function()
   * 1 - ma_record_malloc()
   * 2 - malloc()
   * 3 - caller_function()
   *
   * So, we need to get the name of the function in frame 3.
   */
  //  mem_info->caller = get_caller_function(3);
  mem_info->caller = NULL;
  mem_info->caller_rip = get_caller_rip(3);
  __init_counters(mem_info);

  debug_printf("[%lu] [%lx] malloc(%lu bytes) -> u_ptr=%p\n",
	       mem_info->alloc_date,
	       pthread_self(),
	       mem_info->initial_buffer_size,
	       mem_info->buffer_addr);

  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  mem_list = ht_insert(mem_list, (uint64_t) mem_info->buffer_addr, mem_info);
#else
  p_node->next = mem_list;
  mem_list = p_node;
#endif
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
  struct memory_info* mem_info = info->record_info;
  assert(mem_info);
  mem_info->buffer_addr = new_addr;

  mem_sampling_start();
  UNPROTECT_RECORD;
}

/*
 * remove mem_info from the list of active buffers and add it to the list of inactive buffers
 */
void set_buffer_free(struct mem_block_info* p_block) {
  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  struct memory_info* mem_info = p_block->record_info;
  mem_list = ht_remove_key(mem_list, (uint64_t)mem_info->buffer_addr);
  past_mem_list =  ht_insert(past_mem_list, (uint64_t)mem_info->buffer_addr, mem_info);

#else
  struct memory_info_list * p_node = mem_list;
  if(p_block->record_info == &p_node->mem_info) {
    /* the first record is the one we're looking for */
    mem_list = p_node->next;
    p_node->next = past_mem_list;
    past_mem_list = p_node;
    goto out;
  }

  /* browse the list of malloc'd buffers */
  while(p_node->next) {
    if(&p_node->next->mem_info == p_block->record_info) {
      struct memory_info_list *to_move = p_node->next;
      /* remove to_move from the list of malloc'd buffers */
      p_node->next = to_move->next;
      /* add it to the list of freed buffers */
      to_move->next = past_mem_list;
      past_mem_list = to_move;
      goto out;
    }
    p_node = p_node->next;
  }
  /* couldn't find p_block in the list of malloc'd buffers */
  fprintf(stderr, "Error: I tried to free block %p, but I could'nt find it in the list of malloc'd buffers\n", p_block);
  abort();
#endif
 out:
  pthread_mutex_unlock(&mem_list_lock);
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

  set_buffer_free(info);
  mem_sampling_start();
  UNPROTECT_RECORD;
}

struct call_site {
  char* caller;
  void* caller_rip;
  size_t buffer_size;
  unsigned nb_mallocs;
  struct memory_info mem_info;
  struct mem_counters cumulated_counters[ACCESS_MAX];
  struct call_site *next;
};
struct call_site* call_sites = NULL;

struct call_site *find_call_site(struct memory_info* mem_info) {
  struct call_site * cur_site = call_sites;
  while(cur_site) {
    if(cur_site->buffer_size == mem_info->initial_buffer_size &&
       cur_site->caller_rip == mem_info->caller_rip) {
      return cur_site;
    }
    cur_site = cur_site->next;
  }
  return NULL;
}

struct call_site * new_call_site(struct memory_info* mem_info) {
  struct call_site * site = libmalloc(sizeof(struct call_site));
  if(!mem_info->caller) {
    mem_info->caller = get_caller_function_from_rip(mem_info->caller_rip);
  }
  site->caller_rip = mem_info->caller_rip;
  site->caller = mem_allocator_alloc(string_allocator);
  strcpy(site->caller, mem_info->caller);
  site->buffer_size =  mem_info->initial_buffer_size;
  site->nb_mallocs = 0;

  site->mem_info.alloc_date = 0;
  site->mem_info.free_date = 0;
  site->mem_info.initial_buffer_size = mem_info->initial_buffer_size;
  site->mem_info.buffer_size = mem_info->buffer_size;
  site->mem_info.buffer_addr = mem_info->buffer_addr;
  site->mem_info.caller = site->caller;
  site->mem_info.caller_rip = site->caller_rip;
  int i, j;
  for(j = 0; j<ACCESS_MAX; j++) {
    memset(&site->cumulated_counters[j], 0, sizeof(struct mem_counters));
  }
  for(i = 0; i<MAX_THREADS; i++) {
    for(j = 0; j<ACCESS_MAX; j++) {
      memset(&site->mem_info.count[i][j], 0, sizeof(struct mem_counters));
    }
  }

  site->next = call_sites;
  call_sites = site;
  return site;
}

void update_call_sites(struct memory_info* mem_info) {
  struct call_site* site = find_call_site(mem_info);
  if(!site) {
    site = new_call_site(mem_info);
  }

  site->nb_mallocs++;
  int i, j;
  for(i = 0; i<MAX_THREADS; i++) {
    for(j = 0; j<ACCESS_MAX; j++) {
      site->mem_info.count[i][j].total_count         += mem_info->count[i][j].total_count;
      site->mem_info.count[i][j].na_miss_count       += mem_info->count[i][j].na_miss_count;
      site->mem_info.count[i][j].cache1_count        += mem_info->count[i][j].cache1_count;
      site->mem_info.count[i][j].cache2_count        += mem_info->count[i][j].cache2_count;
      site->mem_info.count[i][j].cache3_count        += mem_info->count[i][j].cache3_count;
      site->mem_info.count[i][j].lfb_count           += mem_info->count[i][j].lfb_count;
      site->mem_info.count[i][j].memory_count        += mem_info->count[i][j].memory_count;
      site->mem_info.count[i][j].remote_memory_count += mem_info->count[i][j].remote_memory_count;
      site->mem_info.count[i][j].remote_cache_count  += mem_info->count[i][j].remote_cache_count;

      site->cumulated_counters[j].total_count         += mem_info->count[i][j].total_count;
      site->cumulated_counters[j].na_miss_count       += mem_info->count[i][j].na_miss_count;
      site->cumulated_counters[j].cache1_count        += mem_info->count[i][j].cache1_count;
      site->cumulated_counters[j].cache2_count        += mem_info->count[i][j].cache2_count;
      site->cumulated_counters[j].cache3_count        += mem_info->count[i][j].cache3_count;
      site->cumulated_counters[j].lfb_count           += mem_info->count[i][j].lfb_count;
      site->cumulated_counters[j].memory_count        += mem_info->count[i][j].memory_count;
      site->cumulated_counters[j].remote_memory_count += mem_info->count[i][j].remote_memory_count;
      site->cumulated_counters[j].remote_cache_count  += mem_info->count[i][j].remote_cache_count;
    }
  }
}

void print_call_site_summary() {
  printf("Summary of the call sites:\n");
  printf("--------------------------\n");
  struct call_site* site = call_sites;
  int nb_threads = next_thread_rank;
  while(site) {
    if(site->cumulated_counters[ACCESS_READ].total_count ||
       site->cumulated_counters[ACCESS_WRITE].total_count) {

      printf("%s (size=%d) - %d buffers. %d read access. %d wr_access\n", site->caller, site->buffer_size, site->nb_mallocs, site->cumulated_counters[ACCESS_READ].total_count, site->cumulated_counters[ACCESS_WRITE].total_count);

#define PRINT_COUNTERS(access_type, counter) do {			\
	if(site->cumulated_counters[access_type].counter) {		\
	  printf("\t%s:\t", #counter);					\
	  for(int i=0; i< nb_threads; i++) {				\
	    printf("%d\t", site->mem_info.count[i][access_type].counter); \
	  }								\
	  printf("\n");							\
	}								\
      } while(0)

      printf("\tREAD accesses:\n");
      PRINT_COUNTERS(ACCESS_READ, na_miss_count);
      PRINT_COUNTERS(ACCESS_READ, cache1_count);
      PRINT_COUNTERS(ACCESS_READ, cache2_count);
      PRINT_COUNTERS(ACCESS_READ, cache3_count);
      PRINT_COUNTERS(ACCESS_READ, lfb_count);
      PRINT_COUNTERS(ACCESS_READ, memory_count);
      PRINT_COUNTERS(ACCESS_READ, remote_memory_count);
      PRINT_COUNTERS(ACCESS_READ, remote_cache_count);

      printf("\tWRITE accesses:\n");
      PRINT_COUNTERS(ACCESS_WRITE, na_miss_count);
      PRINT_COUNTERS(ACCESS_WRITE, cache1_count);
      PRINT_COUNTERS(ACCESS_WRITE, cache2_count);
      PRINT_COUNTERS(ACCESS_WRITE, cache3_count);
      PRINT_COUNTERS(ACCESS_WRITE, lfb_count);
      PRINT_COUNTERS(ACCESS_WRITE, memory_count);
      PRINT_COUNTERS(ACCESS_WRITE, remote_memory_count);
      PRINT_COUNTERS(ACCESS_WRITE, remote_cache_count);
    }
    site = site->next;
  }
}

/* browse the list of malloc'd buffers that were not freed */
void warn_non_freed_buffers() {

  pthread_mutex_lock(&mem_list_lock);

  struct memory_info* mem_info = NULL;
#ifdef USE_HASHTABLE
  while(mem_list) {
    mem_info = mem_list->value;
#else
  while(mem_list) {
    mem_info = mem_list;
#endif

#if WARN_NON_FREED
    printf("Warning: buffer %p (size=%lu bytes) was not freed\n",
	   p_node->mem_info.buffer_addr, p_node->mem_info.buffer_size);
#endif

    mem_info->free_date = new_date();

    /* remove the record from the list of malloc'd buffers */
#ifdef USE_HASHTABLE
    mem_list = ht_remove_key(mem_list, mem_list->key);
    past_mem_list =  ht_insert(past_mem_list, (uint64_t)mem_info->buffer_addr, mem_info);

#else
    mem_list = p_node->next;
    /* add to the list of freed buffers */
    p_node->next = past_mem_list;
    past_mem_list = p_node;
#endif
  }

  pthread_mutex_unlock(&mem_list_lock);
}

void ma_finalize() {
  ma_thread_finalize();
  PROTECT_RECORD;

  warn_non_freed_buffers();

  printf("---------------------------------\n");
  printf("         MEM ANALYZER\n");
  printf("---------------------------------\n");

  pthread_mutex_lock(&mem_list_lock);

  mem_info_node_t p_node = NULL;
  struct memory_info* mem_info = NULL;

  /* browse the list of memory buffers  */
#ifdef USE_HASHTABLE
  FOREACH_HASH(past_mem_list, p_node) {
    mem_info = p_node->value;
#else
    for(p_node = past_mem_list;
	p_node;
	p_node = p_node->next) {
      mem_info = &p_node->mem_info;
#endif
      update_call_sites(mem_info);

      uint64_t duration = mem_info->free_date?
	mem_info->free_date-mem_info->alloc_date:
	0;

      int nb_threads = next_thread_rank;
      unsigned total_read_count = 0;
      unsigned total_write_count = 0;
      for(int i=0; i<nb_threads; i++) {
	total_read_count += mem_info->count[i][ACCESS_READ].total_count;
	total_write_count += mem_info->count[i][ACCESS_WRITE].total_count;
      }

      if(total_read_count > 0 ||
	 total_write_count > 0) {

	double r_access_frequency;
	if(total_read_count)
	  r_access_frequency = (duration/sampling_rate)/total_read_count;
	else
	  r_access_frequency = 0;
	double w_access_frequency;
	if(total_write_count)
	  w_access_frequency = (duration/sampling_rate)/total_write_count;
	else
	  w_access_frequency = 0;

	debug_printf("buffer %p (%lu bytes) duration =%lu ticks. %d write accesses, %d read accesses. allocated : %s. read operation every %lf ticks\n",
		     mem_info->buffer_addr,
		     mem_info->initial_buffer_size,
		     duration,
		     total_read_count,
		     total_write_count,
		     mem_info->caller,
		     r_access_frequency);
      }

    }

    print_call_site_summary();

    mem_sampling_statistics();
    if(_dump) {
      fclose(dump_file);
    }
    pthread_mutex_unlock(&mem_list_lock);
    UNPROTECT_RECORD;
  }
