#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <execinfo.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <gelf.h>

#include "mem_intercept.h"
#include "mem_analyzer.h"
#include "mem_tools.h"
#include "mem_sampling.h"

#define USE_HASHTABLE
#define WARN_NON_FREED 1

#ifdef USE_HASHTABLE
#include "hash.h"
typedef struct ht_node* mem_info_node_t;
#else
struct memory_info_list {
  struct memory_info_list* next;
  struct memory_info_list* prev;
  struct memory_info mem_info;
};
typedef struct memory_info_list* mem_info_node_t;
#endif

static mem_info_node_t mem_list = NULL; // malloc'd buffers currently in use
static mem_info_node_t past_mem_list = NULL; // malloc'd buffers that were freed
static pthread_mutex_t mem_list_lock;

__thread unsigned thread_rank;
unsigned next_thread_rank = 0;
#define PROGRAM_FILE_LEN 4096 // used for readlink cmd
static char program_file[PROGRAM_FILE_LEN];

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

__thread struct mem_allocator* mem_info_allocator = NULL;
struct mem_allocator* string_allocator = NULL;

__thread struct tick tick_array[NTICKS];

date_t origin_date;
#define DATE(d) ((d)-origin_date)

/* todo:
 * - set an alarm every 1ms to collect the sampling info
 * - choose the buffer size
 * - collect read/write accesses
 */
void ma_init() {
  PROTECT_RECORD;
  pthread_mutex_init(&mem_list_lock, NULL);
  origin_date = new_date();

  mem_allocator_init(&string_allocator,
		     sizeof(char)*1024,
		     16*1024);

  mem_sampling_init();
  ma_thread_init();
  UNPROTECT_RECORD;
}

void ma_thread_init() {
  thread_rank = __sync_fetch_and_add( &next_thread_rank, 1 );

#ifdef USE_HASHTABLE
  mem_allocator_init(&mem_info_allocator,
		     sizeof(struct memory_info),
		     16*1024);
#else
  mem_allocator_init(&mem_info_allocator,
		     sizeof(struct memory_info_list),
		     16*1024);
#endif

  for(int i=0; i<NTICKS; i++) {
    init_tick(i);
  }

  mem_sampling_thread_init();
}

void ma_thread_finalize() {
  PROTECT_RECORD;

  mem_sampling_thread_finalize();

  pid_t tid = syscall(SYS_gettid);
#if  ENABLE_TICKS
  if(_verbose) {
    printf("End of thread %s %d\n", __FUNCTION__, tid);
    for(int i=0; i<NTICKS; i++) {
      if(tick_array[i].nb_calls>0) {
	double total_duration = tick_array[i].total_duration;
	double avg_duration = total_duration / tick_array[i].nb_calls;
	printf("tick[%d] : %s -- %d calls. %lf us per call (total: %lf ms)\n",
	       i, tick_array[i].tick_name, tick_array[i].nb_calls,
	       avg_duration/1e3, total_duration/1e6);
      }
    }
  }
#endif
  UNPROTECT_RECORD;
}

static
int is_address_in_buffer(uint64_t addr, struct memory_info *buffer){
  void* addr_ptr = (void*)addr;
  if(buffer->buffer_addr <= addr_ptr &&
     addr_ptr < buffer->buffer_addr + buffer->buffer_size)
    return 1;
  return 0;
}

static
int is_sample_in_buffer(struct mem_sample *sample, struct memory_info *buffer){
  void* addr_ptr = (void*)sample->addr;
  if(buffer->buffer_addr <= addr_ptr &&
     addr_ptr < buffer->buffer_addr + buffer->buffer_size) {
    /* address matches */
    return 1;
    if(buffer->alloc_date <=sample->timestamp &&
       sample->timestamp <= buffer->free_date) {
      /* timestamp matches */
      return 1;
    }
  }
  return 0;
}

void ma_print_mem_info(FILE*f, struct memory_info *mem) {
  if(mem) {
    if(!mem->caller) {
      mem->caller = get_caller_function_from_rip(mem->caller_rip);
    }

    fprintf(f, "mem %p = {.addr=0x%"PRIx64", .alloc_date=%" PRIu64 ", .free_date=%" PRIu64 ", size=%ld, alloc_site=%p / %s}\n", mem,
	   mem->buffer_addr, mem->alloc_date?DATE(mem->alloc_date):0, mem->free_date?DATE(mem->free_date):0,
	   mem->buffer_size, mem->caller_rip, mem->caller?mem->caller:"");
  }
}

static void __ma_print_buffers_generic(FILE*f, mem_info_node_t list) {
#ifdef USE_HASHTABLE
  /* todo */
  struct ht_node*p_node = NULL;
  FOREACH_HASH(mem_list, p_node) {
    struct ht_entry*e = p_node->entries;
    while(e) {
      struct memory_info* mem_info = e->value;
      ma_print_mem_info(f, mem_info);
      e = e->next;
    }

  }
#else
  struct memory_info_list * p_node = list;
  while(p_node) {
    ma_print_mem_info(f, &p_node->mem_info);
    p_node = p_node->next;
  }
#endif
}

void ma_print_current_buffers() {
  __ma_print_buffers_generic(stdout, mem_list);
}

void ma_print_past_buffers() {
  __ma_print_buffers_generic(stdout, past_mem_list);
}

static mem_info_node_t
__ma_find_mem_info_from_addr_generic(mem_info_node_t list,
				     uint64_t ptr) {
  mem_info_node_t retval = NULL;
  int n=0;
  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  mem_info_node_t p_node =  ht_lower_key(list, ptr);
  if(p_node) {
    struct ht_entry*e = p_node->entries;
    while(e) {
      if(is_address_in_buffer(ptr, e->value)) {
	retval = p_node;
      }
      e = e->next;
    }
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

static struct memory_info*
__ma_find_mem_info_from_sample_generic(mem_info_node_t list,
				       struct mem_sample *sample) {
  struct memory_info* retval = NULL;
  int n=0;
  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  mem_info_node_t p_node =  ht_lower_key(list, sample->addr);
  if(p_node) {
    struct ht_entry*e = p_node->entries;
    while(e) {
      struct memory_info*val = e->value;   
      if(is_sample_in_buffer(sample, e->value)) {
	retval = e->value;
	goto out;
      }
      e = e->next;
    }
  }
#else
  struct memory_info_list * p_node = list;
  while(p_node) {
    if(is_sample_in_buffer(sample, &p_node->mem_info)) {
      retval = p_node->value;
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
  /* todo: a virer */
  mem_info_node_t ret = __ma_find_mem_info_from_addr_generic(mem_list, ptr);
  if(ret) {
#ifdef USE_HASHTABLE
    return ret->entries->value;
#else
    return &ret->mem_info;
#endif
  }
  return NULL;
}

struct memory_info*
ma_find_mem_info_from_sample(struct mem_sample* sample) {
  return __ma_find_mem_info_from_sample_generic(mem_list, sample);
}

uint64_t avg_pos = 0;

static mem_info_node_t
__ma_find_mem_info_in_list(mem_info_node_t *list,
			   uint64_t ptr,
			   date_t start_date,
			   date_t stop_date) {
#ifdef USE_HASHTABLE
  fprintf(stderr, "%s not implemented\n", __FUNCTION__);
  return NULL;
#else
  mem_info_node_t retval = NULL;
  int n=0;
  pthread_mutex_lock(&mem_list_lock);
  struct memory_info_list * p_node = *list;
  uint64_t pos = 0;
  while(p_node) {
    if(is_address_in_buffer(ptr, &p_node->mem_info)) {
      if((! p_node->mem_info.alloc_date) /* the buffer is a global variable */
	 ||
	 (p_node->mem_info.alloc_date >= start_date &&
	  p_node->mem_info.free_date <= stop_date)  /* the access happened during the lifespan
						       of the buffer */
	 ||
	 (start_date >= p_node->mem_info.alloc_date &&
	  start_date <= p_node->mem_info.free_date) /* the variable was allocated during the
						       range of the memory access */
	 ||
	 (stop_date >= p_node->mem_info.alloc_date &&
	  stop_date <= p_node->mem_info.free_date)  /* the variable was freed during the
						       range of the memory access */
	 ) {

	/* the buffer existed during the timeframe. It may have been allocated or
	 * freed during the timeframe, but let's say we found a hit
	 */

	retval = p_node;
	goto out;
      } else {
	printf("When searching for %p (%" PRIu64 "-%" PRIu64 "), found %p (%" PRIu64 "-%" PRIu64 ")\n",
	       (void*)ptr, DATE(start_date), DATE(stop_date),
	       p_node->mem_info.buffer_addr, DATE(p_node->mem_info.alloc_date),
	       DATE(p_node->mem_info.free_date));
      }
    }
    n++;
    p_node = p_node->next;
    pos++;
  }

 out:
  pthread_mutex_unlock(&mem_list_lock);
  avg_pos += pos;
  return retval;
#endif
}

/* search for a buffer that contains address ptr
 * the memory access occured between start_date and stop_date
 */
struct memory_info*
ma_find_past_mem_info_from_addr(uint64_t ptr,
				date_t start_date,
				date_t stop_date) {
  /* todo: a virer */
#ifdef USE_HASHTABLE
  mem_info_node_t ret = __ma_find_mem_info_from_addr_generic(past_mem_list, ptr);
#else
  mem_info_node_t ret = __ma_find_mem_info_in_list(&past_mem_list, ptr, start_date, stop_date);
#endif

  if(ret) {
    struct memory_info* retval = NULL;
#ifdef USE_HASHTABLE
    retval = ret->entries->value;
    if((retval->alloc_date >= start_date &&
	retval->alloc_date <= stop_date) ||
       (retval->free_date >= start_date &&
	retval->free_date <= stop_date))    
#else
      retval = &ret->mem_info;
    if(1) 
#endif
      {
	/* the buffer existed during the timeframe. It may have been allocated or
	 * freed during the timeframe, but let's say we found a hit
	 */
	return retval;
      } else {
        printf("When searching for %p (%" PRIu64 "-%" PRIu64 "), found %p (%" PRIu64 "-%" PRIu64 ")\n",
	       (void*)ptr, DATE(start_date), DATE(stop_date),
	     retval->buffer_addr, DATE(retval->alloc_date), DATE(retval->free_date));
    }
  }
  return NULL;
}

static void __allocate_counters(struct memory_info* mem_info) {
  mem_info->blocks = malloc(sizeof(struct block_info*) * MAX_THREADS);
  for(int i=0; i<MAX_THREADS; i++) {
    mem_info->blocks[i] = malloc(sizeof(struct block_info));
    mem_info->blocks[i]->block_id = 0;
    mem_info->blocks[i]->next = 0;
  }
}

#define INIT_COUNTER(c) do {		\
    c.count = 0;				\
    c.min_weight = UINT64_MAX;		\
    c.max_weight = 0;			\
    c.sum_weight = 0;			\
  } while(0)

/* initialize a mem_counters structure */
void init_mem_counter(struct mem_counters* counters) {
  counters->total_count = 0;
  counters->total_weight = 0;
  counters->na_miss_count = 0;

  INIT_COUNTER(counters->cache1_hit);
  INIT_COUNTER(counters->cache2_hit);
  INIT_COUNTER(counters->cache3_hit);
  INIT_COUNTER(counters->lfb_hit);
  INIT_COUNTER(counters->local_ram_hit);
  INIT_COUNTER(counters->remote_ram_hit);
  INIT_COUNTER(counters->remote_cache_hit);
  INIT_COUNTER(counters->io_memory_hit);
  INIT_COUNTER(counters->uncached_memory_hit);
  INIT_COUNTER(counters->cache1_miss);
  INIT_COUNTER(counters->cache2_miss);
  INIT_COUNTER(counters->cache3_miss);
  INIT_COUNTER(counters->lfb_miss);
  INIT_COUNTER(counters->local_ram_miss);
  INIT_COUNTER(counters->remote_ram_miss);
  INIT_COUNTER(counters->remote_cache_miss);
  INIT_COUNTER(counters->io_memory_miss);
  INIT_COUNTER(counters->uncached_memory_miss);
}

/* initialize the counters of a mem_info structure */
static void __init_counters(struct memory_info* mem_info) {
  int i, j;
  for(i=0; i<MAX_THREADS; i++) {
    struct block_info*block = mem_info->blocks[i];
    while(block) {
      for(j=0; j<ACCESS_MAX; j++) {
	init_mem_counter(&block->counters[j]);
      }
      block = block->next;
    }
  }
}

void ma_allocate_counters(struct memory_info* mem_info) {
  __allocate_counters(mem_info);
}

void ma_init_counters(struct memory_info* mem_info) {
  __init_counters(mem_info);
}


#define PAGE_SIZE 4096

/* return the block_info corresponding to page_no in a list of blocks */
struct block_info* __ma_search_block(struct block_info* block,
				     int page_no) {

  /* browse the list of block and search for page_no */
  while(block) {
    if(block->block_id == page_no) {
      return block;
    }
    if((! block->next) ||	/* we are on the last block */
       (block->next->block_id > page_no)) { /* the next block is too high  */
      return NULL;
    }
    block = block->next;
  }
  return NULL;
}

/* return the block_info corresponding to page_no in a list of blocks
 * if not found, this function allocates a new block and returns it
 */
struct block_info* __ma_get_block(struct block_info* block,
				  int page_no) {
  /* uncomment this to store all the memory accesses in a single block */
  //  return block;

  /* browse the list of block and search for page_no */
  while(block) {
    if(block->block_id == page_no) {
      return block;
    }
    if((! block->next) ||	/* we are on the last block */
       (block->next->block_id > page_no)) { /* the next block is too high  */
      /* insert a new block after the current block */
      struct block_info *new_block = malloc(sizeof(struct block_info));

      /* initialize the block */
      new_block->block_id = page_no;
      for(int j=0; j<ACCESS_MAX; j++) {
	init_mem_counter(&new_block->counters[j]);
      }

      /* enqueue it after block */
      new_block->next = block->next;
      block->next = new_block;
    }

    block = block->next;
  }
  return NULL;
}
/* return the block that contains ptr in a mem_info */
struct block_info* ma_get_block(struct memory_info* mem_info,
				int thread_rank,
				uintptr_t ptr) {
  assert(ptr <= ((uintptr_t)mem_info->buffer_addr) + mem_info->buffer_size);

  size_t offset = ptr - (uintptr_t)mem_info->buffer_addr;
  int page_no = offset / PAGE_SIZE;
  struct block_info* block = mem_info->blocks[thread_rank];
  return __ma_get_block(block, page_no);
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

/* find the address range of the stack and add a mem_info record */
static void __ma_register_stack_range(uintptr_t stack_base_addr,
				      uintptr_t stack_end_addr) {
  size_t stack_size = stack_end_addr - stack_base_addr;

  debug_printf("Stack address range: %p-%p (stack size: %lu bytes)\n",
	       stack_base_addr, stack_end_addr, stack_size);

  /* create a mem_info record */
  struct memory_info * mem_info = NULL;
#ifdef USE_HASHTABLE
  mem_info = mem_allocator_alloc(mem_info_allocator);
#else
  struct memory_info_list * p_node = mem_allocator_alloc(mem_info_allocator);
  mem_info = &p_node->mem_info;
#endif

  mem_info->mem_type=stack;
  mem_info->alloc_date = 0;
  mem_info->free_date = 0;
  mem_info->initial_buffer_size = stack_size;
  mem_info->buffer_size = stack_size;
  mem_info->buffer_addr = (void*)stack_base_addr;
  mem_info->caller = mem_allocator_alloc(string_allocator);
  snprintf(mem_info->caller, 1024, "[stack]");
  if(! offline_analysis) {
    __allocate_counters(mem_info);
    __init_counters(mem_info);
  }
  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  mem_list = ht_insert(mem_list, (uint64_t) mem_info->buffer_addr, mem_info);
#else
  p_node->next = mem_list;
  p_node->prev = NULL;
  if(p_node->next)
    p_node->next->prev = p_node;
  mem_list = p_node;
#endif
  pthread_mutex_unlock(&mem_list_lock);
}

void ma_register_stack() {
  char cmd[4096];
  char line[4096];

  uintptr_t stack_base_addr= (uintptr_t)0x7fa000000000;
  uintptr_t stack_end_addr= (uintptr_t)0x7fffffffffff;
  __ma_register_stack_range(stack_base_addr, stack_end_addr);
  return;
  
  FILE* f=fopen("/proc/self/maps", "r");
  if(!f) {
    perror("fopen failed");
    abort();
  }
  while(fgets(line, 4096, f) != NULL) {
    /* extract start/end addresses */
    // each line is in the form:
    // <start_addr>-<end_addr> <permission> <offset> <device> <inode> <file>

    void *stack_base_addr = NULL;
    void *stack_end_addr = NULL;
    char permission[10];
    size_t offset=0;
    int device1;
    int device2;
    int inode;
    char file[4096];
      
    int nfields = sscanf(line, "%p-%p %s %x %x:%x %d %s",
		     &stack_base_addr, &stack_end_addr, permission, &offset,
		     &device1, &device2, &inode, file);
    if(nfields == 7 || (inode == 0 && strcmp(file, "[stack]")==0)) {
      if((uintptr_t)stack_base_addr > (uintptr_t)0x7f0000000000) {
	/* let's assume this is a stack region */
	printf("While reading '%s', found %d fields. inode=%d, file='%s'\n", line, nfields, inode, file);

	__ma_register_stack_range((uintptr_t)stack_base_addr, (uintptr_t)stack_end_addr);
      }
    }
  }
  fclose(f);
}  

/* writes given information into a new memory_info struct and adds it to list or hashtable, and returns the inserted element */
struct memory_info* insert_memory_info(enum mem_type mem_type, size_t initial_buffer_size, void* buffer_addr, const char* caller)
{
	struct memory_info* mem_info = NULL;
#ifdef USE_HASHTABLE
	mem_info = mem_allocator_alloc(mem_info_allocator);
#else
	struct memory_info_list * p_node = mem_allocator_alloc(mem_info_allocator);
	mem_info = &p_node->mem_info;
#endif
	mem_info->mem_type = mem_type;
	mem_info->alloc_date = 0;
	mem_info->free_date = 0;
	mem_info->initial_buffer_size = initial_buffer_size;
	mem_info->buffer_size = mem_info->initial_buffer_size;

	mem_info->buffer_addr = buffer_addr;
	mem_info->caller = mem_allocator_alloc(string_allocator);
	snprintf(mem_info->caller, 1024, "%s", caller);
	if(! offline_analysis) {
	  __allocate_counters(mem_info);
	  __init_counters(mem_info);
	}

	pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
	mem_list = ht_insert(mem_list, (uint64_t) mem_info->buffer_addr, mem_info);
#else
	/* todo: insert large buffers at the beginning of the list since
	 * their are more likely to be accessed often (this will speed
	 * up searching at runtime)
	 */
	p_node->next = mem_list;
	p_node->prev = NULL;
	if(p_node->next)
	  p_node->next->prev = p_node;
	mem_list = p_node;
#endif
	pthread_mutex_unlock(&mem_list_lock);
	return mem_info;
}

/* get the list of global/static variables with their address and size */
void ma_get_global_variables() {
  /* make sure forked processes (eg nm, readlink, etc.) won't be analyzed */
  unset_ld_preload();

  debug_printf("Looking for global variables\n");
  /* get the filename of the program being run */
  char link_path[1024];
  sprintf(link_path, "/proc/%d/exe", getpid());
  readlink(link_path, program_file, PROGRAM_FILE_LEN*sizeof(char));

  debug_printf("  The program file is %s\n", program_file);
  /* get the address at which the program is mapped in memory */
  char cmd[4069];
  char line[4096];
  void *base_addr = NULL;
  void *end_addr = NULL;

  FILE *f;
  sprintf(cmd, "file \"%s\" |grep \"shared object\\|pie executable\" > plop", program_file);
  int ret = system(cmd);
  if(WIFEXITED(ret)) {
    /* find address range of the heap */
    int exit_status= WEXITSTATUS(ret);
    if(exit_status == EXIT_SUCCESS) {
      /* process is compiled with -fPIE, thus, the addresses in the ELF are to be relocated */
      sprintf(cmd, "cat /proc/%d/maps |grep \"[heap]\"", getpid());
      f = popen(cmd, "r");
      fgets(line, 4096, f);
      pclose(f);
      sscanf(line, "%p-%p", &base_addr, &end_addr);
      printf("[NumaMMA]  This program was compiled with -fPIE. It is mapped at address %p\n", base_addr);
    } else {
      /* process is not compiled with -fPIE, thus, the addresses in the ELF are the addresses in the binary */
      base_addr= NULL;
      end_addr= NULL;
      printf("[NumaMMA]  This program was not compiled with -fPIE. It is mapped at address %p\n", base_addr);
    }
  }

  /* get the list of global variables in the current binary */
  if(strcmp(program_file, "/usr/bin/bash")==0)
    exit(EXIT_SUCCESS);
  char nm_cmd[1024];
  sprintf(nm_cmd, "nm --defined-only -l -S %s", program_file);
  f = popen(nm_cmd, "r");

  while(!feof(f)) {
    if( ! fgets(line, 4096, f) ) {
      if(errno == EINTR)
	continue;
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
	/* addr is the offset within the binary. The actual address of the variable is located at
	 *  addr+base_addr
	 */
	size_t offset;
	sscanf(addr, "%lx", &offset);
	mem_info = insert_memory_info(global_symbol, size, offset + (uint8_t*)base_addr, symbol);
	printf("Found a global variable: %s (defined at %s). base addr=%p, size=%zu\n",
		     symbol, file, mem_info->buffer_addr, mem_info->buffer_size);
      }
    }
  }
 out:
  pclose(f);
  /* Restore LD_PRELOAD.
   * This is usefull when the program is run with gdb. gdb creates a process than runs bash -e prog arg1
   * Thus, the ld_preload affects bash. bash then calls execvp to execute the program.
   * If we unset ld_preload, the ld_preload will only affect bash (and not the program)
   * Hence, we need to restore ld_preload here.
   */
  reset_ld_preload();
}

/* get the list of lib variables with their address and size */
void ma_get_lib_variables() {
  /* make sure forked processes (eg nm, readlink, etc.) won't be analyzed */
  unset_ld_preload();

  elf_version(EV_CURRENT); // has to be called before elf_begin

  debug_printf("Looking for lib variables\n");
  /* get the address ranges in /proc/pid/maps */
  char line[4096];
  char maps_path[1024];
  FILE *f = NULL;
  sprintf(maps_path, "/proc/%d/maps", getpid());
  f = fopen(maps_path, "r");
  if (f == NULL) {
    fprintf(stderr, "Could not open %s (reading mode)\n", maps_path);
    abort();
  }
  char last_file[4096] = "not a file"; // each file appears several times, we should not deal with them more than once
  while (!feof(f)) {
    fgets(line, sizeof(line), f);
    // only selecting lines containing lib, could be another criteria, and could filter libnumap, libnumamma, etc.
    if (strstr(line, "lib") != NULL) {
      // get rid of trailing new lines
      strtok(line, "\n");
      /* each line is in the form:
       * addr_begin-addr_end permissions offset device inode file
       */
      void *addr_begin = NULL;
      void *addr_end = NULL;
      char *perm = null_str;
      char *offset = null_str;
      char *device = null_str;
      char *inode = 0;
      char *file = null_str;
      sscanf(strtok(line," "), "%p-%p", &addr_begin, &addr_end);
      perm = strtok(NULL, " ");
      offset = strtok(NULL, " ");
      device = strtok(NULL, " ");
      inode = strtok(NULL, " ");
      file = strtok(NULL, " ");
      assert(file);
      if (strcmp(file, last_file) == 0) continue; // pass if the file has been parsed just before
      strncpy(last_file, file, sizeof(last_file));
      Elf *elf = NULL;
      GElf_Ehdr header;
      int fd = open(file, O_RDONLY);
      if (fd == -1) {
        fprintf(stderr, "open %s failed : (%d) %s\n", file, errno, strerror(errno));
        continue;
      }
      elf = elf_begin(fd, ELF_C_READ, NULL); // obtain ELF descriptor
      if (elf == NULL) {
        fprintf(stderr, "elf_begin failed on %s : (%d) %s\n", file, errno, strerror(errno));
	continue;
      }
      if (gelf_getehdr(elf, &header) == NULL)
      {
        fprintf(stderr, "elf_getehdr failed on %s : (%d) %s\n", file, errno, strerror(errno));
	continue;
      }
      Elf_Scn *scn = NULL; // section
      GElf_Shdr shdr; // symbol header
      Elf_Data *data; // section data
      while ((scn=elf_nextscn(elf, scn)) != NULL) // iterate through sections
      {
        gelf_getshdr(scn, &shdr);
        data = elf_getdata(scn, NULL);
        if (shdr.sh_entsize == 0) continue; // can't explore this one
        int count = (shdr.sh_size / shdr.sh_entsize);
        for (int index = 0; index < count ; index++)
	{
          GElf_Sym sym;
	  if (gelf_getsym(data, index, &sym) == NULL) continue; // pass if we can't retrieve the data at current index
	  // we want objects with a non zero size, and that are global objects
	  // trying to retrieve global functions too seems to break memory analysis (parsing all blocks never ends)
	  if (sym.st_size != 0  && GELF_ST_BIND(sym.st_info) == STB_GLOBAL &&
			  (GELF_ST_TYPE(sym.st_info) == STT_OBJECT
			   /*|| GELF_ST_TYPE(sym.st_info) == STT_FUNC*/)) {
            char *symbol = elf_strptr(elf, shdr.sh_link, sym.st_name);
	    void* addr = (void*) ( (long long) addr_begin + sym.st_value );
	    size_t size = sym.st_size;
            struct memory_info *mem_info = insert_memory_info(lib, size, addr, symbol);
	    printf("Found a lib variable (defined at %s). addr=%p, size=%zu, symbol=%s\n",
			    file, mem_info->buffer_addr, mem_info->buffer_size, mem_info->caller);
	  }
	  // this dumps all symbols found that did not match above requirements in stderr when using verbose
	  // since there are lots of those symbols, it would be better to dump them in a file I guess, so for now I comment this
	  /*
	  else if (_verbose) {
            char *symbol = elf_strptr(elf, shdr.sh_link, sym.st_name);
	    void* addr = (void*) ( (long long) addr_begin + sym.st_value );
	    size_t size = sym.st_size;
            fprintf(stderr, "%s\n\taddr : %p\n\tsize : %zu\n", symbol, addr, size);
	    fprintf(stderr, "\ttype : %d (", GELF_ST_TYPE(sym.st_info));
	    switch(GELF_ST_TYPE(sym.st_info)) {
		    case STT_NOTYPE:
			    fprintf(stderr, "STT_NOTYPE");
			    break;
		    case STT_OBJECT:
			    fprintf(stderr, "STT_OBJECT");
			    break;
		    case STT_FUNC:
			    fprintf(stderr, "STT_FUNC");
			    break;
		    case STT_SECTION:
			    fprintf(stderr, "STT_SECTION");
			    break;
		    case STT_FILE:
			    fprintf(stderr, "STT_FILE");
			    break;
		    case STT_COMMON:
			    fprintf(stderr, "STT_COMMON");
			    break;
		    case STT_TLS:
			    fprintf(stderr, "STT_TLS");
			    break;
		    case STT_NUM:
			    fprintf(stderr, "STT_NUM");
			    break;
		    case STT_LOOS:
		    //case STT_GNU_IFUNC: // both defined to 10
			    fprintf(stderr, "STT_LOOS or STT_GNU_IFUNC");
			    break;
		    case STT_HIOS:
			    fprintf(stderr, "STT_HIOS");
			    break;
		    case STT_LOPROC:
			    fprintf(stderr, "STT_LOPROC");
			    break;
		    case STT_HIPROC:
			    fprintf(stderr, "STT_HIPROC");
			    break;
		    default:
			    fprintf(stderr, "undefined");
			    break;
	    }
	    fprintf(stderr, ")\n");
            fprintf(stderr, "\tbind : %d (", GELF_ST_BIND(sym.st_info));
	    switch(GELF_ST_BIND(sym.st_info)) {
		    case STB_LOCAL:
			    fprintf(stderr, "STB_LOCAL");
			    break;
		    case STB_GLOBAL:
			    fprintf(stderr, "STB_GLOBAL");
			    break;
		    case STB_WEAK:
			    fprintf(stderr, "STB_WEAK");
			    break;
		    case STB_NUM:
			    fprintf(stderr, "STB_NUM");
			    break;
		    case STB_LOOS:
		    //case STB_GNU_UNIQUE: // both defined to 10
			    fprintf(stderr, "STB_LOOS or STB_GNU_UNIQUE");
			    break;
		    case STB_HIOS:
			    fprintf(stderr, "STB_HIOS");
			    break;
		    case STB_LOPROC:
			    fprintf(stderr, "STB_LOPROC");
			    break;
		    case STB_HIPROC:
			    fprintf(stderr, "STB_HIPROC");
			    break;
		    default:
			    fprintf(stderr, "undefined");
			    break;
	    }
	    fprintf(stderr, ")\n");
	  }
	*/
	}
      }
      elf_end(elf);
      close(fd);
    }
  }
  pclose(f);
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

  start_tick(record_malloc);

  mem_sampling_collect_samples();

  start_tick(fast_alloc);

  struct memory_info * mem_info = NULL;
#ifdef USE_HASHTABLE
  mem_info = mem_allocator_alloc(mem_info_allocator);
#else
  struct memory_info_list * p_node = mem_allocator_alloc(mem_info_allocator);
  mem_info = &p_node->mem_info;
#endif
  stop_tick(fast_alloc);
  start_tick(init_block);

  mem_info->mem_type = dynamic_allocation;
  mem_info->alloc_date = new_date();
  mem_info->free_date = 0;
  mem_info->initial_buffer_size = info->size;
  mem_info->buffer_size = info->size;
  mem_info->buffer_addr = info->u_ptr;
  mem_info->blocks = NULL;
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
  if(!offline_analysis) {
    /* todo: when implementing offline analysis, make sure counters are initialized */
    __allocate_counters(mem_info);
    __init_counters(mem_info);
  }

  debug_printf("in %s: [tid=%lx][rdtsc=%lu] malloc(%lu bytes) -> u_ptr=%p\n",
	       __FUNCTION__,
	       syscall(SYS_gettid),
	       mem_info->alloc_date,
	       mem_info->initial_buffer_size,
	       mem_info->buffer_addr);

  stop_tick(init_block);

  start_tick(insert_in_tree);
  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  mem_list = ht_insert(mem_list, (uint64_t) mem_info->buffer_addr, mem_info);
#else
  p_node->next = mem_list;
  p_node->prev = NULL;
  if(p_node->next)
    p_node->next->prev = NULL;
  mem_list = p_node;
#endif
  pthread_mutex_unlock(&mem_list_lock);

  stop_tick(insert_in_tree);

  start_tick(sampling_resume);
  mem_sampling_resume();
  stop_tick(sampling_resume);

  stop_tick(record_malloc);

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

  start_tick(sampling_resume);
  mem_sampling_resume();
  stop_tick(sampling_resume);

  UNPROTECT_RECORD;
}

/*
 * remove mem_info from the list of active buffers and add it to the list of inactive buffers
 */
void set_buffer_free(struct mem_block_info* p_block) {
  pthread_mutex_lock(&mem_list_lock);
#ifdef USE_HASHTABLE
  /* nothing to do here: we keep all buffers in the same hashmap. We'll use the timestamps to differenciate them  */
  struct memory_info* mem_info = p_block->record_info;
#else
  struct memory_info_list * p_node = mem_list;
  if(p_block->record_info == &p_node->mem_info) {
    /* the first record is the one we're looking for */
    mem_list = p_node->next;
    if(p_node->next)
      p_node->next->prev = p_node->prev;
    p_node->next = past_mem_list;
    p_node->prev = NULL;
    if(p_node->next)
      p_node->next->prev = p_node;
    past_mem_list = p_node;
    goto out;
  }

  /* browse the list of malloc'd buffers */
  while(p_node->next) {
    if(&p_node->next->mem_info == p_block->record_info) {
      struct memory_info_list *to_move = p_node->next;
      /* remove to_move from the list of malloc'd buffers */
      p_node->next = to_move->next;
      if(p_node->next)
	p_node->next->prev = p_node;
      /* add it to the list of freed buffers */
      to_move->next = past_mem_list;
      to_move->prev = NULL;
      if(to_move->next)
	to_move->next->prev = to_move;
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
  start_tick(record_free);
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


  start_tick(sampling_resume);
  mem_sampling_resume();
  stop_tick(sampling_resume);
  stop_tick(record_free);
  UNPROTECT_RECORD;
}

struct call_site {
  char* caller;
  void* caller_rip;
  size_t buffer_size;
  unsigned nb_mallocs;
  struct memory_info mem_info;
  struct block_info cumulated_counters;
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

  site->mem_info.mem_type = mem_info->mem_type;
  site->mem_info.alloc_date = 0;
  site->mem_info.free_date = 0;
  site->mem_info.initial_buffer_size = mem_info->initial_buffer_size;
  site->mem_info.buffer_size = mem_info->buffer_size;
  site->mem_info.buffer_addr = mem_info->buffer_addr;
  site->mem_info.caller = site->caller;
  site->mem_info.caller_rip = site->caller_rip;
  ma_allocate_counters(&site->mem_info);
  ma_init_counters(&site->mem_info);

  site->cumulated_counters.block_id = 0;
  site->cumulated_counters.next = NULL;
  int i, j;
  for(j = 0; j<ACCESS_MAX; j++) {
    memset(&site->cumulated_counters.counters[j], 0, sizeof(struct mem_counters));
  }
  __init_counters(&site->mem_info);

  site->next = call_sites;
  call_sites = site;
  return site;
}

void update_call_sites(struct memory_info* mem_info) {
  struct call_site* site = find_call_site(mem_info);
  if(!site) {
    site = new_call_site(mem_info);
  } else {
    mem_info->caller = site->caller;
  }

  site->nb_mallocs++;
  int i, j;
  for(i = 0; i<MAX_THREADS; i++) {
    struct block_info *block = mem_info->blocks[i];
    while(block) {
      struct block_info* mem_block = __ma_get_block(site->mem_info.blocks[i], block->block_id);
      struct block_info* site_block = __ma_get_block(&site->cumulated_counters, 0);

      for(j = 0; j<ACCESS_MAX; j++) {

#define ACC_COUNTER(to, from, _c) do {			\
	  to._c.count += from._c.count;			\
	  to._c.sum_weight += from._c.sum_weight;	\
	  if(to._c.min_weight > from._c.min_weight)	\
	    to._c.min_weight = from._c.min_weight;	\
	  if(to._c.max_weight > from._c.max_weight)	\
	    to._c.max_weight = from._c.max_weight;	\
	} while(0)

#define ACC_COUNTERS(to, from) do {			\
	  to.total_count += from.total_count;		\
	  to.total_weight += from.total_weight;		\
	  to.na_miss_count += from.na_miss_count;	\
	  ACC_COUNTER(to, from, cache1_hit);		\
	  ACC_COUNTER(to, from, cache2_hit);		\
	  ACC_COUNTER(to, from, cache3_hit);		\
	  ACC_COUNTER(to, from, lfb_hit);		\
	  ACC_COUNTER(to, from, local_ram_hit);		\
	  ACC_COUNTER(to, from, remote_ram_hit);	\
	  ACC_COUNTER(to, from, remote_cache_hit);	\
	  ACC_COUNTER(to, from, io_memory_hit);		\
	  ACC_COUNTER(to, from, uncached_memory_hit);	\
	  ACC_COUNTER(to, from, cache1_miss);		\
	  ACC_COUNTER(to, from, cache2_miss);		\
	  ACC_COUNTER(to, from, cache3_miss);		\
	  ACC_COUNTER(to, from, lfb_miss);		\
	  ACC_COUNTER(to, from, local_ram_miss);	\
	  ACC_COUNTER(to, from, remote_ram_miss);	\
	  ACC_COUNTER(to, from, remote_cache_miss);	\
	  ACC_COUNTER(to, from, io_memory_miss);	\
	  ACC_COUNTER(to, from, uncached_memory_miss);	\
	}while(0)

	ACC_COUNTERS(mem_block->counters[j], block->counters[j]);
	ACC_COUNTERS(site_block->counters[j], block->counters[j]);
      }
      block = block->next;
    }
  }
}

/* remove site from the list of callsites */
static void __remove_site(struct call_site*site) {
  struct call_site*cur_site = call_sites;
  if(cur_site == site) {
    /* remove the first site */
    call_sites = cur_site->next;
    return;
  }

  while(cur_site->next) {
    if(cur_site->next == site) {
      /* remove cur_site->next */
      cur_site->next = site->next;
      return;
    }
    cur_site = cur_site->next;
  }
}

/* sort sites depending on their total weight */
static void __sort_sites() {
  struct call_site* head = NULL;
  printf("Sorting call sites\n");

  while(call_sites) {
    struct call_site* cur_site = call_sites;
    struct call_site*min_weight_site  = cur_site;
    /* todo: for now, the sites are sorted according to the number of
     * access to the first block.
     * This should be changed so that they
     * are sorted based on the total number of access (to any block)
     */

    int min_weight = cur_site->cumulated_counters.counters[ACCESS_READ].total_weight;
    while (cur_site) {
      if(cur_site->cumulated_counters.counters[ACCESS_READ].total_weight < min_weight) {
	min_weight = cur_site->cumulated_counters.counters[ACCESS_READ].total_weight;
	min_weight_site = cur_site;
      }
      cur_site = cur_site->next;
    }
    __remove_site(min_weight_site);
    min_weight_site->next = head;
    head = min_weight_site;
  }
  call_sites = head;
}

static void __plot_counters(struct memory_info *mem_info,
			    int nb_threads,
			    const char*filename) {
  FILE* file = fopen(filename, "w");
  assert(file);

  int nb_pages = (mem_info->buffer_size / PAGE_SIZE)+1;
  for(int i=0; i<nb_pages; i++) {
    /* the block was accessed by at least one thread */
      size_t start_offset = i*PAGE_SIZE;
      size_t stop_offset = (i+1)*PAGE_SIZE;
      for(int th=0; th< nb_threads; th++) {
	struct block_info* block =  __ma_search_block(mem_info->blocks[th], i);
	int total_access = 0;
	if(block) {
	  total_access += block->counters[ACCESS_READ].total_count;
	  total_access += block->counters[ACCESS_WRITE].total_count;
	}
	fprintf(file, "\t%d", total_access);
      }
      fprintf(file, "\n");

  }
  fclose(file);
}

void print_buffer_list() {
  char filename[4096];
  create_log_filename("buffers.log", filename, 4096);
  FILE* f=fopen(filename, "w");
  if(!f) {
    perror("failed to open buffer.log for writing");
    return;
  }
  __ma_print_buffers_generic(f, mem_list);
  fclose(f);
}

void print_call_site_summary() {
  printf("Summary of the call sites:\n");
  printf("--------------------------\n");
  __sort_sites();
  struct call_site* site = call_sites;
  int nb_threads = next_thread_rank;
  int site_no=0;

  char summary_filename[1024];
  create_log_filename("summary.log", summary_filename, 1024);
  FILE* summary_file=fopen(summary_filename, "w");
  assert(summary_file != NULL);

  char callsite_filename[1024];
  create_log_filename("call_sites.log", callsite_filename, 1024);
  FILE* callsite_file=fopen(callsite_filename, "w");
  assert(callsite_file!=NULL);
  while(site) {
    if(site->cumulated_counters.counters[ACCESS_READ].total_count ||
       site->cumulated_counters.counters[ACCESS_WRITE].total_count) {

      double avg_read_weight = 0;
      if(site->cumulated_counters.counters[ACCESS_READ].total_count) {
	avg_read_weight = (double)site->cumulated_counters.counters[ACCESS_READ].total_weight / site->cumulated_counters.counters[ACCESS_READ].total_count;
      }

      fprintf(callsite_file, "%d\t%s (size=%zu) - %d buffers. %d read access (total weight: %u, avg weight: %f). %d wr_access\n",
	      site_no, site->caller, site->buffer_size, site->nb_mallocs,
	      site->cumulated_counters.counters[ACCESS_READ].total_count,
	      site->cumulated_counters.counters[ACCESS_READ].total_weight,
	      avg_read_weight,
	      site->cumulated_counters.counters[ACCESS_WRITE].total_count);
      printf("%d\t%s (size=%zu) - %d buffers. %d read access (total weight: %u, avg weight: %f). %d wr_access\n",
	     site_no, site->caller, site->buffer_size, site->nb_mallocs,
	     site->cumulated_counters.counters[ACCESS_READ].total_count,
	     site->cumulated_counters.counters[ACCESS_READ].total_weight,
	     avg_read_weight,
	     site->cumulated_counters.counters[ACCESS_WRITE].total_count);

      fprintf(summary_file, "%d\t%s\t%zu\n", site_no, site->caller, site->buffer_size);

      if(site->mem_info.mem_type != stack) {
	char filename[1024];
	sprintf(filename, "%s/counters_%d.dat", get_log_dir(), site_no);
	site_no++;
	__plot_counters(&site->mem_info, nb_threads, filename);
      }
#if 0
#define PRINT_COUNTERS(access_type, counter) do {			\
	if(site->cumulated_counters.counters[access_type].counter) {	\
	  printf("\t%s:\t", #counter);					\
	  for(int i=0; i< nb_threads; i++) {				\
	    printf("%d\t", site->mem_info.blocks[i]->counters[access_type].counter); \
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
#endif
    }
    site = site->next;
  }
  fclose(summary_file);
  fclose(callsite_file);
  //  print_buffer_list();
}

/* browse the list of malloc'd buffers that were not freed */
void warn_non_freed_buffers() {

  pthread_mutex_lock(&mem_list_lock);

  struct memory_info* mem_info = NULL;
#ifdef USE_HASHTABLE
  struct ht_node*p_node = NULL;
  FOREACH_HASH(mem_list, p_node) {
    struct ht_entry*e = p_node->entries;
    while(e) {
      mem_info = e->value;
      if(! mem_info->free_date) {
#if WARN_NON_FREED
	printf("Warning: buffer %p (size=%lu bytes) was not freed\n",
	       mem_info->buffer_addr, mem_info->buffer_size);
#endif
	mem_info->free_date = new_date();
      }

      e=e->next;
    }
  }

#else
  while(mem_list) {
    mem_info = &mem_list->mem_info;

#if WARN_NON_FREED
    printf("Warning: buffer %p (size=%lu bytes) was not freed\n",
	   mem_info->buffer_addr, mem_info->buffer_size);
#endif

    mem_info->free_date = new_date();

    /* remove the record from the list of malloc'd buffers */
    struct memory_info_list* p_node = mem_list;
    mem_list = p_node->next;
    if(mem_list)
      mem_list->prev = NULL;
    /* add to the list of freed buffers */
    p_node->next = past_mem_list;
    if(p_node->next)
      p_node->next->prev = p_node;
    past_mem_list = p_node;
  }
#endif	/* USE_HASHTABLE */

  pthread_mutex_unlock(&mem_list_lock);
}


void ma_finalize() {

  ma_thread_finalize();
  PROTECT_RECORD;
  warn_non_freed_buffers();
  mem_sampling_finalize();



  printf("---------------------------------\n");
  printf("         MEM ANALYZER\n");
  printf("---------------------------------\n");

  pthread_mutex_lock(&mem_list_lock);

  mem_info_node_t p_node = NULL;
  struct memory_info* mem_info = NULL;

  /* browse the list of memory buffers  */
#ifdef USE_HASHTABLE
  FOREACH_HASH(mem_list, p_node) {
    struct ht_entry*e = p_node->entries;
    while(e) {
      mem_info = e->value;
#else
    for(p_node = past_mem_list;
	p_node;
	p_node = p_node->next) {
      mem_info = &p_node->mem_info;
#endif

      if(!mem_info->blocks) {
	/* not a single memory access on this buffer was detected */
	ma_allocate_counters(mem_info);
	ma_init_counters(mem_info);
      }
      update_call_sites(mem_info);

      uint64_t duration = mem_info->free_date?
	mem_info->free_date-mem_info->alloc_date:
	0;

      int nb_threads = next_thread_rank;
      uint64_t total_read_count = 0;
      uint64_t total_write_count = 0;
      size_t nb_blocks_with_samples = 0;
      for(int i=0; i<nb_threads; i++) {
	struct block_info* block = mem_info->blocks[i];
	while (block) {
	  total_read_count += block->counters[ACCESS_READ].total_count;
	  total_write_count += block->counters[ACCESS_WRITE].total_count;
	  if (block->counters[ACCESS_READ].total_count != 0 ||
	      block->counters[ACCESS_WRITE].total_count != 0) {
	    nb_blocks_with_samples++;
	  }
	  block = block->next;
	}
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

	debug_printf("buffer %p (%lu bytes, %zu blocks with samples), duration = %lu ticks, %"PRIu64" writes, %"PRIu64" reads, allocated : %s, read operation every %lf ticks\n",
		     mem_info->buffer_addr,
		     mem_info->initial_buffer_size,
		     nb_blocks_with_samples,
		     duration,
		     total_write_count,
		     total_read_count,
		     mem_info->caller,
		     r_access_frequency);
      }
#ifdef USE_HASHTABLE
      e = e->next;
    }
#endif
    }

    print_call_site_summary();

    mem_sampling_statistics();
    if(_dump) {
      fclose(dump_file);
    }
    pthread_mutex_unlock(&mem_list_lock);
    UNPROTECT_RECORD;
    //    ma_print_current_buffers();
  }

