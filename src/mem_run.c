/* -*- c-file-style: "GNU" -*- */
#define _GNU_SOURCE

/* intercept a set of memory/pthread related functions
 * and modify their behavior
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <numaif.h>
#include <numa.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "numamma.h"
#include "mem_intercept.h"
#include "mem_tools.h"

#define INTERCEPT_MALLOC 1

//#define CHECK_PLACEMENT 1


// not used, but me need to define the symbol
struct numamma_settings settings;


int _dump = 0;
FILE* dump_file = NULL; // useless
int _verbose = 0;
__thread int is_recurse_unsafe = 0;

/* set to 1 if thread binding is activated */
int bind_threads=0;

enum mbind_policy{
  POLICY_NONE,
  POLICY_INTERLEAVED,
  POLICY_BLOCK,
  POLICY_CUSTOM,
  POLICY_MAX
};
enum mbind_policy _mbind_policy;

/* array describing the binding of each thread */
int thread_bindings[MAX_THREADS];
/* number of valid entries in the array */
int nb_thread_max=0;


int page_size=4096;		/* todo: detect this using sysconf */
int nb_nodes=-1;


struct mbind_directive {
  char block_identifier[4096]; // name of the variable to move
  size_t buffer_len;
  size_t nb_blocks;
  void* base_addr;
  enum {type_global, type_malloc} buffer_type;
  struct block_bind *blocks;
  struct mbind_directive *next;
};
struct mbind_directive *directives = NULL;;
  
struct block_bind {
  int start_page;
  int end_page;
  int numa_node;
};

/* set to 1 when all the hooks are set.
 * This is useful in order to avoid recursive calls
 */
static int __memory_initialized = 0;

void* (*libcalloc)(size_t nmemb, size_t size) = NULL;
void* (*libmalloc)(size_t size) = NULL;
void (*libfree)(void *ptr) = NULL;
void* (*librealloc)(void *ptr, size_t size) = NULL;
int  (*libpthread_create) (pthread_t * thread, const pthread_attr_t * attr,
			   void *(*start_routine) (void *), void *arg) = NULL;
void (*libpthread_exit) (void *thread_return) = NULL;

static void bind_buffer(void* buffer, size_t len, char* buffer_id);
static void bind_malloced_buffer(void* buffer, size_t len, char* buffer_id);

/* Custom malloc function. It is used when libmalloc=NULL (e.g. during startup)
 * This function is not thread-safe and is very likely to be bogus, so use with
 * caution
 */
static void* hand_made_malloc(size_t size) {
  /* allocate a 1MB buffer */
#define POOL_SIZE (1024 * 1024 * 10)
  static char mem[POOL_SIZE] = {'\0'};

  /* since this function is only used before we found libmalloc, there's no
   * fancy memory management mechanism (block reuse, etc.)
   */
  static char* next_slot = &mem[0];
  static int total_alloc = 0;

  if (libmalloc)
    /* let's use the real malloc */
    return malloc(size);

  debug_printf("%s(size=%lu)\n", __FUNCTION__, size);
  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, next_slot, size, 1);
  p_block->mem_type = MEM_TYPE_HAND_MADE_MALLOC;

  /* if you want to make this function thread-safe, these instructions should be protected
   * by a mutex:
   */
  p_block->mem_type = MEM_TYPE_HAND_MADE_MALLOC;
  total_alloc += size;
  next_slot = next_slot + p_block->total_size;
  debug_printf("%s returns: --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);
  return p_block->u_ptr;
}

static int nb_malloc=0;
static int nb_free=0;
static int nb_realloc=0;
static int nb_calloc=0;

#if INTERCEPT_MALLOC

void* malloc(size_t size) {
  nb_malloc++;
  static int total_alloced=0;
  /* if memory_init hasn't been called yet, we need to get libc's malloc
   * address
   */
  if (!libmalloc) {
    if( !IS_RECURSE_SAFE) {
      /* protection flag says that malloc is already trying to retrieve the
       * address of malloc.
       * If we call dlsym now, there will be an infinite recursion, so let's
       * allocate memory 'by hand'
       */
      return hand_made_malloc(size);
    }

    /* set the protection flag and retrieve the address of malloc.
     * If dlsym calls malloc, memory will be allocated 'by hand'
     */
    PROTECT_FROM_RECURSION;
    {
      libmalloc = dlsym(RTLD_NEXT, "malloc");
      char* error;
      if ((error = dlerror()) != NULL) {
	fputs(error, stderr);
	exit(1);
      }
    }
    /* it is now safe to call libmalloc */
    UNPROTECT_FROM_RECURSION;
  }

  /* allocate a buffer */
  debug_printf("%s(size=%lu) \n", __FUNCTION__, size);
  void* pptr = libmalloc(size + HEADER_SIZE + TAIL_SIZE);
  total_alloced+=size + HEADER_SIZE + TAIL_SIZE;

  if(!pptr){
    return NULL;
  }
  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, pptr, size, 1);

  if(__memory_initialized && IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    p_block->mem_type = MEM_TYPE_MALLOC;
    /* TODO: use the callsite to generate a buffer_id */
    bind_malloced_buffer(p_block->u_ptr, size, NULL);
    UNPROTECT_FROM_RECURSION;
    //    return p_block->u_ptr;
  } else {
    /* we are already processing a malloc/free function, so don't try to record information,
     * just call the function
     */
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }
  debug_printf("%s returns: --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);

  return p_block->u_ptr;
}

void* realloc(void *ptr, size_t size) {
  nb_realloc++;
  /* if ptr is NULL, realloc behaves like malloc */
  if (!ptr)
    return malloc(size);

  /* if size=0 and ptr isn't NULL, realloc behaves like free */
  if (!size && ptr) {
    free(ptr);
    return NULL;
  }

  //  FUNCTION_ENTRY;
  if (!librealloc) {
    librealloc = dlsym(RTLD_NEXT, "realloc");
    char* error;
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      exit(1);
    }
  }

  debug_printf("%s(ptr=%p, size=%lu)\n", __FUNCTION__, ptr, size);
  if (!CANARY_OK(ptr)) {
    /* we didn't malloc'ed this buffer */
    fprintf(stderr,"%s(%p). I can't find this pointer !\n", __FUNCTION__, ptr);
    abort();
    void* retval = librealloc(ptr, size);
    debug_printf("%s returns --> %p\n", retval, __FUNCTION__);
    return retval;
  }

  struct mem_block_info *p_block;
  USER_PTR_TO_BLOCK_INFO(ptr, p_block);
  size_t old_size = p_block->size;
  size_t header_size = p_block->total_size - p_block->size;

  if (p_block->mem_type != MEM_TYPE_MALLOC) {
    fprintf(stderr, "Warning: realloc a ptr that was allocated by hand_made_malloc\n");
  }
  void *old_addr= p_block->u_ptr;
  void *pptr = librealloc(p_block->p_ptr, size + header_size);
  INIT_MEM_INFO(p_block, pptr, size, 1);

  if(__memory_initialized && IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    /* retrieve the malloc information from the pointer */
    if (!pptr) {
      /* realloc failed */
      UNPROTECT_FROM_RECURSION;
      debug_printf("%s returns --> %p\n", __FUNCTION__, NULL);
      return NULL;
    }

    p_block->mem_type = MEM_TYPE_MALLOC;
    UNPROTECT_FROM_RECURSION;
  } else {
    /* it is not safe to record information */
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }

  debug_printf("%s returns --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);
  return p_block->u_ptr;
}

void* calloc(size_t nmemb, size_t size) {
  nb_calloc++;
  if (!libcalloc) {
    void* ret = hand_made_malloc(nmemb * size);
    if (ret) {
      memset(ret, 0, nmemb * size);
    }
    return ret;
  }

  debug_printf("calloc(nmemb=%zu, size=%zu)\n", nmemb, size);

  /* compute the number of blocks for header */
  int nb_memb_header = (HEADER_SIZE  + TAIL_SIZE)/ size;
  if (size * nb_memb_header < HEADER_SIZE + TAIL_SIZE)
    nb_memb_header++;

    /* allocate buffer + header */
  void* p_ptr = libcalloc(nmemb + nb_memb_header, size);

  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, p_ptr, nmemb, size);


  if(__memory_initialized && IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    p_block->mem_type = MEM_TYPE_MALLOC;
    /* todo: call mbind ? */
    bind_malloced_buffer(p_block->u_ptr, size*nmemb, NULL);
    UNPROTECT_FROM_RECURSION;
  } else {
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }
  debug_printf("%s returns --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);
  return p_block->u_ptr;
}

void free(void* ptr) {
  nb_free++;
  if (!libfree) {
    libfree = dlsym(RTLD_NEXT, "free");
    char* error;
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      exit(1);
    }
  }
  if (!ptr) {
    libfree(ptr);
    return;
  }

  debug_printf("%s(%p)\n", __FUNCTION__, ptr);
  /* first, check wether we malloc'ed the buffer */
  if (!CANARY_OK(ptr)) {
    /* we didn't malloc this buffer */
    fprintf(stderr, "%s(%p). I don't know this malloc !\n", __FUNCTION__, ptr);
    abort();
    libfree(ptr);
    return;
  }

  struct mem_block_info *p_block;
  USER_PTR_TO_BLOCK_INFO(ptr, p_block);

  void* start_ptr = p_block->p_ptr;
  ERASE_CANARY(ptr);
  //  memset(start_ptr, 0x00, p_block->total_size);
  libfree(start_ptr);
}
#endif	/* INTERCEPT_MALLOC */

/* Internal structure used for transmitting the function and argument
 * during pthread_create.
 */
struct __pthread_create_info_t {
  void *(*func)(void *);
  void *arg;
  int thread_rank;
};

enum thread_status_t {
  thread_status_none,
  thread_status_created,
  thread_status_finalized
};

struct thread_info {
  pthread_t tid;
  enum thread_status_t status;
};
struct thread_info thread_array[MAX_THREADS];
int nb_threads = 0;

static int __get_thread_rank(pthread_t thread_id) {
  int i;
  for(i=0; i< nb_threads; i++) {
    if(thread_array[i].tid == thread_id)
      return i;
  }
  return -1;
}

static void __thread_cleanup_function(void* arg);
/* Invoked by pthread_create on the new thread */
static void *
__pthread_new_thread(void *arg) {
  PROTECT_FROM_RECURSION;
  void* res = NULL;
  struct __pthread_create_info_t *p_arg = (struct __pthread_create_info_t*) arg;
  void *(*f)(void *) = p_arg->func;
  void *__arg = p_arg->arg;
  int thread_rank = p_arg->thread_rank;
  free(p_arg);

  UNPROTECT_FROM_RECURSION;
  int oldtype;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

  pthread_cleanup_push(__thread_cleanup_function,
		       &thread_array[thread_rank]);

  FUNCTION_ENTRY;
  if(_verbose) {
    pid_t tid = syscall(__NR_gettid);
    printf("I'm thread %d (tid=%d) bound on cpu %d\n", thread_rank, tid, thread_bindings[thread_rank]);
  }

  res = (*f)(__arg);

  pthread_cleanup_pop(0);
  if(_verbose)
    fprintf(stderr, "End of thread %lu\n", thread_array[thread_rank].tid);
  __thread_cleanup_function(&thread_array[thread_rank]);
  return res;
}


static void __thread_cleanup_function(void* arg) {
  struct thread_info* me = arg;
  PROTECT_FROM_RECURSION;
  me->status = thread_status_finalized;
  UNPROTECT_FROM_RECURSION;
}

int
pthread_create (pthread_t *__restrict thread,
		const pthread_attr_t *__restrict attr,
		void *(*start_routine) (void *),
		void *__restrict arg) {
  FUNCTION_ENTRY;
  PROTECT_FROM_RECURSION;
  int thread_rank = __sync_fetch_and_add( &nb_threads, 1 );
  thread_array[thread_rank].status = thread_status_created;
  struct __pthread_create_info_t * __args =
    (struct __pthread_create_info_t*) malloc(sizeof(struct __pthread_create_info_t));
  __args->func = start_routine;
  __args->arg = arg;
  __args->thread_rank= thread_rank;

  if (!libpthread_create) {
    libpthread_create = dlsym(RTLD_NEXT, "pthread_create");
  }

  pthread_attr_t local_attr;
  if(attr) {
    memcpy(&local_attr, attr, sizeof(local_attr));
  } else {
    pthread_attr_init(&local_attr);
  }
  if(bind_threads && thread_rank < nb_thread_max) {
    if(thread_bindings[thread_rank] >= 0) {
      cpu_set_t cpuset;
      CPU_ZERO(&cpuset);
      CPU_SET(thread_bindings[thread_rank], &cpuset);
#if 0
      if(_verbose)
	printf("[Mem_run] Binding %d to %d\n", thread_rank, thread_bindings[thread_rank]);
#endif
      int ret = pthread_attr_setaffinity_np(&local_attr,
					    sizeof(cpuset),
					    &cpuset);
      if(ret != 0){
	perror("pthread_attr_setaffinity_np failed");
	abort();
      }
    }
  }
  UNPROTECT_FROM_RECURSION;

  /* We do not call directly start_routine since we want to initialize stuff at the thread startup.
   * Instead, let's invoke __pthread_new_thread that initialize the thread-specific things and call
   * start_routine.
   */
  int retval = libpthread_create(&thread_array[thread_rank].tid, &local_attr,
				 __pthread_new_thread, __args);
  memcpy(thread, &thread_array[thread_rank].tid, sizeof(pthread_t));
  return retval;
}

void pthread_exit(void *thread_return) {
  FUNCTION_ENTRY;

  libpthread_exit(thread_return);
  __builtin_unreachable();
}

/* bind the current thread on a cpu */
static void bind_current_thread(int cpu) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);

  pthread_t current_thread = pthread_self();
  pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
}

static void get_thread_binding() {
  char* str=getenv("NUMAMMA_THREAD_BIND");
  if(str) {
    printf("[Mem_run] Thread binding activated: %s\n", str);

    if(getenv("GOMP_CPU_AFFINITY")) {
      fprintf(stderr, "Error: NUMAMMA_THREAD_BIND conflicts with GOMP_CPU_AFFINITY\n");
      fprintf(stderr, "  Please unset GOMP_CPU_AFFINITY\n");
      abort();
    }

    for(int i = 0; i<MAX_THREADS; i++) {
      thread_bindings[i] = -1;
    }
    char bindings[10*MAX_THREADS];
    strncpy(bindings, str, 10*MAX_THREADS);
    char* token = strtok(bindings, ",");
    while(token) {
      thread_bindings[nb_thread_max] = atoi(token);
      nb_thread_max++;
      token = strtok(NULL, ",");
    }

    bind_threads=1;
    if(_verbose) {
      for(int i=0; i<nb_thread_max; i++) {
	printf("[Mem_run] Thread %d is bound to %d\n", i, thread_bindings[i]);
      }
    }

    int thread_rank = nb_threads++;
    thread_array[thread_rank].status = thread_status_created;

#if 0
    if(_verbose)
      printf("[Mem_run] Binding %d to %d\n", thread_rank, thread_bindings[thread_rank]);
#endif
    bind_current_thread(thread_bindings[thread_rank]);
  } else {
    printf("[Mem_run] No thread binding policy selected.\n");
    printf("[Mem_run] \tYou can use NUMAMMA_THREAD_BIND\n");
  }
}

static void load_custom_block(FILE*f) {
  char block_identifier[4096];
  size_t buffer_len=-1;
  size_t nb_blocks=0;

  struct mbind_directive *dir=malloc(sizeof(struct mbind_directive));
  
  int nread=fscanf(f, "%s\t%zu\t%d", dir->block_identifier, &dir->buffer_len, &dir->nb_blocks);
  assert(nread==3);
  if(_verbose)
    printf("New custom block(id=%s, len=%d, nblocks=%d)\n", dir->block_identifier, dir->buffer_len, dir->nb_blocks);

  if(strcmp(dir->block_identifier, "malloc") == 0) {
    dir->buffer_type=type_malloc;
  } else {
    dir->buffer_type=type_global;
  }
  dir->blocks = malloc(sizeof(struct block_bind)* dir->nb_blocks);
  char* line_buffer=NULL;
  size_t line_size;
  int block_id=0;
  dir->next = directives;
  directives = dir;

  while((nread=getline(&line_buffer, &line_size, f)) != -1) {
    if(strncmp(line_buffer, "end_block", 9) == 0)  {     
      dir->nb_blocks=block_id;
      return;
    }
    struct block_bind*block = &dir->blocks[block_id];
    int numa_node, start_page, end_page;
    nread=sscanf(line_buffer, "%d\t%d\t%d", &block->numa_node, &block->start_page, &block->end_page);
    if(nread == 3) {
      if(block->numa_node > nb_nodes-1) {
	fprintf(stderr, "Warning: trying to bind %s[page %d] on node %d, but there are only %d nodes on this machine\n",
		dir->block_identifier, block->start_page, block->numa_node, nb_nodes);
      }
      block_id++;
      if(block_id > dir->nb_blocks)
	break;
    }
  }
}

static void load_custom_mbind(const char*fname) {
  FILE*f = fopen(fname, "r");
  if(!f) {
    perror("Cannot open mbind file");
    exit(1);
  }
  char *line_buffer=NULL;
  size_t line_size;
  int nread=0;
  while((nread=getline(&line_buffer, &line_size, f)) != -1) {
    if(strncmp(line_buffer, "begin_block", 11) == 0) {
      load_custom_block(f);
    } else {
      /* Something else */
    }
  }
  
  fclose(f);
}

static void read_options() {
  char* verbose_str = getenv("NUMAMMA_VERBOSE");
  if(verbose_str) {
    if(strcmp(verbose_str, "0")!=0) {
      _verbose = 1;
      printf("Verbose mode enabled\n");
    }
  }

  char* mbind_policy_str = getenv("NUMAMMA_MBIND_POLICY");
  if(mbind_policy_str) {
    if(strcmp(mbind_policy_str, "interleaved")==0) {
      _mbind_policy= POLICY_INTERLEAVED;
      printf("Memory binding (interleaved) enabled\n");
    } else if(strcmp(mbind_policy_str, "block")==0) {
      _mbind_policy= POLICY_BLOCK;
      printf("Memory binding (block) enabled\n");
    } else if(strcmp(mbind_policy_str, "none")==0) {
      _mbind_policy= POLICY_NONE;
      printf("Memory binding (none) enabled\n");
    } else if(strcmp(mbind_policy_str, "custom")==0) {
      _mbind_policy= POLICY_CUSTOM;
      char* mbind_file=getenv("NUMAMMA_MBIND_FILE");
      if(!mbind_file) {
	fprintf(stderr, "Please set the NUMAMMA_MBIND_FILE variable\n");
	exit(1);
      }
      load_custom_mbind(mbind_file);
      printf("Memory binding (custom) enabled\n");
    } 
  } else {
    printf("[Mem_run] No memory binding policy selected.\n");
    printf("[Mem_run] \tYou can use NUMAMMA_MBIND_POLICY=interleaved|block|custom\n");
  }

  get_thread_binding();
}

extern char**environ;
char ld_preload_value[4096];

/* unset LD_PRELOAD
 * this makes sure that forked processes will not be analyzed
 */
void unset_ld_preload() {
  /* unset LD_PRELOAD */
  char* ld_preload = getenv("LD_PRELOAD");
  if(!ld_preload) {
    ld_preload_value[0]='\0';
    return;
  }

  /* save the value of ld_preload so that we can set it back later */
  strncpy(ld_preload_value, ld_preload, 4096);
  int ret = unsetenv("LD_PRELOAD");
  if(ret != 0 ){
    fprintf(stderr, "unsetenv failed ! %s\n", strerror(errno));
    abort();
  }

  /* also change the environ variable since exec* function
   * rely on it.
   */
  for (int i=0; environ[i]; i++) {
    if (strstr(environ[i],"LD_PRELOAD=")) {
      printf("hacking out LD_PRELOAD from environ[%d]\n",i);
      environ[i][0] = '\0';
    }
  }
  char*plop=getenv("LD_PRELOAD");
  if(plop) {
    fprintf(stderr, "Warning: cannot unset LD_PRELOAD\n");
    fprintf(stderr, "This is likely to cause problems later.\n");
  }
}

/* set LD_PRELOAD so that future forked processes are analyzed
 *  you need to call unset_ld_preload before calling this function
 */
void reset_ld_preload() {
  if(strlen(ld_preload_value)>0) {
    debug_printf("Setting back ld_preload to %s\n", ld_preload_value);
    setenv("LD_PRELOAD", ld_preload_value, 1);
  }
}

uintptr_t align_ptr(uintptr_t ptr, int align) {
  uintptr_t mask = ~(uintptr_t)(align - 1);
  uintptr_t res = ptr & mask;
  return ptr & mask;
}

int get_numa_node(void* address) {
  void * ptr_to_check = address;
  /*here you should align ptr_to_check to page boundary */
  int status=-1;
  int ret_code;
  ret_code = move_pages(0 /*self memory */, 1, &ptr_to_check,
			NULL, &status, 0);
  if(ret_code != 0) {
    perror("move_pages failed");
    abort();
  }
  if(status < 0){
    printf("move_pages failed: %s\n", strerror(-status));
  }
  return status;
}

static void bind_buffer_blocks(void*buffer, size_t len,
			       int n_blocks, struct block_bind* blocks) {
  if(n_blocks*page_size > len+page_size) {
    /* too many blocks ! */
    abort();
  }

  uintptr_t base_addr=align_ptr((uintptr_t)buffer, page_size);

  if(_verbose)
    printf("[Mem_run] Binding %d blocks. starting at %p\n", n_blocks, base_addr);


  for(int i=0; i<n_blocks; i++) {
    uintptr_t start_addr=base_addr + ((uintptr_t)blocks[i].start_page*page_size);
    start_addr+=page_size;
    size_t block_len=((blocks[i].end_page+1 - blocks[i].start_page))*page_size;
    const uint64_t nodeMask = 1UL << blocks[i].numa_node;

    if(blocks[i].numa_node>nb_nodes) {
      fprintf(stderr, "Bad binding: binding on node %d requested, but only %d nodes are available\n", blocks[i].numa_node, nb_nodes);
      abort();
    }
    if(_verbose)
      printf("\t[Mem_run] Binding pages %d-%d to node %d\n", blocks[i].start_page, blocks[i].end_page, blocks[i].numa_node);

    if(start_addr+block_len > (uintptr_t)buffer+len) {
      /* make sure there's no overflow */
      block_len=(uintptr_t)buffer+len-start_addr;
    }

    int ret = mbind((void*)start_addr, block_len, MPOL_BIND, &nodeMask, sizeof(nodeMask)*8, MPOL_MF_MOVE | MPOL_MF_STRICT);
    if(ret < 0) {
      perror("mbind failed");
      abort();
    }
    
#if CHECK_PLACEMENT
    int effective_node=get_numa_node((void*)start_addr);
    if(effective_node != blocks[i].numa_node ){
      printf("Warning: when binding %p to node %d: page is actually on node %d\n",
	     start_addr, blocks[i].numa_node, effective_node);
    } else {
      printf("When binding %p to node %d: page is indeed on node %d\n",
	     start_addr, blocks[i].numa_node, effective_node);
    }
#endif
  }
}

static void bind_block(void*buffer, size_t len) {
  if(_mbind_policy != POLICY_BLOCK)
    return;
  int nb_pages=((len/page_size));
  int nb_pages_per_node=1;
  if(nb_pages > nb_nodes) {
    nb_pages_per_node=nb_pages/nb_nodes;
  }

  int nb_blocks=0;
  struct block_bind blocks[nb_nodes];
  for(int i=0; i<nb_nodes; i++){
    blocks[i].start_page = i * nb_pages_per_node;
    blocks[i].end_page   = (i+1) * nb_pages_per_node;
    blocks[i].numa_node = i;
    nb_blocks++;
    if(blocks[i].end_page > nb_pages) {
      /* the last node gets all the remaining blocks */
      blocks[i].end_page = nb_pages;
      break;
    }
  }

  bind_buffer_blocks(buffer, len, nb_blocks, blocks);
}

static void bind_interleaved(void* buffer, size_t len) {
  if(_mbind_policy != POLICY_INTERLEAVED)
    return;
  int nblocks=(len/page_size)+1;
  struct block_bind blocks[nblocks];
  for(int i=0; i<nblocks; i++){
    blocks[i].start_page=i;
    blocks[i].end_page=i+1;
    blocks[i].numa_node = i%nb_nodes;
  }
  bind_buffer_blocks(buffer, len, nblocks, blocks);
}

static void check_buffer_placement(struct mbind_directive *dir) {
  assert(dir->base_addr);
  uintptr_t base_addr=align_ptr((uintptr_t)dir->base_addr, page_size);

  for(int i=0; i<dir->nb_blocks; i++) {
    uintptr_t start_addr=base_addr + dir->blocks[i].start_page*page_size;
    start_addr+=page_size;
    size_t block_len=((dir->blocks[i].end_page - dir->blocks[i].start_page))*page_size;
    const uint64_t nodeMask = 1UL << dir->blocks[i].numa_node;

    if(start_addr+block_len > (uintptr_t)dir->base_addr+dir->buffer_len) {
      /* make sure there's no overflow */
      block_len=(uintptr_t)dir->base_addr+dir->buffer_len-start_addr;
    }

#if CHECK_PLACEMENT
    int effective_node=get_numa_node((void*)start_addr);
    if(effective_node != dir->blocks[i].numa_node ){
      printf("Warning: %p/%d should be on node %d: page is actually on node %d\n",
	     start_addr, dir->blocks[i].start_page, dir->blocks[i].numa_node, effective_node);
    }
#endif
  }
}

static void check_placement() {
  struct mbind_directive *dir = directives;
  while(dir) {
    if( dir->base_addr)
      check_buffer_placement(dir);
    dir = dir->next;
  }
}

static void bind_custom(void* buffer, size_t len, char* buffer_id) {
  if(_mbind_policy != POLICY_CUSTOM || buffer_id == NULL)
    return;

  printf("Trying to bind %s\n", buffer_id);
  /* search for buffer_id in the list of mbind directives */
  struct mbind_directive *dir = directives;
  while(dir) {
    if(strcmp(dir->block_identifier, buffer_id)==0) {

      if(dir->buffer_len != len) {
	fprintf(stderr, "Warning: I found variable %s, but its length (%zu) is different from the specified length (%zu)\n",
		buffer_id, len, dir->buffer_len);
      } else {
	printf("Binding %s\n", buffer_id);
	dir->base_addr = buffer;
	bind_buffer_blocks(buffer, len, dir->nb_blocks, dir->blocks);
      }
      return;
    }
    dir = dir->next;
  }
  printf("\t%s not found\n", buffer_id);
}

static void bind_malloced_buffer(void* buffer, size_t len, char* buffer_id) {
  struct mbind_directive* dir = directives;
  while(dir) {
    /* search for the directive corresponding to this malloc */

    /* todo:
     * - take the buffer_id into account
     * - don't apply a directive several times
     */
    if(dir->buffer_type == type_malloc &&
       dir->buffer_len == len) {

      dir->base_addr = buffer;
      if(_verbose) {
	printf("Binding malloced buffer(len=%d)\n", len);
      }
      bind_buffer_blocks(buffer, len, dir->nb_blocks, dir->blocks);
      return;
    }

    dir = dir->next;
  }
}

static void bind_buffer(void* buffer, size_t len, char* buffer_id) {

  if(len > page_size) {
    switch(_mbind_policy) {
    case POLICY_INTERLEAVED:
      bind_interleaved(buffer, len);
      break;
    case POLICY_BLOCK:
      bind_block(buffer, len);
      break;
    case POLICY_CUSTOM:
      bind_custom(buffer, len, buffer_id);
      break;
      /* else: nothing to do */
    }
  }
}

char null_str[]="";

/* get the list of global/static variables with their address and size, and bind them
 * according to _mbind_policy
 */
void bind_global_variables() {
  if(_mbind_policy == POLICY_NONE) {
    /* nothing to do */
    return;
  }

  /* TODO: this function, share a lot of code with the ma_get_global_variables defined
   * in mem_analyzer.c
   * Maybe we should merge them ?
   */

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
    /* find address range of the heap */
    int exit_status= WEXITSTATUS(ret);
    if(exit_status == EXIT_SUCCESS) {
      /* process is compiled with -fPIE, thus, the addresses in the ELF are to be relocated */
      //      sprintf(cmd, "cat /proc/%d/maps |grep \"%s\" | grep  \" rw-p \"", getpid(), program_file);
      sprintf(cmd, "cat /proc/%d/maps |grep \"[heap]\"", getpid());
      f = popen(cmd, "r");
      fgets(line, 4096, f);
      fclose(f);
      sscanf(line, "%p-%p", &base_addr, &end_addr);
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
  sprintf(nm_cmd, "nm -fs --defined-only -l -S %s", program_file);
  //sprintf(nm_cmd, "nm --defined-only -l -S %s", program_file);
  f = popen(nm_cmd, "r");

  while(!feof(f)) {
    if( ! fgets(line, 4096, f) ) {
      goto out;
    }

    char *addr = null_str;
    char *size_str = null_str;
    char *section = null_str;
    char *symbol = null_str;
    char *file = null_str;
    char *type = null_str;

    int nb_found;
    /* line is in the form:
symbol_name |addr| section | type |symbol_size| [line]    |section    [file:line]
    */
    const char* delim="| \t\n";

    symbol = strtok(line, delim);
    if(!symbol|| strcmp(symbol, "_end")==0) {
      /* nothing to read */
      continue;
    }
    
    addr = strtok(NULL, delim);
    if(!addr) {
      /* nothing to read */
      continue;
    }

    section = strtok(NULL, delim);
    if(!section) {
      /* nothing to read */
      continue;
    }
    type = strtok(NULL, delim);
    if(!type) {
      /* nothing to read */
      continue;
    }

    size_str = strtok(NULL, " \t\n");
    if(!size_str) {
      /* nothing to read */
      continue;
    }

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

      if(strcmp(type, "TLS") == 0) {
	continue;
      }
      size_t size;
      sscanf(size_str, "%lx", &size);
      if(size) {

	
#if 0
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
#endif
	
	/* addr is the offset within the binary. The actual address of the variable is located at
	 *  addr+base_addr
	 */
	size_t offset;
	sscanf(addr, "%lx", &offset);
	void* buffer_addr = offset + (uint8_t*)base_addr;
	size_t buffer_size = size;
	char caller[1024];
	snprintf(caller, 1024, "%s in %s", symbol, file);

	debug_printf("Found a global variable: %s (defined at %s). base addr=%p, size=%zu\n",
		     symbol, file, buffer_addr, buffer_size);
	bind_buffer(buffer_addr, buffer_size, symbol);
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

static void __memory_init(void) __attribute__ ((constructor));
static void __memory_init(void) {
  PROTECT_FROM_RECURSION;
  /* TODO: there's a race condition here: if I remove the printf, then mem_run
   * fails while loading the custom mbind policy file. This should be investigated !
   */
  printf("[Mem_run] initializing stuff\n");
#if INTERCEPT_MALLOC
  printf("[Mem_run] malloc interception is enabled\n");
#else
    printf("[Mem_run] malloc interception is disabled\n");
#endif
  libmalloc = dlsym(RTLD_NEXT, "malloc");
  libcalloc = dlsym(RTLD_NEXT, "calloc");
  librealloc = dlsym(RTLD_NEXT, "realloc");
  libfree = dlsym(RTLD_NEXT, "free");
  libpthread_create = dlsym(RTLD_NEXT, "pthread_create");
  libpthread_exit = dlsym(RTLD_NEXT, "pthread_exit");

  nb_nodes = numa_num_configured_nodes();
  read_options();

  bind_global_variables();

  __memory_initialized = 1;
  printf("[Mem_run] initialization done\n");
  UNPROTECT_FROM_RECURSION;
}

static void __memory_conclude(void) __attribute__ ((destructor));
static void __memory_conclude(void) {
  check_placement();
  __memory_initialized = 0;
  printf("Nb malloc: %d\n", nb_malloc);
  printf("Nb realloc: %d\n", nb_realloc);
  printf("Nb calloc: %d\n", nb_calloc);
  printf("Nb free: %d\n", nb_free);
}
