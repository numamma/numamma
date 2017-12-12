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

#include "numamma.h"

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
  POLICY_MAX
};
enum mbind_policy _mbind_policy;

/* array describing the binding of each thread */
int thread_bindings[100];
/* number of valid entries in the array */
int nb_thread_max=0;


int page_size=4096;		/* todo: detect this using sysconf */
int nb_nodes=-1;

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

static void bind_buffer(void* buffer, size_t len);


/* Custom malloc function. It is used when libmalloc=NULL (e.g. during startup)
 * This function is not thread-safe and is very likely to be bogus, so use with
 * caution
 */
static void* hand_made_malloc(size_t size) {
  /* allocate a 1MB buffer */
#define POOL_SIZE (1024 * 1024)
  static char mem[POOL_SIZE] = {'\0'};

  /* since this function is only used before we found libmalloc, there's no
   * fancy memory management mechanism (block reuse, etc.)
   */
  static char* next_slot = &mem[0];
  static int total_alloc = 0;

  if (libmalloc)
    /* let's use the real malloc */
    return malloc(size);

  debug_printf("%s(size=%lu) ", __FUNCTION__, size);


  /* if you want to make this function thread-safe, these instructions should be protected
   * by a mutex:
   */
  total_alloc += size;
  void* buffer=next_slot;
  next_slot = next_slot + size;

  return buffer;
}

void* malloc(size_t size) {
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
  void* pptr = libmalloc(size);
  bind_buffer(pptr, size);

  return pptr;
}

void* realloc(void *ptr, size_t size) {

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

  void *pptr = librealloc(ptr, size);
  return pptr;
}

void* calloc(size_t nmemb, size_t size) {
  if (!libcalloc) {
    void* ret = hand_made_malloc(nmemb * size);
    if (ret) {
      memset(ret, 0, nmemb * size);
    }
    return ret;
  }

  /* allocate buffer + header */
  void* p_ptr = libcalloc(nmemb, size);
  return p_ptr;
}

void free(void* ptr) {

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
  libfree(ptr);
}

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
  libfree(p_arg);

  UNPROTECT_FROM_RECURSION;
  int oldtype;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

  pthread_cleanup_push(__thread_cleanup_function,
		       &thread_array[thread_rank]);

  res = (*f)(__arg);

  pthread_cleanup_pop(0);
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
  int thread_rank = __sync_fetch_and_add( &nb_threads, 1 );
  thread_array[thread_rank].status = thread_status_created;
  struct __pthread_create_info_t * __args =
    (struct __pthread_create_info_t*) libmalloc(sizeof(struct __pthread_create_info_t));
  __args->func = start_routine;
  __args->arg = arg;
  __args->thread_rank= thread_rank;

  if (!libpthread_create) {
    libpthread_create = dlsym(RTLD_NEXT, "pthread_create");
  }

  pthread_attr_t local_attr;
  if(attr) {
    memcpy(&local_attr, attr, sizeof(local_attr));
  }
  if(bind_threads && thread_rank < nb_thread_max) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(thread_bindings[thread_rank], &cpuset);
    if(_verbose)
      printf("[MemRun] Binding %d to %d\n", thread_rank, thread_bindings[thread_rank]);
    int ret = pthread_attr_setaffinity_np(&local_attr,
					  sizeof(cpuset),
					  &cpuset);
    if(ret != 0){
      perror("pthread_attr_setaffinity_np failed");
      abort();
    }
  }

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
    } 
  }
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

struct block_bind {
  int start_page;
  int end_page;
  int numa_node;
};

uintptr_t align_ptr(uintptr_t ptr, int align) {
  uintptr_t mask = ~(uintptr_t)(align - 1);
  uintptr_t res = ptr & mask;
  return ptr & mask;
}

static void bind_buffer_blocks(void*buffer, size_t len,
			       int n_blocks, struct block_bind* blocks) {
  if(n_blocks*page_size > len+page_size) {
    /* too many blocks ! */
    abort();
  }

  uintptr_t base_addr=align_ptr((uintptr_t)buffer, page_size);
  if(_verbose)
    printf("[MemRun] Binding %d blocks. starting at %p\n", n_blocks, base_addr);

  for(int i=0; i<n_blocks; i++) {
    uintptr_t start_addr=base_addr + blocks[i].start_page*page_size;
    size_t block_len=((blocks[i].end_page - blocks[i].start_page)+1)*page_size;
    const unsigned long nodeMask = 1UL << blocks[i].numa_node;
    if(_verbose)
      printf("\t[MemRun] Binding pages %d-%d to node %d\n", blocks[i].start_page, blocks[i].end_page, blocks[i].numa_node);
    int ret = mbind((void*)start_addr, block_len, MPOL_BIND, &nodeMask, sizeof(nodeMask), MPOL_MF_MOVE | MPOL_MF_STRICT);
    if(ret < 0) {
      perror("mbind failed");
      abort();
    }
  }
}

static void bind_block(void*buffer, size_t len) {
  if(_mbind_policy != POLICY_BLOCK)
    return;
  int nb_pages=((len/page_size)+1); // 1
  int nb_pages_per_node=1;
  if(nb_pages > nb_nodes) {
    nb_pages_per_node=nb_pages/nb_nodes; // 1
  }

  int nb_blocks=0;
  struct block_bind blocks[nb_nodes];

  for(int i=0; i<nb_nodes; i++){
    blocks[i].start_page = i * nb_pages_per_node; // 0
    blocks[i].end_page   = (i+1) * nb_pages_per_node; // 1
    blocks[i].numa_node = i;
    nb_blocks++;
    if(i==nb_nodes-1) {
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

static void bind_buffer(void* buffer, size_t len) {

  if(len > page_size) {
    switch(_mbind_policy) {
    case POLICY_INTERLEAVED:
      bind_interleaved(buffer, len);
      break;
    case POLICY_BLOCK:
      bind_block(buffer, len);
      break;
      /* else: nothing to do */
    }
  }
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
    printf("[MemRun] Thread binding activated: %s\n", str);
    char bindings[1024];
    strncpy(bindings, str, 1024);
    char* token = strtok(bindings, ",");
    while(token) {
      thread_bindings[nb_thread_max] = atoi(token);
      nb_thread_max++;
      token = strtok(NULL, ",");
    }

    bind_threads=1;
    if(_verbose) {
      for(int i=0; i<nb_thread_max; i++) {
	printf("[MemRun] Thread %d is bound to %d\n", i, thread_bindings[i]);
      }
    }

    int thread_rank = nb_threads++;
    thread_array[thread_rank].status = thread_status_created;

    if(_verbose)
      printf("[MemRun] Binding %d to %d\n", thread_rank, thread_bindings[thread_rank]);
    bind_current_thread(thread_bindings[thread_rank]);
  }
}

static void __memory_init(void) __attribute__ ((constructor));
static void __memory_init(void) {
  PROTECT_FROM_RECURSION;

  libmalloc = dlsym(RTLD_NEXT, "malloc");
  libcalloc = dlsym(RTLD_NEXT, "calloc");
  librealloc = dlsym(RTLD_NEXT, "realloc");
  libfree = dlsym(RTLD_NEXT, "free");
  libpthread_create = dlsym(RTLD_NEXT, "pthread_create");
  libpthread_exit = dlsym(RTLD_NEXT, "pthread_exit");

  read_options();
  nb_nodes = numa_num_configured_nodes();
  printf("There are %d nodes\n", nb_nodes);
  get_thread_binding();
  //  ma_get_global_variables();

  __memory_initialized = 1;
  UNPROTECT_FROM_RECURSION;
}

static void __memory_conclude(void) __attribute__ ((destructor));
static void __memory_conclude(void) {

  __memory_initialized = 0;
}
