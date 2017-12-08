/* -*- c-file-style: "GNU" -*- */
#define _GNU_SOURCE

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

#include "numamma.h"
#include "mem_intercept.h"
#include "mem_analyzer.h"
#include "mem_tools.h"

int _verbose = 0;
int _dump = 0;
FILE* dump_file = NULL;
__thread int is_recurse_unsafe = 0;

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

  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, next_slot, size, 1);

  p_block->mem_type = MEM_TYPE_HAND_MADE_MALLOC;
  total_alloc += size;
  next_slot = next_slot + p_block->total_size;

  return p_block->u_ptr;
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

  //debug_printf("%s(size=%lu) ", __FUNCTION__, size);
  /* allocate a buffer */
  void* pptr = libmalloc(size + HEADER_SIZE + TAIL_SIZE);
  /* fill the information on the malloc'd buffer */
  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, pptr, size, 1);

  if(__memory_initialized && IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;

    p_block->mem_type = MEM_TYPE_MALLOC;

    /* let the analysis module record information on the malloc */
    ma_record_malloc(p_block);
    //    debug_printf("-> %p (p_block=%p)\n", p_block->u_ptr, p_block);

    UNPROTECT_FROM_RECURSION;
    //    return p_block->u_ptr;
  } else {
    /* we are already processing a malloc/free function, so don't try to record information,
     * just call the function
     */
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }

  //  debug_printf("--> %p (p_block=%p)\n", p_block->u_ptr, p_block);
  return p_block->u_ptr;//  return pptr;
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

  debug_printf("%s(ptr=%p, size=%lu) ", __FUNCTION__, ptr, size);

  if (!CANARY_OK(ptr)) {
    /* we didn't malloc'ed this buffer */
    fprintf(stderr,"%s(%p). I can't find this pointer !\n", __FUNCTION__, ptr);
    abort();
    void* retval = librealloc(ptr, size);
    debug_printf("--> %p\n", retval);
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
      debug_printf("--> %p\n", NULL);
      return NULL;
    }

    p_block->mem_type = MEM_TYPE_MALLOC;
    void *new_addr= p_block->u_ptr;
    ma_update_buffer_address(p_block, old_addr, new_addr);
    UNPROTECT_FROM_RECURSION;
  } else {
    /* it is not safe to record information */
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }

  debug_printf("--> %p (p_block=%p)\n", p_block->u_ptr, p_block);
  return p_block->u_ptr;
}

void* calloc(size_t nmemb, size_t size) {
  if (!libcalloc) {
    void* ret = hand_made_malloc(nmemb * size);
    if (ret) {
      memset(ret, 0, nmemb * size);
    }
    return ret;
  }

  debug_printf("calloc(nmemb=%zu, size=%zu) ", nmemb, size);

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

    ma_record_malloc(p_block);
    UNPROTECT_FROM_RECURSION;
  } else {
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
    //  return libcalloc(nmemb, size);
  }
  debug_printf("--> %p (p_block=%p)\n", p_block->u_ptr, p_block);
  return p_block->u_ptr;
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

  //  debug_printf("%s(ptr=%lu) ", __FUNCTION__, ptr);

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

  /* retrieve the block information and free it */
  if(__memory_initialized && IS_RECURSE_SAFE &&p_block->mem_type == MEM_TYPE_MALLOC) {
    PROTECT_FROM_RECURSION;

    //    debug_printf("free(%p)\n", ptr);

    if(!TAIL_CANARY_OK(p_block)) {
      fprintf(stderr, "Warning: tail canary erased :'( (%" PRIu64 " instead of %" PRIu64 ")\n", p_block->tail_block->canary, CANARY_PATTERN);
      abort();
    }

    if (p_block->mem_type == MEM_TYPE_MALLOC) {
      ma_record_free(p_block);
    } else {
      /* the buffer was allocated by hand_made_malloc, there's nothing to free */
    }
    UNPROTECT_FROM_RECURSION;
  } else {
    /* internal malloc or hand made malloc, nothing to do */
  }
  libfree(p_block->p_ptr);
}

/* Internal structure used for transmitting the function and argument
 * during pthread_create.
 */
struct __pthread_create_info_t {
  void *(*func)(void *);
  void *arg;
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
  libfree(p_arg);
  ma_thread_init();
  UNPROTECT_FROM_RECURSION;
  int oldtype;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

  int thread_rank = __get_thread_rank(pthread_self());
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
  ma_thread_finalize();
  me->status = thread_status_finalized;
  UNPROTECT_FROM_RECURSION;
}

int
pthread_create (pthread_t *__restrict thread,
		const pthread_attr_t *__restrict attr,
		void *(*start_routine) (void *),
		void *__restrict arg) {
  FUNCTION_ENTRY;
  struct __pthread_create_info_t * __args =
    (struct __pthread_create_info_t*) libmalloc(sizeof(struct __pthread_create_info_t));
  __args->func = start_routine;
  __args->arg = arg;

  if (!libpthread_create) {
    libpthread_create = dlsym(RTLD_NEXT, "pthread_create");
  }

  int thread_rank = __sync_fetch_and_add( &nb_threads, 1 );
  thread_array[thread_rank].status = thread_status_created;

  /* We do not call directly start_routine since we want to initialize stuff at the thread startup.
   * Instead, let's invoke __pthread_new_thread that initialize the thread-specific things and call
   * start_routine.
   */
  int retval = libpthread_create(&thread_array[thread_rank].tid, attr, __pthread_new_thread, __args);
  memcpy(thread, &thread_array[thread_rank].tid, sizeof(pthread_t));

  return retval;
}

void pthread_exit(void *thread_return) {
  FUNCTION_ENTRY;
  PROTECT_FROM_RECURSION;
  {
    ma_thread_finalize();
  }
  UNPROTECT_FROM_RECURSION;
  libpthread_exit(thread_return);
  __builtin_unreachable();
}

static char* dump_filename = NULL;

static void read_options() {
  char* verbose_str = getenv("NUMAMMA_VERBOSE");
  if(verbose_str) {
    if(strcmp(verbose_str, "0")!=0) {
      _verbose = 1;
      printf("Verbose mode enabled\n");
    }
  }

  char* dump_str = getenv("NUMAMMA_DUMP");
  if(dump_str) {
    if(strcmp(dump_str, "0")!=0) {
      _dump = 1;
      dump_filename="/tmp/memory_dump.log";
      dump_file = fopen(dump_filename, "w");
      printf("Dump mode enabled. Data will be dumped to %s\n", dump_filename);
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
  ma_init();

  ma_get_global_variables();

  __memory_initialized = 1;
  UNPROTECT_FROM_RECURSION;
}

void wait_for_other_threads() {
  int i;
  for(i=0; i<nb_threads; i++) {
    /* the thread is still running */
    if(thread_array[i].status == thread_status_created) {
      /* ask the thread to stop */
      int retval = pthread_cancel(thread_array[i].tid);
      if(retval != 0) {
	fprintf(stderr, "pthread_cancel failed (%s)\n", strerror(errno));
	abort();
      }

      /* wait until the thread stopped */

      /* we could use pthread_join, but join may fail if the thread is not joinable (OpenMP
       * thread for instance)
       */
      while(thread_array[i].status == thread_status_created) {
	sched_yield();
      }

    }
  }
}

static void __memory_conclude(void) __attribute__ ((destructor));
static void __memory_conclude(void) {

  wait_for_other_threads();
  __memory_initialized = 0;
  ma_finalize();
  if(dump_filename) {
    printf("Samples were written to %s\n", dump_filename);
  }
}
