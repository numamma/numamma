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
#include <sys/stat.h>
#include <sys/types.h>

#include "numamma.h"
#include "mem_intercept.h"
#include "mem_analyzer.h"
#include "mem_tools.h"

struct numamma_settings settings;
static char dump_filename[STRING_LEN];
FILE* dump_file = NULL;
static char dump_unmatched_filename[STRING_LEN];
FILE* dump_unmatched_file = NULL;
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
void* (*lib_Znwm)(size_t size) = NULL; /* the "new" operator in c++ 64bits  */
void* (*lib_Znwj)(size_t size) = NULL; /* the "new" operator in c++ 32bits  */

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


#define STRINGIFY(x) #x
#define GENERIC_MALLOC(FNAME, MALLOC_TYPE, CALLBACK)			\
  void* FNAME(size_t size) {						\
    /* if memory_init hasn't been called yet, we need to get libc's malloc \
     * address								\
     */									\
    if (!CALLBACK) {							\
      if( !IS_RECURSE_SAFE) {						\
	/* protection flag says that malloc is already trying to retrieve the \
	 * address of malloc.						\
	 * If we call dlsym now, there will be an infinite recursion, so let's \
	 * allocate memory 'by hand'					\
	 */								\
	return hand_made_malloc(size);					\
      }									\
									\
      /* set the protection flag and retrieve the address of malloc.	\
       * If dlsym calls malloc, memory will be allocated 'by hand'	\
       */								\
      PROTECT_FROM_RECURSION;						\
      {									\
	CALLBACK = dlsym(RTLD_NEXT, STRINGIFY(FNAME));			\
	char* error;							\
	if ((error = dlerror()) != NULL) {				\
	  fputs(error, stderr);						\
	  exit(1);							\
	}								\
      }									\
      /* it is now safe to call libmalloc */				\
      UNPROTECT_FROM_RECURSION;						\
    }									\
									\
    /* allocate a buffer */						\
    void* pptr = CALLBACK(size + HEADER_SIZE + TAIL_SIZE);		\
    /* fill the information on the malloc'd buffer */			\
    struct mem_block_info *p_block = NULL;				\
    INIT_MEM_INFO(p_block, pptr, size, 1);				\
									\
    if(__memory_initialized && IS_RECURSE_SAFE) {			\
      PROTECT_FROM_RECURSION;						\
									\
      p_block->mem_type = MALLOC_TYPE;					\
									\
      /* let the analysis module record information on the malloc */	\
      ma_record_malloc(p_block);					\
									\
      UNPROTECT_FROM_RECURSION;						\
    } else {								\
      /* we are already processing a malloc/free function, so don't try to record information, \
       * just call the function						\
       */								\
      p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;			\
    }									\
    return p_block->u_ptr;		\
  }									\

GENERIC_MALLOC(malloc, MEM_TYPE_MALLOC, libmalloc);
GENERIC_MALLOC(_Znwj, MEM_TYPE_NEW, libmalloc);
GENERIC_MALLOC(_Znwm, MEM_TYPE_NEW, libmalloc);

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

  if (p_block->mem_type == MEM_TYPE_HAND_MADE_MALLOC) {
    /* the buffer was allocated by hand_made_malloc.
     * we need to emulate the behavior of realloc:
     * allocate a buffer, and copy the data to the new buffer
     */
    void* pptr = malloc(size);
    memcpy(pptr, p_block->u_ptr, p_block->size);
    return pptr;
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
    //    abort();
    libfree(ptr);
    return;
  }

  struct mem_block_info *p_block;
  USER_PTR_TO_BLOCK_INFO(ptr, p_block);

  /* retrieve the block information and free it */
  if(__memory_initialized && IS_RECURSE_SAFE &&
     (p_block->mem_type == MEM_TYPE_MALLOC || p_block->mem_type == MEM_TYPE_NEW) ) {
    PROTECT_FROM_RECURSION;

    //    debug_printf("free(%p)\n", ptr);

    if(!TAIL_CANARY_OK(p_block)) {
      fprintf(stderr, "Warning: tail canary erased :'( (%" PRIu64 " instead of %" PRIu64 ")\n", p_block->tail_block->canary, CANARY_PATTERN);
      abort();
    }

    ma_record_free(p_block);
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
  ma_thread_init();
  thread_array[thread_rank].status = thread_status_created;

  UNPROTECT_FROM_RECURSION;
  int oldtype;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

  pthread_cleanup_push(__thread_cleanup_function,
		       &thread_array[thread_rank]);

  res = (*f)(__arg);

  pthread_cleanup_pop(0);
  fprintf(stderr, "End of thread [%d] %lu\n", thread_rank, thread_array[thread_rank].tid);
  __thread_cleanup_function(&thread_array[thread_rank]);
  return res;
}


static void __thread_cleanup_function(void* arg) {
  struct thread_info* me = arg;
  is_recurse_unsafe ++;
  ma_thread_finalize();
  me->status = thread_status_finalized;
  is_recurse_unsafe --;
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
  __args->thread_rank = thread_rank;

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

char *counters_dir=NULL;

char* get_log_dir() {
  if(!counters_dir) {
    counters_dir = malloc(STRING_LEN);
    snprintf(counters_dir, STRING_LEN, "%s", settings.output_dir);
    mkdir(counters_dir, S_IRWXU);
  }
  return counters_dir;
}

void create_log_filename(char* basename, char *filename, int length) {
  snprintf(filename, length, "%s/%s", get_log_dir(), basename);
}

#define getenv_int(var, envname, default_value) do {	\
    char* str = getenv(envname);			\
    (var) = default_value;				\
    if(str) {						\
      (var) = atoi(str);				\
    }							\
  } while(0)

static void read_settings() {
  getenv_int(settings.verbose, "NUMAMMA_VERBOSE", SETTINGS_VERBOSE_DEFAULT);
  getenv_int(settings.sampling_rate, "NUMAMMA_SAMPLING_RATE", SETTINGS_SAMPLING_RATE_DEFAULT);
  getenv_int(settings.alarm, "NUMAMMA_ALARM", SETTINGS_ALARM_DEFAULT);
  getenv_int(settings.flush, "NUMAMMA_FLUSH", SETTINGS_FLUSH_DEFAULT);
  getenv_int(settings.buffer_size, "NUMAMMA_BUFFER_SIZE", SETTINGS_BUFFER_SIZE_DEFAULT);

  char* str = getenv("NUMAMMA_OUTPUT_DIR");
  settings.output_dir = malloc(STRING_LEN);
  if(str) {
    strncpy(settings.output_dir, str, STRING_LEN);
  } else {
    snprintf(settings.output_dir, STRING_LEN, "/tmp/numamma_%s", getenv("USER"));
  }

  getenv_int(settings.match_samples, "NUMAMMA_MATCH_SAMPLES", SETTINGS_MATCH_SAMPLES_DEFAULT);
  getenv_int(settings.online_analysis, "NUMAMMA_ONLINE_ANALYSIS", SETTINGS_ONLINE_ANALYSIS_DEFAULT);
  getenv_int(settings.dump, "NUMAMMA_DUMP", SETTINGS_DUMP_DEFAULT);
  getenv_int(settings.dump_unmatched, "NUMAMMA_DUMP_UNMATCHED", SETTINGS_DUMP_UNMATCHED_DEFAULT);
}

static void print_settings() {
  printf("-----------------------------------\n");
  printf("NumaMMA settings\n");
  printf("verbose        : %s\n", settings.verbose ? "yes":"no");
  printf("sampling_rate  : %d\n", settings.sampling_rate);
  printf("alarm          : %d\n", settings.alarm);
  printf("flush          : %s\n", settings.flush? "yes":"no");
  printf("buffer_size    : %d KB\n", settings.buffer_size);
  printf("output_dir     : %s\n", settings.output_dir);
  printf("match_samples  : %s\n", settings.match_samples? "yes":"no");
  printf("online_analysis: %s\n", settings.online_analysis? "yes":"no");
  printf("dump           : %s\n", settings.dump? "yes":"no");
  printf("dump_unmatched : %s\n", settings.dump_unmatched? "yes":"no");
  printf("-----------------------------------\n");
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

  read_settings();
  print_settings();

  if(settings.dump) {
    create_log_filename("memory_dump.log", dump_filename, STRING_LEN);
    dump_file = fopen(dump_filename, "w");
    if(!dump_file) {
      fprintf(stderr, "Cannot create %s: %s\n", dump_filename, strerror(errno));
      abort();
    }
  }

  if(settings.dump_unmatched) {
    create_log_filename("unmatched.log", dump_unmatched_filename, STRING_LEN);
    dump_unmatched_file = fopen(dump_unmatched_filename, "w");
    if(!dump_unmatched_file) {
      fprintf(stderr, "Cannot create %s: %s\n", dump_unmatched_filename, strerror(errno));
      abort();
    }
  }

  ma_init();

  ma_get_variables();

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

  printf("\n\n");
  printf("-----------------------------------\n");
  printf("NumaMMA report:\n");
  
  ma_finalize();
  if(settings.dump) {
    fclose(dump_file);
    printf("Samples were written to %s\n", dump_filename);
  }

  if(settings.dump_unmatched) {
    fclose(dump_unmatched_file);
    printf("Unmatched samples were written to %s\n", dump_unmatched_filename);
  }
}
