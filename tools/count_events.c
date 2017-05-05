#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>

struct counter{
  struct perf_event_attr attr;
  int counter_id;
  char counter_name[80];
  int fd;
  long long count;
  int status;
};

#define NB_COUNTERS 28
struct counter counters[]={
  {.counter_id=PERF_COUNT_HW_CPU_CYCLES, .counter_name="PERF_COUNT_HW_CPU_CYCLES"},
  {.counter_id=PERF_COUNT_HW_INSTRUCTIONS, .counter_name="PERF_COUNT_HW_INSTRUCTIONS"},
  {.counter_id=PERF_COUNT_HW_CACHE_REFERENCES, .counter_name="PERF_COUNT_HW_CACHE_REFERENCES"},
  {.counter_id=PERF_COUNT_HW_CACHE_MISSES, .counter_name="PERF_COUNT_HW_CACHE_MISSES"},
  {.counter_id=PERF_COUNT_HW_BRANCH_MISSES, .counter_name="PERF_COUNT_HW_BRANCH_MISSES"},
  {.counter_id=PERF_COUNT_HW_BUS_CYCLES, .counter_name="PERF_COUNT_HW_BUS_CYCLES"},
  {.counter_id=PERF_COUNT_HW_REF_CPU_CYCLES, .counter_name="PERF_COUNT_HW_REF_CPU_CYCLES"},
  {.counter_id=PERF_COUNT_HW_CACHE_L1D	, .counter_name="PERF_COUNT_HW_CACHE_L1D	"},
  {.counter_id=PERF_COUNT_HW_CACHE_L1I	, .counter_name="PERF_COUNT_HW_CACHE_L1I	"},
  {.counter_id=PERF_COUNT_HW_CACHE_LL	, .counter_name="PERF_COUNT_HW_CACHE_LL	"},
  {.counter_id=PERF_COUNT_HW_CACHE_DTLB, .counter_name="PERF_COUNT_HW_CACHE_DTLB"},
  {.counter_id=PERF_COUNT_HW_CACHE_ITLB, .counter_name="PERF_COUNT_HW_CACHE_ITLB"},
  {.counter_id=PERF_COUNT_HW_CACHE_BPU	, .counter_name="PERF_COUNT_HW_CACHE_BPU	"},
  {.counter_id=PERF_COUNT_HW_CACHE_NODE, .counter_name="PERF_COUNT_HW_CACHE_NODE"},
  {.counter_id=PERF_COUNT_HW_CACHE_OP_READ, .counter_name="PERF_COUNT_HW_CACHE_OP_READ"},
  {.counter_id=PERF_COUNT_HW_CACHE_OP_WRITE, .counter_name="PERF_COUNT_HW_CACHE_OP_WRITE"},
  {.counter_id=PERF_COUNT_HW_CACHE_OP_PREFETCH, .counter_name="PERF_COUNT_HW_CACHE_OP_PREFETCH"},
  {.counter_id=PERF_COUNT_HW_CACHE_RESULT_MISS, .counter_name="PERF_COUNT_HW_CACHE_RESULT_MISS"},
  {.counter_id=PERF_COUNT_SW_CPU_CLOCK	, .counter_name="PERF_COUNT_SW_CPU_CLOCK	"},
  {.counter_id=PERF_COUNT_SW_TASK_CLOCK, .counter_name="PERF_COUNT_SW_TASK_CLOCK"},
  {.counter_id=PERF_COUNT_SW_PAGE_FAULTS, .counter_name="PERF_COUNT_SW_PAGE_FAULTS"},
  {.counter_id=PERF_COUNT_SW_CONTEXT_SWITCHES, .counter_name="PERF_COUNT_SW_CONTEXT_SWITCHES"},
  {.counter_id=PERF_COUNT_SW_CPU_MIGRATIONS, .counter_name="PERF_COUNT_SW_CPU_MIGRATIONS"},
  {.counter_id=PERF_COUNT_SW_PAGE_FAULTS_MIN, .counter_name="PERF_COUNT_SW_PAGE_FAULTS_MIN"},
  {.counter_id=PERF_COUNT_SW_PAGE_FAULTS_MAJ, .counter_name="PERF_COUNT_SW_PAGE_FAULTS_MAJ"},
  {.counter_id=PERF_COUNT_SW_EMULATION_FAULTS, .counter_name="PERF_COUNT_SW_EMULATION_FAULTS"},
  {.counter_id=PERF_COUNT_SW_DUMMY	, .counter_name="PERF_COUNT_SW_DUMMY	"},
  {.counter_id=PERF_COUNT_SW_BPF_OUTPUT, .counter_name="PERF_COUNT_SW_BPF_OUTPUT"},
};


static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
  int ret;

  ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		group_fd, flags);
  return ret;
}

int init_perf_event_attr(struct counter*c) {

  struct perf_event_attr*p = &c->attr;
  int config = c->counter_id;
  int fd;
  memset(p, 0, sizeof(struct perf_event_attr));
  p->type = PERF_TYPE_HARDWARE;
  p->size = sizeof(struct perf_event_attr);
  p->config = config;
  p->disabled = 1;
  p->exclude_kernel = 1;
  p->exclude_hv = 1;

  c->fd = perf_event_open(p, 0, -1, -1, 0);
  if (c->fd == -1) {
    fprintf(stderr, "Error opening counter %s (%s)\n", c->counter_name, strerror(errno));
    return -1;
  }

  ioctl(c->fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(c->fd, PERF_EVENT_IOC_ENABLE, 0);
  c->status = 1;
  return fd;
}

static void __init_function(void) __attribute__ ((constructor));
static void __init_function(void) {
  int i;
  int ncount = NB_COUNTERS;
  for(i=0; i<ncount; i++) {
    init_perf_event_attr(&counters[i]);
  }

}

static void __conclude_function(void) __attribute__ ((destructor));
static void __conclude_function(void) {
  int i;
  int ncount = NB_COUNTERS;
  for(i=0; i<ncount; i++) {
    if(counters[i].status > 0) {
      ioctl(counters[i].fd, PERF_EVENT_IOC_DISABLE, 0);
      read(counters[i].fd, &counters[i].count, sizeof(long long));
      printf("%s: %lld\n", counters[i].counter_name, counters[i].count);
      close(counters[i].fd);
    }
  }
}
