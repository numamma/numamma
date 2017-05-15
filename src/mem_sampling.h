#ifndef MEM_SAMPLING_H
#define MEM_SAMPLING_H

#include "numap.h"
#include "mem_analyzer.h"

#define USE_NUMAP 1

extern int sampling_rate;

void mem_sampling_init();
void mem_sampling_thread_init();
void mem_sampling_thread_finalize();

void mem_sampling_collect_samples();
void mem_sampling_start();
void mem_sampling_resume();

void mem_sampling_statistics();

#endif /* MEM_SAMPLING_H */
