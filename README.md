# NumaMMa: Numa Memory Manager 

## Content of this repository

### `tools` folder

#### count_events

The  two  files `count_events.c`  and  `count_events.in`  are used  to
generate  a dynamic  library, `libcount_events.so`  and an  executable
script.   This  scripts   takes  a  program  as   argument,  adds  the
`libcount_events.so` to the list of  libraries loaded when the process
is started and starts the program.

The `libcount_events.so` contains constructor and destructor functions
automatically called when  the process is started  and terminated. The
constructor  function starts  the counting  of 28  events through  the
`perf_event_open`  system call.   The  destructor  function stops  the
counting and prints the count of each event on stdout.

#### libnumamma-tools

The   file    `hash.c`   is    compiled   into   a    shared   library
`libnumamma-tools.so`.  This file  provides  functions  to create  and
manipulate a has map.

 
### src folder

#### libnumama

- `mem_intercept.c`
  + This file contains overload  of `pthread_create` function to start
    sampling  for the  thread  created.  This is  done  by  call  to
    `ma_thread_init`.
  +  This  file  contains  overload of  memory  allocation  functions,
    `malloc` and co to log the accesses by calls to `ma_record_malloc`
    and `ma_update_buffer_address` and `ma_record_free` functions;
- `mem_tools.c`
  + This  file contains  function to do  something with  the backtrace
    lib. To retreive some information.
- `mem_sampling.c`
  + Provides functions to start / stop mem sampling.
- `mem_analyzer.c`
  + The main file gluing together all the other ones.
- `mem_intercept.in` 
  + Shell  script parametric  file  used  to ld_preload  `libnumama.so`
    before running a program.

#### libnuma_run

Something new  by François  which is  just as  `mem_intercept.c` whith
control of threads location.

- `mem_run.c`
