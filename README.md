# NumaMMa: Numa Memory Manager 

NumaMMa is both a NUMA memory profiler and a NUMA application execution engine. The profiler allows to run an application while gathering information about memory accesses. Based on the results of the profiler, the execution engine is capable of executing the application in an efficient way by allocating memory pages in a clever way.

## Dependencies

NumaMMa relies on the folowing libraries:

- `numactl`
- `numap`
- `backtrace`

## Build

The above dependencies must be installed first. Then NumaMMa itself can be built. The following commands can be used to download and build NumaMMa with all its dependencies. If you do not have a github account with an SSH key properly configured, the git clone commands targeting github.com should be changed to use https.

```bash

# create folder where NumaMMa and its dependencies will be downloaded and built
cd /tmp
rm -rf numamma-build
mkdir numamma-build
cd numamma-build

# numactl for numap
git clone git@github.com:numactl/numactl.git
cd numactl
git co v2.0.11
./autogen.sh
./configure --prefix=/tmp/numamma-build/numactl/install-release
make -j4 install
cd ..

# libpfm for numap
git clone https://git.code.sf.net/p/perfmon2/libpfm4 libpfm4
cd libpfm4
git co v4.9.0
make PREFIX=/tmp/numamma-build/libpfm4/install-release -j4 install
cd ..

# numap for numamma
git clone git@github.com:numap-library/numap.git
cd numap
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/tmp/numamma-build/numap/install-release \
      -DNUMACTL_DIR=/tmp/numamma-build/numactl/install-release \
      -DPFM_DIR=/tmp/numamma-build/libpfm4/install-release \
      ..
make -j4 install
cd ../..

# backtrace for numamma
git clone git@github.com:ianlancetaylor/libbacktrace.git
cd libbacktrace
git co 177940370e4a6b2509e92a0aaa9749184e64af43
./configure --prefix=/tmp/numamma-build/libbacktrace/install-release
make -j4 install
cd install-release/include
mkdir libbacktrace
mv backtrace.h  backtrace-supported.h libbacktrace
cd ../../..

# numamma
git clone git@github.com:numamma/numamma.git
cd numamma
mkdir build
cd build
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/tmp/numamma-build/numap/install-release/lib/pkgconfig
cmake -DCMAKE_INSTALL_PREFIX=/tmp/numamma-build/numamma/install-release \
      -DBACKTRACE_DIR=/tmp/numamma-build/libbacktrace/install-release \
      -DNUMACTL_DIR=/tmp/numamma-build/numactl/install-release \
       ..
make -j4 install
cd ../..

```

## Content of this repository

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
