#!/bin/bash

# by default, build/install everything in the current directory
ROOT_DIR=$PWD

if [ "$1" == "-h" ]; then
  echo "Usage: `basename $0` absolute/path/to/build_and_install/dir/"
  exit 0
fi

if [ $# -ne 0 ]; then

    if [[ "$1" = /* ]]; then
	# you can also pass a prefix
	ROOT_DIR=$1
    else
	echo "Build and installation directory must be an absolute path"
	exit 0
    fi
fi

ROOT_INSTALL_DIR=$ROOT_DIR/install

mkdir -p $ROOT_INSTALL_DIR

#libbacktrace
LIBBACKTRACE_ROOT=$ROOT_DIR/libbacktrace
LIBBACKTRACE_INSTALL_ROOT=$ROOT_INSTALL_DIR/libbacktrace

if ! [ -d $LIBBACKTRACE_INSTALL_ROOT ]; then
    echo "Installing libbacktrace..."
    rm -rf $LIBBACKTRACE_ROOT 
    git clone git@github.com:ianlancetaylor/libbacktrace.git $LIBBACKTRACE_ROOT|| exit 1
    cd $LIBBACKTRACE_ROOT || exit 1

    # any version should work, but to be sure, specify a revision that was tested
    git checkout 177940370e4a6b2509e92a0aaa9749184e64af43 || exit 1
    ./configure --prefix=$LIBBACKTRACE_INSTALL_ROOT || exit 1
    make -j4 install|| exit 1
    cd $LIBBACKTRACE_INSTALL_ROOT/include|| exit 1
    mkdir $LIBBACKTRACE_INSTALL_ROOT/include/libbacktrace|| exit 1
    mv $LIBBACKTRACE_INSTALL_ROOT/include/backtrace.h  $LIBBACKTRACE_INSTALL_ROOT/include/backtrace-supported.h $LIBBACKTRACE_INSTALL_ROOT/include/libbacktrace|| exit 1
else
    echo "libbacktrace is already installed"
fi

#libpfm-4.8.0
PFM_ROOT=$ROOT_DIR/libpfm-4.8.0
PFM_INSTALL_ROOT=$ROOT_INSTALL_DIR/libpfm-4.8.0

if ! [ -d $PFM_INSTALL_ROOT ]; then
    echo "Installing libpfm..."
    rm -rf $PFM_ROOT
    git clone https://git.code.sf.net/p/perfmon2/libpfm4 $PFM_ROOT || exit 1
    cd $PFM_ROOT || exit 1
    git checkout v4.9.0 || exit 1
    make PREFIX=$PFM_INSTALL_ROOT -j4 install || exit 1
else
    echo "libpfm is already installed"
fi

#numactl-2.0.11
NUMACTL_ROOT=$ROOT_DIR/numactl-2.0.11
NUMACTL_INSTALL_ROOT=$ROOT_INSTALL_DIR/numactl-2.0.11

if ! [ -d $NUMACTL_INSTALL_ROOT ]; then
    echo "Installing numactl..."

    rm -rf $NUMACTL_ROOT || exit 1
    git clone git@github.com:numactl/numactl.git $NUMACTL_ROOT || exit 1
    cd $NUMACTL_ROOT  || exit 1
    git checkout v2.0.11 || exit 1
    ./autogen.sh || exit 1
    mkdir build || exit 1
    cd build

    ../configure --prefix=$NUMACTL_INSTALL_ROOT || exit 1
    make || exit 1
    make install || exit 1
else
    echo "numactl is already installed"
fi

#numap
NUMAP_ROOT=$ROOT_DIR/numap
NUMAP_INSTALL_ROOT=$ROOT_INSTALL_DIR/numap
if ! [ -d $NUMAP_INSTALL_ROOT ]; then
    echo "Installing numap..."
    rm -rf $NUMAP_ROOT || exit 1

    git clone https://github.com/numap-library/numap.git $NUMAP_ROOT || exit 1
    cd $NUMAP_ROOT  || exit 1
    mkdir build || exit 1
    cd build
    cmake  -DCMAKE_INSTALL_PREFIX=$NUMAP_INSTALL_ROOT -DPFM_DIR=$PFM_INSTALL_ROOT -DNUMACTL_DIR=$NUMACTL_INSTALL_ROOT  $NUMAP_ROOT || exit 1
    make || exit 1
    make install || exit 1
else
    echo "numap is already installed"
fi

#numamma
NUMAMMA_ROOT=$ROOT_DIR/numamma
NUMAMMA_INSTALL_ROOT=$ROOT_INSTALL_DIR/numamma
if ! [ -d  $NUMAMMA_INSTALL_ROOT ]; then
    echo "Installing numamma..."
    rm -rf $NUMAMMA_ROOT || exit 1
    git clone https://github.com/numamma/numamma.git $NUMAMMA_ROOT || exit 1
    cd $NUMAMMA_ROOT || exit 1
    mkdir build || exit 1
    cd build || exit 1
    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$NUMAP_INSTALL_ROOT/lib/pkgconfig
    cmake  -DCMAKE_INSTALL_PREFIX=$NUMAMMA_INSTALL_ROOT -DBACKTRACE_DIR=$LIBBACKTRACE_INSTALL_ROOT -DNUMACTL_DIR=$NUMACTL_INSTALL_ROOT  $NUMAMMA_ROOT || exit 1
    make || exit 1
    make install || exit 1
else
    echo "numamma is already installed"
fi
   
