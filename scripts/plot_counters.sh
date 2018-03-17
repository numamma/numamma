#!/bin/bash

input=$1
output=$1.png

gnuplot <<EOF
set terminal png
set output "$output"
set xtics 1
set xrange  [-0.5:]
set yrange  [-0.5:]
set logscale cb
plot "$input" matrix with image title ""
EOF
