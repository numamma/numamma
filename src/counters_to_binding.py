#!/usr/bin/env python2

import sys;
input_file=open(sys.argv[1], "r")
nb_nodes=int(sys.argv[2]);
name=sys.argv[3];
buffer_size=sys.argv[4];
threshold=3;

line_no=0
# first, read the file and count the number of memory access per numa node
counters=[];
for line in input_file:
    line_split=line.split();
    N_threads=len(line_split);
    threads_per_node=N_threads/nb_nodes;
    counters.append([0]*nb_nodes);
    for th in range(N_threads):
        numa_node=th / threads_per_node;
        counters[line_no][numa_node]=counters[line_no][numa_node]+int(line_split[th]);

#    print counters[line_no];
    line_no=line_no+1;

nb_lines=line_no;

prev_node=-1
cur_block=0
block_counters=0
block_str=""

blocks=[];
nblocks=-1

# create "blocks"
for line in counters:
    cur_node_counter=max(line);
    cur_node=line.index(cur_node_counter);

    if cur_node_counter != 0 and cur_node != prev_node and cur_node_counter > threshold:
        if prev_node != -1:
            b=blocks[nblocks];
            b["end_page"]=cur_block;
            b["counters"]=block_counters;
            density=b["counters"]/(b["end_page"]-b["start_page"]);
            if density <= 1:
                nblocks=nblocks -1;


        blocks.append({});
        nblocks=nblocks+1;
        blocks[nblocks]["node"]=cur_node;
        blocks[nblocks]["start_page"]=cur_block;

        block_counters=0;
        prev_node=cur_node;

    block_counters=block_counters + cur_node_counter;
    cur_block=cur_block+1;

# finish the last block
blocks[nblocks]["end_page"]=cur_block;
blocks[nblocks]["counters"]=block_counters;

print "begin_block";
print name+" "+buffer_size+" "+str(nblocks+1);
for b in blocks:
    if b :
        print str(b["node"])+" "+str(b["start_page"])+" "+str(b["end_page"])+" "+str(b["counters"]);
print "end_block";
