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

# each block should have at least density_threshold access per page
density_threshold=8

#print "Start creating blocks"

# create "blocks"
for line in counters:
    cur_node_counter=max(line);
    cur_node=line.index(cur_node_counter);

    if cur_node_counter > density_threshold:
        # the current block has many accesses
        if prev_node != cur_node:
            # start a new block
            blocks.append({});
            nblocks=nblocks+1;
            b=blocks[nblocks];
            b["node"]=cur_node;
            b["start_page"]=cur_block;
            b["end_page"]=cur_block;
            b["counters"]=cur_node_counter;
            b["density"]=b["counters"]/(1+b["end_page"]-b["start_page"]);
            prev_node=cur_node;
#            print "New block"+str(nblocks)+": " +str(b["node"])+" "+str(b["start_page"])+" "+str(b["end_page"])+" "+str(b["counters"])+" -- density:"+str(b["density"]);
        else:
        # add the current page with the current block
            b=blocks[nblocks];
            b["end_page"]=cur_block;
            b["counters"]=cur_node_counter+b["counters"];
            b["density"]=b["counters"]/(1+b["end_page"]-b["start_page"]);
 #           print "Update block "+str(nblocks)+": " +str(b["node"])+" "+str(b["start_page"])+" "+str(b["end_page"])+" "+str(b["counters"])+" -- density:"+str(b["density"]);

#    else: # cur_node_counter > density_threshold
#        if cur_node_counter == 0 or cur_node == prev_node:
#            # the current page has few accesses, but maybe we can merge it with the current block ?
#            density=(b["counters"]+cur_node_counter)/(1+cur_block-b["start_page"]);
#            if density > density_threshold:
#                # add the current page to the current block
#                b=blocks[nblocks];
#                b["end_page"]=cur_block;
#                b["counters"]=cur_node_counter;
#                b["density"]=b["counters"]/(1+b["end_page"]-b["start_page"]);
        cur_block=cur_block+1;

if nblocks > 0:
    print "begin_block";
    print name+" "+buffer_size+" "+str(nblocks+1);
    for b in blocks:
        if b :
            print str(b["node"])+" "+str(b["start_page"])+" "+str(b["end_page"])+" "+str(b["counters"]);
    print "end_block";
