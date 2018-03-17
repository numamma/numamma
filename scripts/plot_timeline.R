#!/usr/bin/R

args<-commandArgs(TRUE)
input_file=args[1]

if(length(args)>1){
  output_file=args[2];
} else {
  output_file=paste(input_file,".png", sep="")
}

partx=1
if(length(args)>2){
  partx=as.numeric(args[3]);
}

data<-read.table(input_file, sep=" ", colClasses="character")

# rename columns
names(data)<-c("cpu", "timestamp", "addr", "offset")

#data["offset"]=lapply(data["offset"], function(x) {as.integer(x);})
data["offset"]=lapply(data["offset"], function(x) {as.numeric(x);})
data["timestamp"]=lapply(data["timestamp"], function(x) {as.numeric(x);})

max_offset=range(data["offset"])[2]
graduations=seq(0, max_offset, 20971520)
labels=graduations/(2097152/2)

min_ts=range(data["timestamp"])[1]
data["timestamp"]=lapply(data["timestamp"], function(x) {x-min_ts;})

limx=c(range(data["timestamp"])[1], range(data["timestamp"])[2])
# extract partx % of the data on the x axis
xrange=(limx[2]-limx[1])
xrange=xrange*partx
limx[2]=limx[1]+xrange

labels=lapply(labels, function(x) {paste(x, " MB");})

require(ggplot2)
#library(scales)

p1<-qplot(data=data, x=timestamp, y=offset, colour=cpu, size=I(0.5), xlab="timestamp", xlim=limx)+
		     theme(axis.text.x = element_blank(), legend.position="none") +
		     scale_y_continuous(breaks=graduations, labels=labels)+
		     geom_hline(yintercept = graduations)

ggsave(output_file, plot = p1)
