#!/usr/bin/R

args<-commandArgs(TRUE)
data<-read.table(args[1], sep=" ", colClasses="character")

# rename columns
names(data)<-c("cpu", "ip", "addr", "offset")

#data["offset"]=lapply(data["offset"], function(x) {as.integer(x);})
data["offset"]=lapply(data["offset"], function(x) {as.numeric(x);})
data["ip"]=lapply(data["ip"], function(x) {as.numeric(x);})
max_offset=range(data["offset"])[2]
graduations=seq(0, max_offset, 20971520)
labels=graduations/(2097152/2)

labels=lapply(labels, function(x) {paste(x, " MB");})

require(ggplot2)
#library(scales)

p1<-qplot(data=data, x=ip, y=offset, colour=cpu, size=I(0.5), xlab="timestamp")+
		     theme(axis.text.x = element_blank(), legend.position="none") +
		     scale_y_continuous(breaks=graduations, labels=labels)+
		     geom_hline(yintercept = graduations)

ggsave(args[2], plot = p1)
