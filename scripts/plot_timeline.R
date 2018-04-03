#!/usr/bin/R

# Input file parameter
args<-commandArgs(TRUE)
input_file=args[1]

# Read input file, rename columns, change type
data<-read.table(input_file, sep=" ", colClasses="character")
names(data)<-c("Thread", "timestamp", "addr", "offset")
data["offset"]=lapply(data["offset"], function(x) {as.numeric(x);})
data["timestamp"]=lapply(data["timestamp"], function(x) {as.numeric(x);})

# Output file parameter
if(length(args)>1){
  output_file=args[2];
} else {
  output_file=paste(input_file,".png", sep="")
}

# Horizontal lines parameter
oneMiB=1024*1024
if(length(args)>2){
    hlinesP = as.integer(args[3]);
    hlinesMiB = oneMiB * hlinesP
    max_offset = range(data["offset"])[2]
    graduations = seq(0, max_offset, hlinesMiB)
    customLabels = graduations / oneMiB
    #customLabels = lapply(customLabels, function(x) {paste(x, " MiB");})
}

# Vertical lines parameter
oneSec = 1E9
vlinesP = oneSec
if(length(args)>3){
    vlinesP = as.integer(args[4]);
} 

# Part of the trace to plot parameter:
# 1 is all, 0.5 is first half
partx=1
if(length(args)>4){
  partx=as.numeric(args[5]);
}

# Update timestamp values such that it starts at 0
tsRange = range(data["timestamp"]) 
minTs = tsRange[1]
data["timestamp"] = lapply(data["timestamp"], function(x) {x-minTs;})
tsRange = range(data["timestamp"])
stopifnot(tsRange[1] == 0)

# Extract partx % of the data on the x axis
tsRangeLength = tsRange[2] - tsRange[1]
newMaxTs = tsRangeLength * partx
newTsRange = c(tsRange[1], tsRange[1] + newMaxTs)

# Set time ticks and ticks labels
print(newTsRange[2])
oneSec = 1E9
timeGraduations = seq(newTsRange[1], newTsRange[2], vlinesP)
print(timeGraduations)
customTimeLabels = timeGraduations / oneSec
print(customTimeLabels)

# Plot the data and save into file
require(ggplot2)
p1<-qplot(data = data,
          x = timestamp,
          y = offset,
          colour = Thread,
          size = I(0.5), # size of the dots
          ylab = "Offset (MiB)",
          xlab = "Time (second)")#,
          #xlim = newTsRange)
p1 = p1 + scale_x_continuous(breaks=timeGraduations, labels=customTimeLabels)
if (exists("customLabels")) {
    p1 = p1 + scale_y_continuous(breaks=graduations, labels=customLabels)
}
ggsave(output_file, plot = p1)
