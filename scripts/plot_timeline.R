#!/usr/bin/R

require(ggplot2)

# Input file parameter
args<-commandArgs(TRUE)
input_file=args[1]

# Read input file, rename columns, change type
data <- read.table(input_file, sep=" ", colClasses="character")
names(data) <- c("Thread", "timestamp", "addr", "offset")
data["offset"] = lapply(data["offset"], function(x) {as.numeric(x);})
data["timestamp"] = lapply(data["timestamp"], function(x) {as.numeric(x);})

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

# Divide timestamp by parameter
div = 1
if(length(args)>5){
    div = as.numeric(args[6]);
    data["timestamp"] = lapply(data["timestamp"], function(x) {x/div;})
}

# Do modulo on thread ids
if(length(args)>6){
    modulo = as.numeric(args[7]);
    data["Thread"]=lapply(data["Thread"], function(x) {as.integer(x)%%modulo;})
    data["Thread"]=lapply(data["Thread"], function(x) {as.character(x);})
}

# Update timestamp values such that it starts at 0
tsRange = range(data["timestamp"]) 
minTs = tsRange[1]
data["timestamp"] = lapply(data["timestamp"], function(x) {x-minTs;})
tsRange = range(data["timestamp"])
stopifnot(tsRange[1] == 0)

# Extract partx % of the data on the x axis
tsRangeLength = tsRange[2] - tsRange[1]
print(paste0("Total execution time in seconds = ", tsRange[2] * div / 1E9))
newMaxTs = tsRangeLength * partx
newTsRange = c(tsRange[1], tsRange[1] + newMaxTs)
print(paste0("View execution time in seconds = ", newTsRange[2] * div / 1E9))

# Set time ticks and ticks labels
timeGraduations = seq(newTsRange[1], newTsRange[2], vlinesP)
print(timeGraduations)
customTimeLabels = timeGraduations / oneSec * div

# Plot the data and save into file
p1 <- qplot(data = data,
          x = timestamp,
          y = offset,
          colour = Thread,
          size = I(0.5), # size of the dots
          ylab = "Offset (MiB)",
          xlab = "Time (second)")
threadAsNum <- lapply(data["Thread"], function(x) {as.numeric(x);})
maxThread = range(threadAsNum)[2]
p1 = p1 + scale_color_discrete(breaks=seq(0, as.integer(maxThread), 1))
#p1 = p1 + theme(legend.position="none")
p1 = p1 + scale_x_continuous(breaks=timeGraduations, labels=customTimeLabels, lim=newTsRange)
if (exists("customLabels")) {
    p1 = p1 + scale_y_continuous(breaks=graduations, labels=customLabels)
}
ggsave(output_file, plot = p1)
