#!/usr/bin/Rscript

library(ggplot2)
library(reshape2)
library(dplyr)

#Function to get default color palette
gg_color_hue <- function(n) {
  hues = seq(15, 375, length = n + 1)
  hcl(h = hues, l = 65, c = 100)[1:n]
}

# Input file parameter
args<-commandArgs(TRUE)
input_file=args[1]

# Output file parameter
if(length(args)>1){
  output_file=args[2];
} else {
  output_file=paste(input_file,".png", sep="")
}

d <- read.table(input_file)
names(d) <- c("Thread 0", "Thread 1", " Thread 2", " Thread 3")
d$page <- 1:nrow(d)

t <- melt(d, id.vars=c("page"))

# Plot the data and save into file
p1 <- ggplot(data=t,
             aes(x = variable,
                 y = page,
                 fill = value)
             ) +
    ylab("Page number") +
    geom_tile() +  
    scale_fill_gradient(high = "white", low = "darkblue", trans="log1p", 
                        name = "Number of\naccesses", breaks=c(0, 20, 2000)) +
    theme(legend.direction = "vertical",
          legend.position = "right",
          legend.title.align = 1.2,
          axis.title.x = element_blank(),
          axis.text.x = element_text(color=gg_color_hue(4))
    ) 
        
    # + guides(fill=guide_legend())
ggsave(output_file, plot = p1)
