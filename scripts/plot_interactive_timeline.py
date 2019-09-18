#!/usr/bin/python3
import pandas as pd
import plotly.express as px
import sys

print( "Number of arguments: ", len(sys.argv))

#load the data
df = pd.read_csv(sys.argv[1], delimiter=' ')

#convert timestamps to second since the first memory access
df['timestamp']=(df['timestamp']-min(df['timestamp']))/1e9
start_time = min(df['timestamp'])
end_time = max(df['timestamp'])
# set the access_weight to 1 to all the line with access_weight=0
#df['access_weight']=df.loc[df['access_weight'==0]]=1
df.loc[df['access_weight'] == 0,"access_weight"]=1
df.loc[df['access_weight'] > 200,"access_weight"]=200
print("start_time:"+str(start_time));
print("end_time:"+str(end_time));

fig = px.scatter(df, x='timestamp', y='offset', color='#thread_rank', size='access_weight')
fig.show()
