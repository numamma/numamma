LDFLAGS=-ldl
CFLAGS=-g

NUMAP_PREFIX=$(HOME)/Soft/opt/numap/
CFLAGS+=-I$(NUMAP_PREFIX)/include
LDFLAGS+=-L$(NUMAP_PREFIX) -lnumap

all: libmemory.so

libmemory.so: memory.o mem_analyzer.o
	$(CC) -shared -o libmemory.so memory.o mem_analyzer.o $(LDFLAGS)

memory.o: memory.c
	$(CC) -c memory.c -fPIC $(CFLAGS)

mem_analyzer.o: mem_analyzer.c
	$(CC) -c mem_analyzer.c -fPIC $(CFLAGS)

clean:
	rm -f libmemory.so memory.o mem_analyzer.o


