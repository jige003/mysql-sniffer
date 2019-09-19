CXX = g++
CC = gcc
LDFLAGS= -lpcap
CFLAGS= -Wall -g
CXXFLAGS= -Wall -g -std=c++11
CSOURCE=$(wildcard ./*.c)
CXXSOURCE=$(wildcard ./*.cxx)
COBJS=$(CSOURCE:.c=.o)
CXXOBJS=$(CXXSOURCE:.cxx=.o)
TARGET= sniffer

all: release

$(COBJS) : %.o : %.c
	$(CC) -c $< -o $@ $(CFLAGS)

$(CXXOBJS) : %.o: %.cxx
	$(CXX) -c $< -o $@ $(CXXFLAGS)

release: $(COBJS) $(CXXOBJS)
	$(CXX) -o $(TARGET) $^ $(LDFLAGS)

clean:
	rm -f  *.o  $(TARGET) 

d:
	 jdebug=true ./$(TARGET) -i eth0
