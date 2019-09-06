CC=gcc 
LDFLAGS= -lpcap  
CFLAGS= -Wall -g
SOURCE= mysql-sniffer.c mysql.c
OBJS=$(SOURCE:.cc=.o)
TARGET= mysql-sniffer

.c.o:
	$(CC) $(CFLAGS) $< -o $@

all: release

x:
	./mysql-sniffer -i lo

d:
	jdebug=true ./mysql-sniffer -i lo

release: $(OBJS)
	$(CC)  -o $(TARGET) $^ $(LDFLAGS)


clean:
	rm -f  *.o  $(TARGET)

