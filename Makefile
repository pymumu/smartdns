
BIN=smartdns 
OBJS=smartdns.o fast_ping.o lib/bitops.o dns_client.o
CFLAGS=-g -O0 -Wall
CFLAGS +=-Iinclude
CXXFLAGS=-g -O0 -Wall -std=c++11
CXXFLAGS +=-Iinclude

.PHONY: all

all: $(BIN)

$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ -lpthread

clean:
	$(RM) $(OBJS) $(BIN)