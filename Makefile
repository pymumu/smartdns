
BIN=smartdns 
OBJS=smartdns.o fast_ping.o 
CFLAGS=-g -O0
CFLAGS=-Iinclude

.PHONY: all

all: $(BIN)

$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ -lpthread

clean:
	$(RM) $(OBJS) $(BIN)