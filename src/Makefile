
BIN=smartdns 
OBJS_LIB=lib/rbtree.o lib/art.o lib/bitops.o
OBJS=smartdns.o fast_ping.o dns_client.o dns_server.o dns.o util.o tlog.o conf.o dns_cache.o $(OBJS_LIB)
CFLAGS=-g -O0 -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing 
CFLAGS +=-Iinclude
CFLAGS += -DBASE_FILE_NAME=\"$(notdir $<)\"
CXXFLAGS=-g -O0 -Wall -std=c++11 
CXXFLAGS +=-Iinclude
LDFLAGS += -lpthread 

.PHONY: all

all: $(BIN)
 
$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(BIN)
