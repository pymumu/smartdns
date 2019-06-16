
BIN=smartdns 
OBJS_LIB=lib/rbtree.o lib/art.o lib/bitops.o lib/radix.o lib/conf.o
OBJS=smartdns.o fast_ping.o dns_client.o dns_server.o dns.o util.o tlog.o dns_conf.o dns_cache.o http_parse.o $(OBJS_LIB)
CFLAGS +=-O2 -g -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing 
CFLAGS +=-Iinclude
CFLAGS += -DBASE_FILE_NAME=\"$(notdir $<)\"
CXXFLAGS=-O2 -g -Wall -std=c++11 
CXXFLAGS +=-Iinclude
ifeq ($(STATIC), yes)
LDFLAGS += -lssl -lcrypto -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldl -static
else
LDFLAGS += -lssl -lcrypto -lpthread 
endif

.PHONY: all

all: $(BIN)
 
$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(BIN)
