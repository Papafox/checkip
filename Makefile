# Copyright (c) 2015 Matthew Donald
# All rights reserved
# Licensed under GPL v3

PROG = checkip
LIBS=-lm -lpcre -lssl
CFLAGS = -W -Wall -O0 $(CFLAGS_EXTRA)
CFLAGS_EXTRA =  -DNS_ENABLE_IPV6 -DNS_ENABLE_SSL -DMONGOOSE_NO_FILESYSTEM
SOURCES = src/$(PROG).c src/mongoose.c src/pidfile.c src/log_msg.c src/netif_addr.c src/validip.c

$(PROG): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(PROG) $(LIBS)

