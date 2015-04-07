# Copyright (c) 2015 Matthew Donald
# All rights reserved
# Licensed under GPL v3

PROG = checkip
LIBS=-lm -lpcre -lssl
CFLAGS = -W -Wall -O0 $(LIBS) $(CFLAGS_EXTRA)
SOURCES = src/$(PROG).c src/mongoose.c src/pidfile.c src/region_locking.c

$(PROG): $(SOURCES)
	$(CC) -o $(PROG) $(SOURCES) $(CFLAGS)

