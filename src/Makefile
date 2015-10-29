#*******************************************************************
# kyoscand - Kyocera Scan System F PC Daemon
#
# (C) Copyright 2006 by Pavel Pisa - Originator
#
# The kyoscand is distributed under the Gnu General Public License. 
# See file COPYING for details.
#
#*******************************************************************

all : depend default

default : kyoscand

.PHONY : default clean install

# Select compiler
CC=gcc

# Basic compilation flags
override CFLAGS += -I.
CFLAGS += -Wall -Wstrict-prototypes 
CFLAGS += -O2
CFLAGS += -ggdb
CFLAGS += -pthread
#CFLAGS += -pg
#CFLAGS += -std=c99
#CFLAGS += -std=gnu99 -DWITH_C99

override LDFLAGS += -lpthread
override LDFLAGS += -pthread

DESTDIR ?=
prefix ?= /usr
bindir ?= $(prefix)/bin
datarootdir ?= ${prefix}/share
datadir ?= ${datarootdir}/kyoscand
sysconfdir ?= /etc

depend: *.c *.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -w -E -M *.c $(MORE_C_FILES) | \
	sed 's/^\([^:]*\)\.o *:/\1.o \1.lo:/g' > depend

clean :
	rm -f depend *.o *.lo *~ *.a *.so *.so.* kyoscand

kyoscand: kyoscand.o ul_logbase.o

#-o root -g root
install: all
	install -m 0755 -d $(DESTDIR)$(bindir)
	install -m 0755 -t $(DESTDIR)$(bindir) kyoscand

check:

-include depend
