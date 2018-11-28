VPATH = ../
EXEC = ulog-dbacctd

# Uncomment to make gcc search kernel source tree for includes
# (You may need to change the directory to match the location
# of your kernel sources.)
#KERNELDIR = -I/usr/src/linux-2.4/include

# Configuration options
# Uncomment for debugging output
#DEBUG += -g

# For profiling
#DEBUG += -pg -a -fprofile-arcs

# Disable for debugging
OPT = -O2

CFLAGS += -Wall -Wstrict-prototypes $(OPT) $(DEBUG) $(KERNELDIR)
OBJECTS = main.o daemon.o process.o utils.o config.o capture.c dbase.c iphash.o
DISTSRC = ChangeLog Makefile capture.c config.c daemon.c main.c  ulog-acct.h process.c utils.c iphash.c iphash.h
CC = gcc

# POSTGRESQL
CFLAGS += -DPOSTGRES -I/usr/include/pgsql
LIBS += -lpq

# MYSQL
#CFLAGS += -DMY -I/usr/include/mysql
#LIBS += -L/usr/lib/mysql -lmysqlclient -lz

all:	$(EXEC)

depend dep:
	for i in *.c;do $(CPP) -M $$i;done > .tmpdepend
	mv .tmpdepend .depend

$(EXEC):	$(OBJECTS)
		$(CC) -o $(EXEC) $(CFLAGS) $^ $(LIBS)

clean:
	rm -f *.o $(EXEC)

testconf: testconf.o config.o
	$(CC) -o testconf testconf.o config.o utils.o

ifeq (.depend,$(wildcard .depend))
include .depend
endif
