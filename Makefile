UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
  LDNSPKG := libldns
else
  LDNSPKG := ldns
endif

INCS = $(shell pkg-config $(LDNSPKG) --cflags)
LIBS = $(shell pkg-config $(LDNSPKG) --libs)

CXXFLAGS = -g -O3 -std=c++11 -Wall -Werror -Wno-error=pragmas $(INCS) -D_POSIX_SOURCE
LDFLAGS =

BIN = lightning benchmark
COMMON_OBJS = server.o packet.o zone.o util.o
LIBS += -lresolv

.PHONY:	all clean

all: $(BIN)

lightning:	main.o packet.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

benchmark:	 benchmark.o datafile.o query.o timer.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o

# dependencies
benchmark.o:	server.h datafile.h buffer.h timer.h
datafile.o:	datafile.h util.h
main.o:		server.h
packet.o:	packet.h util.h
query.o:	query.h
server.o:	server.h util.h
timer.o:	timer.h
util.o:		util.h
zone.o:		zone.h util.h

datafile.h:	query.h
server.h:	zone.h packet.h buffer.h
zone.h:		buffer.h
