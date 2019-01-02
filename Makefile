UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
  LDNSPKG := libldns
else
  LDNSPKG := ldns
  BIN := lightning
endif

INCS = $(shell pkg-config $(LDNSPKG) --cflags)
LIBS = $(shell pkg-config $(LDNSPKG) --libs)

CXXFLAGS := $(CFLAGS)
CXXFLAGS += -O3 -g -std=c++14 -Wall -Werror -Wno-error=pragmas $(INCS)
LDFLAGS =

BIN += fuzz_packet fuzz_zone lightbench
COMMON_OBJS = context.o zone.o answer.o rrlist.o util.o
NETSERVER_SRCS = $(wildcard netserver/*.cc)
NETSERVER_OBJS = $(NETSERVER_SRCS:.cc=.o)

.PHONY:	all clean

all:		lightning

tests:		lightbench fuzz_packet fuzz_zone

lightning:	main.o server.o thread.o $(NETSERVER_OBJS) $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS) -lpthread

fuzz_packet:	fuzz_packet.o server.o thread.o $(NETSERVER_OBJS) $(COMMON_OBJS)
	afl-$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS) -lpthread

fuzz_zone:	fuzz_zone.o server.o thread.o $(NETSERVER_OBJS) $(COMMON_OBJS)
	afl-$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS) -lpthread

lightbench:	 lightbench.o queryfile.o timer.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS) -lresolv

clean:
	$(RM) $(BIN) *.o netserver/*.o

.cc.s:
	$(CXX) -S $^ $(CXXFLAGS) $(CPPFLAGS)

install:	lightning
	/usr/bin/install -s -m 0755 lightning /usr/local/sbin
	/usr/bin/chcon -t bin_t /usr/local/sbin/lightning
	/usr/sbin/setcap cap_net_raw=+ep /usr/local/sbin/lightning

# dependencies
answer.o:	answer.h util.h
lightbench.o:	context.h zone.h queryfile.h timer.h
context.o:	context.h zone.h util.h
main.o:		server.h
queryfile.o:	queryfile.h util.h
rrlist.o:	rrlist.h
server.o:	server.h context.h util.h
timer.o:	timer.h
util.o:		util.h
zone.o:		context.h zone.h util.h

answer.h:	buffer.h rrlist.h
context.h:	buffer.h answer.h zone.h
server.h:	zone.h
zone.h:		answer.h
