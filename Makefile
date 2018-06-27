UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
  LDNSPKG := libldns
else
  LDNSPKG := ldns
  BIN := lightning
endif

INCS = $(shell pkg-config $(LDNSPKG) --cflags)
LIBS = $(shell pkg-config $(LDNSPKG) --libs)

CXXFLAGS = -O3 -g -std=c++14 -Wall -Werror -Wno-error=pragmas $(INCS)
LDFLAGS =

BIN += lightbench
COMMON_OBJS = context.o zone.o answer.o rrlist.o util.o
LIBS += -lpthread -lresolv

.PHONY:	all clean

all: $(BIN)

lightning:	main.o server.o packet.o checksum.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

lightbench:	 lightbench.o queryfile.o timer.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o

.cc.s:
	$(CXX) -S $^ $(CXXFLAGS) $(CPPFLAGS)

# dependencies
answer.o:	answer.h util.h
lightbench.o:	context.h zone.h queryfile.h timer.h
context.o:	context.h zone.h util.h
main.o:		server.h
packet.o:	packet.h util.h
queryfile.o:	queryfile.h util.h
rrlist.o:	rrlist.h
server.o:	server.h context.h util.h
timer.o:	timer.h
util.o:		util.h
zone.o:		context.h zone.h util.h

answer.h:	buffer.h rrlist.h
context.h:	buffer.h answer.h zone.h
server.h:	zone.h packet.h
zone.h:		answer.h
