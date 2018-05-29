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
COMMON_OBJS = context.o parser.o zone.o util.o
LIBS += -lresolv

.PHONY:	all clean

all: $(BIN)

lightning:	main.o server.o packet.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

benchmark:	 benchmark.o queryfile.o timer.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o

# dependencies
benchmark.o:	zone.h queryfile.h parser.h timer.h
context.o:	context.h
main.o:		server.h
packet.o:	packet.h util.h
parser.o:	parser.h
queryfile.o:	queryfile.h util.h
server.o:	server.h parser.h util.h
timer.o:	timer.h
util.o:		util.h
zone.o:		zone.h util.h

parser.h:	zone.h buffer.h
server.h:	zone.h packet.h
zone.h:		buffer.h
