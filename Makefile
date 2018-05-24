UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
  LDNSPKG := libldns
else
  LDNSPKG := ldns
endif

INCS = $(shell pkg-config $(LDNSPKG) --cflags)
LIBS = $(shell pkg-config $(LDNSPKG) --libs)

CXXFLAGS = -g -O0 -std=c++11 -Wall -Werror -Wno-error=pragmas $(INCS) -D_POSIX_SOURCE
LDFLAGS =

BIN = lightning
COMMON_OBJS = server.o zone.o timer.o datafile.o query.o util.o
LIBS += -lresolv

.PHONY:	all clean

all: $(BIN)

$(BIN):	main.o packet.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

benchmark: benchmark.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o

# dependencies
server.o:	buffer.h
