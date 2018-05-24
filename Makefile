INCS = $(shell pkg-config ldns --cflags)
LIBS = $(shell pkg-config ldns --libs)

CXXFLAGS = -g -O0 -std=c++11 -Wall -Werror -Wno-error=pragmas $(INCS) -D_POSIX_SOURCE
LDFLAGS =

BIN = lightning
COMMON_OBJS = zone.o timer.o datafile.o query.o util.o
LIBS += -lresolv

.PHONY:	all clean

all: $(BIN)

$(BIN):	main.o packet.o server.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

benchmark: benchmark.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o

# dependencies
server.o:	buffer.h
