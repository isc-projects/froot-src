INCS = $(shell pkg-config ldns --cflags)
LIBS = $(shell pkg-config ldns --libs)

CXXFLAGS = -O3 -std=c++11 -Wall -Werror -Wno-error=pragmas $(INCS)
LDFLAGS =

BIN = lightning
OBJS = server.o zone.o packet.o response.o timer.o datafile.o query.o util.o
LIBS += -lresolv

.PHONY:	all clean

all: $(BIN)

$(BIN):	main.o $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

benchmark: benchmark.o $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o
