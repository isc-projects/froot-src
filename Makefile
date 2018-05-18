INCS = $(shell pkg-config ldns --cflags)
LIBS = $(shell pkg-config ldns --libs)

CXXFLAGS = -O0 -std=c++11 -Wall -Werror -Wno-error=pragmas $(INCS)
LDFLAGS =

BIN = root-server
OBJS = main.o server.o zone.o timer.o datafile.o query.o util.o
LIBS += -lresolv

.PHONY:	all clean

all: $(BIN)

$(BIN):	$(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o
