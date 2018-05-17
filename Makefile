INCS = $(shell pkg-config libldns --cflags)
LIBS = $(shell pkg-config libldns --libs)

CXXFLAGS = -O3 -std=c++11 -Wall -Werror $(INCS)
LDFLAGS =

BIN = root-server
OBJS = main.o zone.o timer.o datafile.o query.o util.o
LIBS += -lresolv

.PHONY:	all clean

all: $(BIN)

$(BIN):	$(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(BIN) *.o
