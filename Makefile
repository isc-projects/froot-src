PREFIX = /usr/local
BIN := froot

LDNSPKG := $(shell pkg-config --list-package-names | egrep '^(lib)?ldns' )
INCS := $(shell pkg-config $(LDNSPKG) --cflags)
LIBS := $(shell pkg-config $(LDNSPKG) --libs)

LDFLAGS =
CPPFLAGS = -iquote src/include -iquote src -DPREFIX="$(PREFIX)"
CXXFLAGS := $(CFLAGS)
CXXFLAGS += -O3 -g -std=c++14 -Wall -Werror $(INCS)
LIBS += -lpthread

COMMON_SRCS = src/context.cc src/zone.cc src/answer.cc src/rrlist.cc src/timer.cc src/util.cc
COMMON_OBJS = $(COMMON_SRCS:.cc=.o)

NETSERVER_SRCS = $(wildcard src/netserver/*.cc)
NETSERVER_OBJS = $(NETSERVER_SRCS:.cc=.o)

.PHONY:	all clean install

all:		froot

tests:		tests/frootbench tests/fuzz_packet tests/fuzz_zone

froot:		src/main.o src/server.o src/thread.o $(NETSERVER_OBJS) $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

tests/fuzz_packet:	tests/fuzz_packet.o src/server.o src/thread.o $(NETSERVER_OBJS) $(COMMON_OBJS)
	afl-$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

tests/fuzz_zone:	tests/fuzz_zone.o src/server.o src/thread.o $(NETSERVER_OBJS) $(COMMON_OBJS)
	afl-$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS)

tests/frootbench:	tests/frootbench.o tests/queryfile.o tests/benchmark.o $(COMMON_OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS) $(LIBS) -lresolv

clean:
	$(RM) $(BIN) src/*.o src/netserver/*.o tests/*.o

.cc.s:
	$(CXX) -S $^ $(CXXFLAGS) $(CPPFLAGS)

install:	froot
	/usr/bin/install -s -m 0755 $^ $(PREFIX)/sbin
	/usr/bin/chcon -t bin_t $(PREFIX)/sbin/$^

# dependencies
src/answer.o:		src/include/answer.h src/include/util.h
src/frootbench.o:	src/include/context.h src/include/zone.src/include/h queryfile.h src/include/timer.h
src/context.o:		src/include/context.h src/include/zone.h src/include/util.h
src/main.o:		src/include/server.h
tests/queryfile.o:	tests/queryfile.h src/include/util.h
src/rrlist.o:		src/include/rrlist.h
src/server.o:		src/include/server.h src/include/context.h src/include/util.h
src/timer.o:		src/include/timer.h
src/util.o:		src/include/util.h
src/zone.o:		src/include/context.h src/include/zone.h src/include/util.h

src/answer.h:		src/include/buffer.h src/include/rrlist.h
src/context.h:		src/include/buffer.h src/include/answer.h src/include/zone.h
src/server.h:		src/include/zone.h
src/zone.h:		src/include/answer.h
