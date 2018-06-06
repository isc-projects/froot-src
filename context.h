#pragma once

#include <string>
#include <vector>
#include <sys/types.h>		// for iovec

#include "buffer.h"
#include "answer.h"

class Zone;

class Context {

private:
	void parse_edns();
	void parse_question();
	void parse_packet();
	const Answer* perform_lookup();

private:
	uint8_t			_head_buf[512];
	uint8_t			_edns_buf[11];

	WriteBuffer		head { _head_buf, sizeof(_head_buf) } ;
	WriteBuffer		edns { _edns_buf, sizeof(_edns_buf) } ;

private:
	const Zone&		zone;
	ReadBuffer&		in;

private:
	std::string		qname;
	uint16_t		qtype;
	uint16_t		qdstart;

	// initial state
	uint16_t		qdsize = 0;
	uint16_t		bufsize = 512;
	uint8_t			qlabels = 0;
	bool			match = false;
	bool			has_edns = false;
	bool			do_bit = false;

public:
	uint16_t		rcode;

public:
	Context(const Zone& zone, ReadBuffer& in);
	~Context();

	bool execute(std::vector<iovec>& iov);
	Answer::Type type() const;
};
