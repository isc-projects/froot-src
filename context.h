#pragma once

#include <string>
#include <vector>
#include <sys/types.h>		// for iovec

#include "buffer.h"
#include "answer.h"

class Zone;

class Context {

private:
	void reset();
	void parse_edns(ReadBuffer& in);
	void parse_question(ReadBuffer& in);
	void parse_packet(ReadBuffer& in);
	const Answer* perform_lookup();

private:
	uint8_t			_head_buf[512];
	uint8_t			_len_buf[2];
	uint8_t			_an_buf[4096];

	WriteBuffer		head { _head_buf, sizeof(_head_buf) } ;

private:
	const Zone&		zone;

private:
	std::string		qname;
	uint16_t		qtype;
	uint16_t		qdstart;
	uint16_t		qdsize;
	uint16_t		bufsize;
	uint8_t			qlabels;
	bool			match;
	bool			has_edns;
	bool			do_bit;
	uint16_t		rcode;

public:
	Context(const Zone& zone);
	~Context();

	bool execute(ReadBuffer& in, std::vector<iovec>& iov, bool tcp = false);
	constexpr Answer::Type type() const;
};
