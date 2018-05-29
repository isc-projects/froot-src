#pragma once

#include <cstdint>
#include <string>

#include "buffer.h"
#include "answer.h"
#include "zone.h"

class Context {

private:
	void lookup();

private:
	const Zone&		zone;
	ReadBuffer&		in;
	WriteBuffer&		head;

public:
	std::string		qname;
	uint16_t		qtype;
	uint16_t		qdsize;
	uint16_t		bufsize;

	uint8_t			qlabels;
	uint8_t			rcode;

	bool			match;
	bool			edns;
	bool			do_bit;
	const Answer*		answer;

public:
	Context(const Zone& zone, ReadBuffer& in, WriteBuffer& head);

	bool parse(ReadBuffer& body);
};
