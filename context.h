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
	ReadBuffer&		body;

private:
	std::string		qname;
	uint16_t		qtype;
	uint16_t		qdsize;
	uint16_t		bufsize;

	uint8_t			qlabels;

	bool			match;
	bool			edns;
	bool			do_bit;
	const Answer*		answer;

public:
	uint8_t			rcode;

public:
	Context(const Zone& zone, ReadBuffer& in, WriteBuffer& head, ReadBuffer& body);
	~Context();

	bool execute();
};
