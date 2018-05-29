#pragma once

#include <cstdint>
#include <string>

class Answer;

class Context {

public:
	std::string		qname;
	uint16_t		qtype;
	uint16_t		bufsize;

	uint8_t			qlabels;
	uint8_t			rcode;

	bool			match;
	bool			edns;
	bool			do_bit;
	const Answer*		answer;

public:
	Context();

};
