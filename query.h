#pragma once

#include <cstdint>
#include <string>

class Query {

public:
	std::string		qname;
	uint16_t		qtype;
	uint8_t			qlabels;

	bool			match;
	bool			edns;
	bool			do_bit;

	uint16_t		bufsize;

public:
	Query();

};
