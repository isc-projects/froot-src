#pragma once

#include <ldns/dnssec.h>

#include "buffer.h"
#include "rrlist.h"

class Answer {

	ReadBuffer*		buffer;

public:
	uint16_t		ancount = 0;
	uint16_t		nscount = 0;
	uint16_t		arcount = 0;
	bool			aa_bit = false;

public:
	Answer(const RRList& an, const RRList& ns, const RRList& ar, bool aa_bit);
	~Answer();

	ReadBuffer		data() const;
	bool			authoritative() const;

public:
	static Answer*		empty;

};
