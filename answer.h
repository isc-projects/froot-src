#pragma once

#include "buffer.h"

#include <ldns/dnssec.h>

class Answer {

	ReadBuffer*		buffer;

public:
	uint16_t		ancount = 0;
	uint16_t		nscount = 0;
	uint16_t		arcount = 0;
	bool			aa_bit = false;

public:
	Answer(ldns_rr_list* an, ldns_rr_list* ns, ldns_rr_list* ar, bool aa_bit);
	~Answer();

	ReadBuffer		data() const;
	bool			authoritative() const;

public:
	static Answer*		empty;

};
