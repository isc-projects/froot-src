#pragma once

#include <sys/socket.h>		// for iovec
#include <ldns/dnssec.h>

#include "buffer.h"
#include "rrlist.h"

class Answer {

	void*			buf;
	size_t			size;

public:
	uint16_t		ancount = 0;
	uint16_t		nscount = 0;
	uint16_t		arcount = 0;
	bool			aa_bit = false;

public:
	Answer(const RRList& an, const RRList& ns, const RRList& ar, bool aa_bit, bool sigs = false);
	~Answer();

				operator iovec() const;
	bool			authoritative() const;

public:
	static Answer*		empty;

};
