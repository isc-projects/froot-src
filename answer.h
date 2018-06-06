#pragma once

#include <sys/socket.h>		// for iovec
#include <ldns/ldns.h>

#include "buffer.h"
#include "rrlist.h"

class Answer {

public:
	enum Type {
		root_soa = 0,
		root_ns,
		root_dnskey,
		root_nsec,
		root_any,
		root_nodata,
		tld_ds,
		tld_referral,
		nxdomain,
		max
	};

private:
	void*			buf;
	size_t			size;
	bool			aa_bit = false;

public:
	uint16_t		ancount = 0;
	uint16_t		nscount = 0;
	uint16_t		arcount = 0;

public:
	Answer(const RRList& an, const RRList& ns, const RRList& ar, bool aa_bit, bool sigs = false);
	~Answer();

				operator iovec() const;
	bool			authoritative() const { return aa_bit; };

public:
	static const Answer*	empty;

};

class AnswerSet {

private:
        Answer**                plain;
        Answer**                dnssec;

private:
        void generate_root_answers(const ldns_dnssec_zone* zone);
        void generate_tld_answers(const ldns_dnssec_name*name, const ldns_dnssec_zone* zone);

public:
        AnswerSet(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone);
        ~AnswerSet();

public:
        const Answer* answer(Answer::Type type, bool do_bit) const;
};
