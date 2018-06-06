#pragma once

#include <map>

#include <sys/socket.h>		// for iovec
#include <ldns/ldns.h>

#include "buffer.h"
#include "rrlist.h"

struct DNameCompare {
        bool operator()(const ldns_rdf* a, const ldns_rdf* b) {
                return ldns_dname_compare(a, b) < 0;
        }
};

class Answer {

private:
	void dname_to_wire(ldns_buffer* lbuf, const ldns_rdf* name);
	void rr_to_wire(ldns_buffer* lbuf, const ldns_rr* rr, int section);
	size_t rrlist_to_wire(ldns_buffer* lbuf, const RRList& rrs, int section, bool sigs);

public:
	typedef std::map<const ldns_rdf*, uint16_t, DNameCompare> CompressTable;
	typedef std::vector<uint16_t> CompressOffsets;

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
	CompressTable		c_table;
	CompressOffsets		c_offsets;

public:
	uint16_t		ancount = 0;
	uint16_t		nscount = 0;
	uint16_t		arcount = 0;

public:
	Answer(const RRList& an, const RRList& ns, const RRList& ar, bool aa_bit, bool sigs = false);
	~Answer();

				operator iovec() const { return iovec { buf, size }; };
	bool			authoritative() const { return aa_bit; };
	iovec			data_offset_by(uint16_t offset) const;

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
