#pragma once

#include <map>
#include <memory>
#include <vector>
#include <type_traits>

#include <sys/socket.h>		// for iovec
#include <ldns/ldns.h>

#include "buffer.h"
#include "rrlist.h"

//
//  Wire format for an EDNS OPT RR
//
struct __attribute__((__packed__)) edns_opt_rr {
        uint8_t         name;
        uint16_t        type;
        uint16_t        bufsize;
        uint8_t         ercode;
        uint8_t         version;
        uint16_t        flags;
        uint16_t        rdlen;
};

//
// comparison functor for comparing ldns_rdf* objects
//

class Answer {

private:
	typedef std::shared_ptr<const ldns_rdf> RDFPtr;

	struct DNameCompare {
		bool operator()(RDFPtr a, RDFPtr b) const {
			return ldns_dname_compare(a.get(), b.get()) < 0;
		}
	};

private:
	uint16_t get_name_pointer(const ldns_rdf* name) const;
	void put_name_pointer(const ldns_rdf* name, uint16_t offset);

	void dname_to_wire(ldns_buffer* lbuf, const ldns_rdf* name);
	void rr_to_wire(ldns_buffer* lbuf, const ldns_rr* rr);
	size_t rrlist_to_wire(ldns_buffer* lbuf, const RRList& rrs);

private:
	typedef std::map<RDFPtr, uint16_t, DNameCompare> CompressTable;
	typedef std::vector<uint16_t> CompressOffsets;

public:

	// flags passed to the constructor
	enum Flags : uint16_t {
		none = 0,
		auth = 1,
		dnssec = 2,
		nocompress = 4
	};

	// possible answer types
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
	uint8_t*		buf;
	size_t			_size;
	uint16_t		fix_offset;
	Flags			flags;
	CompressTable		c_table;
	CompressOffsets		c_offsets;

public:
	uint16_t		ancount = 0;
	uint16_t		nscount = 0;
	uint16_t		arcount = 0;

public:
	Answer(const ldns_rdf* name, const RRList& an, const RRList& ns, const RRList& ar, Flags flags = none);
	~Answer();

				operator iovec() const { return iovec { buf, _size }; };
	size_t			size() const { return _size; };

	bool			authoritative() const { return flags & Flags::auth; };
	bool			compressed() const { return ! (flags & Flags::nocompress); };

	iovec			data_offset_by(uint16_t offset, uint8_t* out) const;

public:
	static const Answer*	empty;

};

// convenience operator for combining Flags returning 'Flags'
// instead of the automatic promotion to 'int' that the '|'
// operator usually causes

constexpr inline Answer::Flags operator|(Answer::Flags lhs, Answer::Flags rhs)
{
	using T = std::underlying_type<Answer::Flags>::type;

	return static_cast<Answer::Flags>(
		static_cast<T>(lhs) | static_cast<T>(rhs)
	);
};

constexpr inline void operator|=(Answer::Flags& lhs, Answer::Flags rhs)
{
	lhs = lhs | rhs;
}

class AnswerSet {

private:
        Answer**                plain;
        Answer**                dnssec;

private:
        void generate_root_answers(const ldns_dnssec_zone* zone, bool compress);
        void generate_tld_answers(const ldns_dnssec_name*name, const ldns_dnssec_zone* zone, bool compress);

public:
        AnswerSet(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone, bool compress = true);
        ~AnswerSet();

public:
        const Answer* answer(Answer::Type type, bool do_bit) const;
};
