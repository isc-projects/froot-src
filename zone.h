#pragma once

#include <string>
#include <map>
#include <unordered_map>

#include <ldns/dnssec.h>

#include "buffer.h"

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

};

class NameData {

private:
	Answer*			negative;
	Answer*			positive;

public:
	NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone);
	~NameData();

public:
	const Answer* answer(ldns_enum_pkt_rcode rcode, unsigned labels, bool match, uint16_t qtype, bool do_bit) const;
};

class Zone {

private:
	typedef std::map<std::string, const NameData*> Data;

private:
	ldns_dnssec_zone*	zone = nullptr;
	Data data;

private:
	void add_name(const ldns_dnssec_name* name);
	void build_answers();

public:
	void load(const std::string& filename);
	const NameData& lookup(const std::string& qname, bool& match) const;

public:
	Zone();
	~Zone();
};
