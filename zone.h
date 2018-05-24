#pragma once

#include <string>
#include <map>

#include <ldns/dnssec.h>

#include "buffer.h"

/*
	<= 512 positive
	<= 512 negative

	EDNS positive
	EDNS negative

	EDNS + DO positive
	EDNS + DO negative

	+ TC variants
*/

class Answer {

	ReadBuffer*		buffer;

public:
	uint16_t		ancount;
	uint16_t		nscount;
	uint16_t		arcount;

public:
	Answer(ldns_rr_list* an, ldns_rr_list* ns, ldns_rr_list* ar);
	~Answer();

	ReadBuffer		data() const;

};

class NameData {

private:
	Answer*			positive;

public:
	NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone);
	~NameData();

public:
	const Answer* answer(ldns_enum_pkt_rcode rcode) const;
};

class Zone {

public:
	typedef std::map<std::string, const NameData*> Data;

private:
	ldns_dnssec_zone*	zone = nullptr;
	Data data;

private:
	void add_name(const ldns_dnssec_name* name);
	void build_answers();

public:
	void load(const std::string& filename);
	Data::const_iterator lookup(const std::string& qname, bool& match) const;

public:
	Zone();
	~Zone();
};
