#pragma once

#include <string>
#include <map>

#include <ldns/dnssec.h>

/*
	<= 512 positive
	<= 512 negative

	EDNS positive
	EDNS negative

	EDNS + DO positive
	EDNS + DO negative

	+ TC variants
*/

class NameData {

#if 0
	ldns_rr_list*		ns;
	ldns_rr_list*		ds;
	ldns_rr_list*		glue_a;
	ldns_rr_list*		glue_aaaa;
#endif
	ldns_rr*		nsec;
	ldns_rr_list*		nsec_sigs;

public:
	NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone);
	~NameData();

};

class Zone {

public:
	typedef std::map<std::string, const NameData&> Data;

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
