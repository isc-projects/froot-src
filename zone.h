#pragma once

#include <string>
#include <map>

#include <ldns/dnssec.h>

class NameData {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-private-field"
	ldns_rr_list*		ns;
	ldns_rr_list*		ds;
	ldns_rr_list*		glue_a;
	ldns_rr_list*		glue_aaaa;
#pragma GCC diagnostic pop
	ldns_rr*		nsec;
	ldns_rr_list*		nsec_sigs;

public:
	NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone);
	~NameData();

};

class Zone {

	ldns_dnssec_zone*	zone;

	typedef std::map<std::string, const NameData&> Data;
	Data data;

private:
	void add_name(const ldns_dnssec_name* name);
	void build_answers();

public:
	void load(const std::string& filename);
	int lookup(const std::string& qname) const;

public:
	Zone();
	~Zone();
};
