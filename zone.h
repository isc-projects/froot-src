#pragma once

#include <string>
#include <map>
#include <unordered_map>

#include <ldns/dnssec.h>

#include "context.h"
#include "answer.h"

class NameData {

private:
	static Answer*		empty;

	Answer**		plain;
	Answer**		dnssec;

private:
	void generate_root_answers(const ldns_dnssec_zone* zone);
	void generate_tld_answers(const ldns_dnssec_name*name, const ldns_dnssec_zone* zone);

public:
	NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone);
	~NameData();

public:
	const Answer* answer(Context::Type type, bool do_bit) const;
};

class Zone {

private:
	typedef std::map<std::string, const NameData*> Data;
	typedef std::unordered_map<std::string, const NameData*> Aux;

private:
	ldns_dnssec_zone*	zone = nullptr;
	Data data;
	Aux aux;

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
