#pragma once

#include <string>
#include <map>

#include <ldns/dnssec.h>

#include "answer.h"

class Context;

class NameData {

private:
	static Answer*		empty;
	Answer*			negative;
	Answer*			positive;

public:
	NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone);
	~NameData();

public:
	const Answer* answer(const Context& ctx) const;
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
