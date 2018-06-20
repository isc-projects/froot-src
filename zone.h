#pragma once

#include <memory>
#include <string>
#include <map>
#include <unordered_map>

#include <ldns/ldns.h>

#include "context.h"

class AnswerSet;

class Zone {

private:
	typedef std::map<std::string, std::shared_ptr<const AnswerSet>> Data;
	typedef std::unordered_map<std::string, std::shared_ptr<const AnswerSet>> Aux;

private:
	ldns_dnssec_zone*	zone = nullptr;
	Data data;
	Aux aux;

private:
	void build_answers(const ldns_dnssec_name* name, bool compress);
	void build_zone(bool compress);

public:
	void load(const std::string& filename, bool compress);
	const AnswerSet* lookup(const std::string& qname, bool& match) const;

public:
	Zone();
	~Zone();
};
