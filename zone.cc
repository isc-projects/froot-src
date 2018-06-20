#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>

#include <ldns/ldns.h>

#include "zone.h"
#include "util.h"

void Zone::build_answers(const ldns_dnssec_name* name, bool compressed)
{
	auto owner = name->name;
	auto str = ldns_rdf2str(owner);
	auto len = strlen(str) - 1;
	auto p = reinterpret_cast<const uint8_t*>(str);
	std::string key = strlower(p, len);
	free(str);

	auto nd = std::make_shared<AnswerSet>(name, zone, compressed);
	data[key] = nd;
	aux[key] = nd;
}

void Zone::build_zone(bool compressed)
{
	auto node = ldns_rbtree_first(zone->names);
	while (node != LDNS_RBTREE_NULL) {
		// can be const in later versions of ldns
		auto tmp = reinterpret_cast<const ldns_dnssec_name *>(node->data);
		auto name = const_cast<ldns_dnssec_name *>(tmp);

		if (!ldns_dnssec_name_is_glue(name)) {
			build_answers(name, compressed);
		}
		node = ldns_rbtree_next(node);
	}
}

void Zone::load(const std::string& filename, bool compressed)
{
	if (zone != nullptr) {
		ldns_dnssec_zone_deep_free(zone);
	}

	auto origin = ldns_dname_new_frm_str(".");
	auto fp = fopen(filename.c_str(), "r");
	if (!fp) {
		throw_errno("opening zone file");
	}

	auto status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 3600, LDNS_RR_CLASS_IN);
	fclose(fp);
	ldns_rdf_deep_free(origin);

	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("zone load failed");
	}

	ldns_dnssec_zone_mark_glue(zone);
	build_zone(compressed);
}

const AnswerSet* Zone::lookup(const std::string& qname, bool& matched) const
{
	// look for an exact match first
	{
		const auto& iter = aux.find(qname);
		if (iter != aux.end()) {
			matched = true;
			return iter->second.get();
		}
	}

	// exact match not found, return predecessor (for NSEC generation)
	matched = false;
	auto iter = data.lower_bound(qname);
	return (--iter)->second.get();
}

Zone::Zone()
{
}

Zone::~Zone()
{
	ldns_dnssec_zone_deep_free(zone);
}
