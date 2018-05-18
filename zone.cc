#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>
#include <ldns/dname.h>
#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>
#include <ldns/wire2host.h>

#include "zone.h"
#include "util.h"

ldns_rr_list* LDNS_rr_list_new_frm_dnssec_rrs(ldns_dnssec_rrs *rrs)
{
	auto rr_list = ldns_rr_list_new();
	while (rrs) {
	          ldns_rr_list_push_rr(rr_list, ldns_rr_clone(rrs->rr));
	          rrs = rrs->next;
	}
	return rr_list;
}

NameData::NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone *zone)
{
	auto p = name->rrsets;
	while (p) {
		// build here
		p = p->next;
	}

	nsec = ldns_rr_clone(name->nsec);
	nsec_sigs = LDNS_rr_list_new_frm_dnssec_rrs(name->nsec_signatures);
}

NameData::~NameData()
{
	ldns_rr_free(nsec);
	ldns_rr_list_deep_free(nsec_sigs);
}

void Zone::add_name(const ldns_dnssec_name* name)
{
	auto owner = name->name;
	auto str = ldns_rdf2str(owner);
	auto len = strlen(str) - 1;
	auto p = reinterpret_cast<const uint8_t*>(str);
	std::string key = strlower(p, len);
	free(str);

	data.emplace_hint(data.end(), std::move(key), NameData(name, zone));
}

void Zone::build_answers()
{
	auto node = ldns_rbtree_first(zone->names);
	while (node != LDNS_RBTREE_NULL) {
		auto name = reinterpret_cast<const ldns_dnssec_name *>(node->data);
		if (!ldns_dnssec_name_is_glue(name)) {
			add_name(name);
		}
		node = ldns_rbtree_next(node);
	}
}

void Zone::load(const std::string& filename)
{
	if (zone != nullptr) {
		ldns_dnssec_zone_deep_free(zone);
	}

	auto origin = ldns_dname_new_frm_str(".");
	auto fp = fopen(filename.c_str(), "r");
	auto status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 3600, LDNS_RR_CLASS_IN);
	fclose(fp);
	ldns_rdf_free(origin);

	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("zone load failed");
	}

	ldns_dnssec_zone_mark_glue(zone);
	build_answers();
}

Zone::Data::const_iterator Zone::lookup(const std::string& qname, bool& matched) const
{
	auto itr = data.lower_bound(qname);
	matched = (itr->first == qname);
	return itr;
}

Zone::Zone()
{
}

Zone::~Zone()
{
	ldns_dnssec_zone_deep_free(zone);
}
