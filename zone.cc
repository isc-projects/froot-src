#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>
#include <ldns/dname.h>
#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>

#include "context.h"
#include "zone.h"
#include "util.h"

const Answer* NameData::answer(const Context& ctx) const
{
	if (ctx.rcode == LDNS_RCODE_NXDOMAIN) {
		return negative;
	} else {
		return positive;
	}
}

NameData::NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone *zone)
{
	// ldns_rr_list* glue_a = nullptr;
	// ldns_rr_list* glue_aaaa = nullptr;

	RRList empty, ns, soa, glue;

	soa.append(ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA));

	auto rrset = name->rrsets;
	while (rrset) {

		if (rrset->type == LDNS_RR_TYPE_NS) {
			ns.append(rrset);
		}

		// follow list
		rrset = rrset->next;
	}

	negative = new Answer(soa, empty, empty, true);
	positive = new Answer(empty, ns, empty, false);

	// nsec = ldns_rr_clone(name->nsec);
	// nsec_sigs = LDNS_rr_list_new_frm_dnssec_rrs(name->nsec_signatures);
}

NameData::~NameData()
{
	// ldns_rr_free(nsec);
	// ldns_rr_list_deep_free(nsec_sigs);

	delete negative;
	delete positive;
}

void Zone::add_name(const ldns_dnssec_name* name)
{
	auto owner = name->name;
	auto str = ldns_rdf2str(owner);
	auto len = strlen(str) - 1;
	auto p = reinterpret_cast<const uint8_t*>(str);
	std::string key = strlower(p, len);
	free(str);

	data.emplace_hint(data.end(), std::move(key), new NameData(name, zone));
}

void Zone::build_answers()
{
	auto node = ldns_rbtree_first(zone->names);
	while (node != LDNS_RBTREE_NULL) {
		auto name = reinterpret_cast<const ldns_dnssec_name *>(node->data);

		// temporary const_cast for older versions of ldns
		if (!ldns_dnssec_name_is_glue(const_cast<ldns_dnssec_name*>(name))) {
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
	ldns_rdf_deep_free(origin);

	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("zone load failed");
	}

	ldns_dnssec_zone_mark_glue(zone);
	build_answers();
}

const NameData& Zone::lookup(const std::string& qname, bool& matched) const
{
	auto iter = data.lower_bound(qname);
	matched = (iter != data.end()) && (iter->first == qname);
	if (!matched) {
		--iter;
	}
	return *(iter->second);
}

Zone::Zone()
{
}

Zone::~Zone()
{
	auto iter = data.begin();
	while (iter != data.end()) {
		delete iter->second;
		++iter;
	}
	ldns_dnssec_zone_deep_free(zone);
}
