#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <ldns/dname.h>
#include <ldns/rr.h>
#include <ldns/rr_functions.h>
#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>

#include "context.h"
#include "zone.h"
#include "util.h"

const Answer* NameData::answer(Context::Type type, bool do_bit) const
{
	Answer* a = nullptr;

	if (do_bit) {
		a = dnssec[type];
	} else {
		a = plain[type];
	}

	return a ? a : Answer::empty;
}

static void find_glue(RRList& rrl, const ldns_dnssec_rrsets* rrset, const ldns_dnssec_zone* zone)
{
	// temporary const_cast for older versions of ldns
	auto _zone = const_cast<ldns_dnssec_zone*>(zone);

	if (rrset) {
		auto rrs = rrset->rrs;
		while (rrs) {
			auto name = ldns_rr_ns_nsdname(rrs->rr);
			rrl.append(ldns_dnssec_zone_find_rrset(_zone, name, LDNS_RR_TYPE_A));
			rrl.append(ldns_dnssec_zone_find_rrset(_zone, name, LDNS_RR_TYPE_AAAA));
			rrs = rrs->next;
		}
	}
}

void NameData::generate_root_answers(const ldns_dnssec_zone* zone)
{
	RRList empty, soa, ns, dnskey, nsec, glue;

	auto name = zone->soa;
	soa.append(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_SOA));
	ns.append(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_NS));
	dnskey.append(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_DNSKEY));
	nsec.append(name->nsec);

	// fill out glue
	auto ns_rrl = ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_NS);
	find_glue(glue, ns_rrl, zone);

	plain[Context::Type::ctx_root_soa] = new Answer(soa, ns, glue, true);
	plain[Context::Type::ctx_root_ns] = new Answer(ns, empty, glue, true);
	plain[Context::Type::ctx_root_dnskey] = new Answer(dnskey, empty, empty, true);
	plain[Context::Type::ctx_root_nsec] = new Answer(nsec, ns, glue, true);
	plain[Context::Type::ctx_root_nodata] = new Answer(empty, soa, empty, true);

	// add RRSIGS for the NSEC records
	nsec.append(name->nsec_signatures);

	dnssec[Context::Type::ctx_root_soa] = new Answer(soa, ns, glue, true, true);
	dnssec[Context::Type::ctx_root_ns] = new Answer(ns, empty, glue, true, true);
	dnssec[Context::Type::ctx_root_dnskey] = new Answer(dnskey, empty, empty, true, true);
	dnssec[Context::Type::ctx_root_nsec] = new Answer(nsec, ns, glue, true, true);
	dnssec[Context::Type::ctx_root_nodata] = new Answer(empty, soa, empty, true, true);
}

void NameData::generate_tld_answers(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone)
{
	RRList empty, soa, ns, ds, glue;

	// temporary const_cast for older versions of ldns
	auto _name = const_cast<ldns_dnssec_name*>(name);

	soa.append(ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA));
	ns.append(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_NS));
	ds.append(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_DS));

	// fill out glue
	auto ns_rrl = ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_NS);
	find_glue(glue, ns_rrl, zone);

	// create unsigned answers
	plain[Context::Type::ctx_tld_ds] = new Answer(ds, empty, empty, true);
	plain[Context::Type::ctx_tld_referral] = new Answer(empty, ns, glue, false);
	plain[Context::Type::ctx_nxdomain] = new Answer(empty, soa, empty, true);

	// signed SOA in NXD requires NSEC records
	soa.append(name->nsec);
	soa.append(name->nsec_signatures);
	soa.append(zone->soa->nsec);
	soa.append(zone->soa->nsec_signatures);

	// signed referral requires signed DS record
	ns.append(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_DS));

	// create signed answers
	dnssec[Context::Type::ctx_tld_ds] = new Answer(ds, empty, empty, true, true);
	dnssec[Context::Type::ctx_tld_referral] = new Answer(empty, ns, glue, false, true);
	dnssec[Context::Type::ctx_nxdomain] = new Answer(empty, soa, empty, true, true);
}

NameData::NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone *zone)
{
	plain = new Answer*[Context::Type::ctx_size];
	dnssec = new Answer*[Context::Type::ctx_size];

	for (auto i = 0U; i < Context::Type::ctx_size; ++i) {
		plain[i] = nullptr;
		dnssec[i] = nullptr;
	}

	if (name == zone->soa) {
		generate_root_answers(zone);
	} else {
		generate_tld_answers(name, zone);
	}
}

NameData::~NameData()
{
	for (int i = 0U; i < Context::Type::ctx_size; ++i) {
		if (plain[i]) {
			delete plain[i];
		}
		if (dnssec[i]) {
			delete dnssec[i];
		}
	}

	delete[] dnssec;
	delete[] plain;
}

void Zone::add_name(const ldns_dnssec_name* name)
{
	auto owner = name->name;
	auto str = ldns_rdf2str(owner);
	auto len = strlen(str) - 1;
	auto p = reinterpret_cast<const uint8_t*>(str);
	std::string key = strlower(p, len);
	free(str);

	auto nd = new NameData(name, zone);
	data.insert({key, nd});
	aux.insert({key, nd});
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
	build_answers();
}

const NameData& Zone::lookup(const std::string& qname, bool& matched) const
{
	{
		auto iter = aux.find(qname);
		if (iter != aux.end()) {
			matched = true;
			return *(iter->second);
		}
	}

	matched = false;
	auto iter = data.lower_bound(qname);
	--iter;
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
