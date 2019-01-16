/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <iostream>
#include <stdexcept>
#include <atomic>

#include <syslog.h>
#include <arpa/inet.h>

#include <ldns/ldns.h>

#include "zone.h"
#include "util.h"

void Zone::build_answers(PData& data, PAux& aux, const ldns_dnssec_zone* zone, const ldns_dnssec_name* name, bool compressed)
{
	auto owner = name->name;
	auto rdata = ldns_rdf_data(owner);
	auto len = rdata[0];
	std::string key = strlower(rdata + 1, len);

	auto nd = std::make_shared<AnswerSet>(name, zone, compressed);
	(*data)[key] = nd;
	(*aux)[key] = nd;
}

void Zone::build_zone(const ldns_dnssec_zone* zone, bool compressed)
{
	PData new_data = std::make_shared<Data>();
	PAux new_aux = std::make_shared<Aux>();

	auto node = ldns_rbtree_first(zone->names);
	while (node != LDNS_RBTREE_NULL) {
		// can be const in later versions of ldns
		auto tmp = reinterpret_cast<const ldns_dnssec_name *>(node->data);
		auto name = const_cast<ldns_dnssec_name *>(tmp);

		if (!ldns_dnssec_name_is_glue(name)) {
			build_answers(new_data, new_aux, zone, name, compressed);
		}
		node = ldns_rbtree_next(node);
	}

	std::atomic_exchange(&data, new_data);
	std::atomic_exchange(&aux, new_aux);
}

void Zone::check_zone(const ldns_dnssec_zone* zone)
{
	if (!zone->names) {
		throw std::runtime_error("names not found in zone");
	}

	if (!zone->soa) {
		throw std::runtime_error("no SOA found in zone");
	}
}

void Zone::load(const std::string& filename, bool compressed, bool notice)
{
	auto origin = std::shared_ptr<ldns_rdf>(ldns_dname_new_frm_str("."), ldns_rdf_deep_free);
	auto fp = ::fopen(filename.c_str(), "r");
	if (!fp) {
		throw_errno("opening zone file: " + filename);
	}

	ldns_dnssec_zone *zone = nullptr;
	auto status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin.get(), 3600, LDNS_RR_CLASS_IN);
	::fclose(fp);

	if (status != LDNS_STATUS_OK || zone == nullptr) {
		throw std::runtime_error("zone load failed");
	}

	// ensure release of the zone data
	auto zp = std::shared_ptr<ldns_dnssec_zone>(zone, ldns_dnssec_zone_deep_free);

	// check the zone structure and build the zone representation
	check_zone(zp.get());
	ldns_dnssec_zone_mark_glue(zp.get());
	build_zone(zp.get(), compressed);

	// report the serial number
	if (notice)  {
		auto soa_rr = ldns_dnssec_name_find_rrset(zp->soa, LDNS_RR_TYPE_SOA)->rrs->rr;
		auto serial = ldns_rdf2native_int32(ldns_rr_rdf(soa_rr, 2));
		syslog(LOG_NOTICE, "root zone loaded with SOA serial %u", serial);
	}

	loaded = true;
}

const AnswerSet* Zone::lookup(const std::string& qname, bool& matched) const
{
	if (!loaded) {
		return nullptr;
	}

	// look for an exact match first
	{
		const auto& iter = aux->find(qname);
		if (iter != aux->end()) {
			matched = true;
			return iter->second.get();
		}
	}

	// exact match not found, return predecessor (for NSEC generation)
	matched = false;
	auto iter = data->lower_bound(qname);
	return (--iter)->second.get();
}

Zone::Zone()
{
}

Zone::~Zone()
{
}
