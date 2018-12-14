#include <iostream>
#include <stdexcept>
#include <atomic>

#include <syslog.h>
#include <arpa/inet.h>

#include <ldns/ldns.h>

#include "zone.h"
#include "util.h"

void Zone::build_answers(PData& data, PAux& aux, const ldns_dnssec_name* name, bool compressed)
{
	auto owner = name->name;
	auto rdata = ldns_rdf_data(owner);
	auto len = rdata[0];
	std::string key = strlower(rdata + 1, len);

	auto nd = std::make_shared<AnswerSet>(name, zone, compressed);
	(*data)[key] = nd;
	(*aux)[key] = nd;
}

void Zone::build_zone(bool compressed)
{
	PData new_data = std::make_shared<Data>();
	PAux new_aux = std::make_shared<Aux>();

	auto node = ldns_rbtree_first(zone->names);
	while (node != LDNS_RBTREE_NULL) {
		// can be const in later versions of ldns
		auto tmp = reinterpret_cast<const ldns_dnssec_name *>(node->data);
		auto name = const_cast<ldns_dnssec_name *>(tmp);

		if (!ldns_dnssec_name_is_glue(name)) {
			build_answers(new_data, new_aux, name, compressed);
		}
		node = ldns_rbtree_next(node);
	}

	std::atomic_exchange(&data, new_data);
	std::atomic_exchange(&aux, new_aux);
}

void Zone::load(const std::string& filename, bool compressed, bool notice)
{
	auto origin = ldns_dname_new_frm_str(".");
	auto fp = fopen(filename.c_str(), "r");
	if (!fp) {
		throw_errno("opening zone file: " + filename);
	}

	auto status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 3600, LDNS_RR_CLASS_IN);
	fclose(fp);
	ldns_rdf_deep_free(origin);

	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("zone load failed");
	}

	ldns_dnssec_zone_mark_glue(zone);
	build_zone(compressed);

	auto soa_rr = ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA)->rrs->rr;
	auto serial = ldns_rdf2native_int32(ldns_rr_rdf(soa_rr, 2));
	ldns_dnssec_zone_deep_free(zone);

	if (notice)  {
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
