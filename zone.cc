#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>
#include <ldns/dname.h>
#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>
#include <ldns/wire2host.h>
#include <ldns/host2wire.h>

#include "zone.h"
#include "util.h"

/*
 * answer types:
 *
 *   . SOA	[ SOA, NS, glue ] + AA
 *   . NS	[ NS, empty, glue ] + AA
 *   . DNSKEY	[ DNSKEY, empty, empty ] + AA
 *   . NSEC	[ NSEC, NS, glue ] + AA
 *   . xxx	[ empty, SOA, empty ] + AA
 *
 *   foo DS	[ DS, empty, empty ] + AA
 *   foo xxx	[ empty, NS, glue ] -> "referral"
 *   *.foo xxx	referral
 *
 *   nxd	[ empty, SOA, empty ] + AA
 *
 *   with DNSSEC:
 *
 *   . SOA	[ SOA*, NS*, glue ] + AA
 *   . NS	[ NS*, empty, glue ] + AA
 *   . DNSKEY	[ DNSKEY*, empty, empty ] + AA
 *   . NSEC	[ NSEC*, NS*, glue ] + AA
 *   . xxx	[ empty, SOA* + NSEC*, empty ] + AA
 *
 *   foo DS	[ DS*, empty, empty ] + AA
 *   foo xxx	[ empty, NS + DS*, glue ] -> "signed referral"
 *   *.foo xxx	signed referral
 *
 *   nxd	[ empty, SOA* + NSEC*, empty ] + AA
 *
 */

ldns_rr_list* LDNS_rr_list_new_frm_dnssec_rrs(ldns_dnssec_rrs *rrs)
{
	auto rr_list = ldns_rr_list_new();
	while (rrs) {
	          ldns_rr_list_push_rr(rr_list, ldns_rr_clone(rrs->rr));
	          rrs = rrs->next;
	}
	return rr_list;
}

int LDNS_rr_list2buffer_wire(ldns_buffer* buf, ldns_rr_list* list, int section)
{
	if (list) {
		auto n = ldns_rr_list_rr_count(list);
		for (auto i = 0U; i < n; ++i) {
			ldns_rr2buffer_wire(buf, ldns_rr_list_rr(list, i), section);
		}
		return n;
	} else {
		return 0;
	}
}

ReadBuffer Answer::data() const
{
	return *buffer;
}

bool Answer::authoritative() const
{
	return aa_bit;
}

Answer::Answer(ldns_rr_list* an, ldns_rr_list* ns, ldns_rr_list* ar, bool aa_bit) : aa_bit(aa_bit)
{
	size_t n = 4096;
	auto lbuf = ldns_buffer_new(n);

	ancount = LDNS_rr_list2buffer_wire(lbuf, an, LDNS_SECTION_ANSWER);
	nscount = LDNS_rr_list2buffer_wire(lbuf, ns, LDNS_SECTION_AUTHORITY);
	arcount = LDNS_rr_list2buffer_wire(lbuf, ar, LDNS_SECTION_ADDITIONAL);

	auto size = ldns_buffer_position(lbuf);
	auto p = reinterpret_cast<uint8_t*>(ldns_buffer_export(lbuf));
	ldns_buffer_free(lbuf);

	buffer = new ReadBuffer(p, size);
	(void) buffer->read(size);
}

Answer::~Answer()
{
	auto p = buffer->base();
	delete buffer;
	free(const_cast<void*>(p));
}

const Answer* NameData::answer(ldns_pkt_rcode rcode, unsigned labels, bool match, uint16_t qtype, bool do_bit) const
{
	if (rcode == LDNS_RCODE_NXDOMAIN) {
		return negative;
	} else {
		return positive;
	}
}

NameData::NameData(const ldns_dnssec_name* name, const ldns_dnssec_zone *zone)
{
	// ldns_rr_list* glue_a = nullptr;
	// ldns_rr_list* glue_aaaa = nullptr;
	ldns_rr_list* ns = nullptr;
	auto soa = LDNS_rr_list_new_frm_dnssec_rrs(ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA)->rrs);

	auto rrset = name->rrsets;
	while (rrset) {

		if (rrset->type == LDNS_RR_TYPE_NS) {
			ns = LDNS_rr_list_new_frm_dnssec_rrs(rrset->rrs);
		}

		// follow list
		rrset = rrset->next;
	}

	negative = new Answer(soa, nullptr, nullptr, true);
	positive = new Answer(nullptr, ns, nullptr, false);

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
	ldns_dnssec_zone_deep_free(zone);
}
