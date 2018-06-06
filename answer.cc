#include <ldns/ldns.h>

#include "answer.h"
#include "util.h"

/*
 * answer types:
 *
 *   . SOA	[ SOA, NS, glue ] + AA
 *   . NS	[ NS, empty, glue ] + AA
 *   . DNSKEY	[ DNSKEY, empty, empty ] + AA
 *   . NSEC	[ NSEC, NS, glue ] + AA
 *   . ANY	[ SOA* + NS* + NSEC* + DNSKEY*, empty, glue] + AA
 *   . xxx	[ empty, SOA, empty ] + AA
 *
 *   foo DS	[ DS, empty, empty ] + AA
 *   foo xxx	[ empty, NS, glue ] -> "referral"
 *   foo ANY	referral
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
 *   . ANY	[ SOA* + NS* + NSEC* + DNSKEY*, empty, glue] + AA
 *   . xxx	[ empty, SOA* + NSEC*, empty ] + AA
 *
 *   foo DS	[ DS*, empty, empty ] + AA
 *   foo xxx	[ empty, NS + DS*, glue ] -> "signed referral"
 *   foo ANY	signed referral
 *   *.foo xxx	signed referral
 *
 *   nxd	[ empty, SOA* + NSEC*, empty ] + AA
 *
 */

const Answer* Answer::empty = new Answer(RRList(), RRList(), RRList(), false);

Answer::operator iovec() const
{
	return iovec { buf, size };
}

Answer::Answer(const RRList& an, const RRList& ns, const RRList& ar, bool aa_bit, bool sigs) : aa_bit(aa_bit)
{
	size_t n = 4096;
	auto lbuf = ldns_buffer_new(n);

	ancount = an.to_buffer_wire(lbuf, LDNS_SECTION_ANSWER, sigs);
	nscount = ns.to_buffer_wire(lbuf, LDNS_SECTION_AUTHORITY, sigs);
	arcount = ar.to_buffer_wire(lbuf, LDNS_SECTION_ADDITIONAL, sigs);

	size = ldns_buffer_position(lbuf);
	buf = ldns_buffer_export(lbuf);
	ldns_buffer_free(lbuf);
}

Answer::~Answer()
{
	free(buf);
}

const Answer* AnswerSet::answer(Answer::Type type, bool do_bit) const
{
	Answer* a = nullptr;

	if (do_bit) {
		a = dnssec[type];
	} else {
		a = plain[type];
	}

	return a ? a : Answer::empty;
}

static RRList find_glue(const ldns_dnssec_rrsets* rrset, const ldns_dnssec_zone* zone)
{
	RRList result;

	// temporary const_cast for older versions of ldns
	auto _zone = const_cast<ldns_dnssec_zone*>(zone);

	if (rrset) {
		auto rrs = rrset->rrs;
		while (rrs) {
			auto name = ldns_rr_ns_nsdname(rrs->rr);
			result.append(ldns_dnssec_zone_find_rrset(_zone, name, LDNS_RR_TYPE_A));
			result.append(ldns_dnssec_zone_find_rrset(_zone, name, LDNS_RR_TYPE_AAAA));
			rrs = rrs->next;
		}
	}

	return result;
}

void AnswerSet::generate_root_answers(const ldns_dnssec_zone* zone)
{
	RRList empty, soa, ns, dnskey, nsec;

	auto name = zone->soa;
	soa.append(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_SOA));
	ns.append(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_NS));
	dnskey.append(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_DNSKEY));

	nsec.append(name->nsec);
	nsec.append(name->nsec_signatures);

	// fill out glue
	auto ns_rrl = ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_NS);
	RRList glue = find_glue(ns_rrl, zone);

	plain[Answer::Type::root_soa] = new Answer(soa, ns, glue, true);
	plain[Answer::Type::root_ns] = new Answer(ns, empty, glue, true);
	plain[Answer::Type::root_dnskey] = new Answer(dnskey, empty, empty, true);
	plain[Answer::Type::root_nsec] = new Answer(nsec, ns, glue, true);
	plain[Answer::Type::root_nodata] = new Answer(empty, soa, empty, true);

	dnssec[Answer::Type::root_soa] = new Answer(soa, ns, glue, true, true);
	dnssec[Answer::Type::root_ns] = new Answer(ns, empty, glue, true, true);
	dnssec[Answer::Type::root_dnskey] = new Answer(dnskey, empty, empty, true, true);
	dnssec[Answer::Type::root_nsec] = new Answer(nsec, ns, glue, true, true);
	dnssec[Answer::Type::root_nodata] = new Answer(empty, soa, empty, true, true);

	plain[Answer::Type::root_any] = new Answer(soa + ns + nsec + dnskey, empty, glue, true, true);
	dnssec[Answer::Type::root_any] = new Answer(soa + ns + nsec + dnskey, empty, glue, true, true);
}

void AnswerSet::generate_tld_answers(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone)
{
	RRList empty, soa, ns, ds;

	// temporary const_cast for older versions of ldns
	auto _name = const_cast<ldns_dnssec_name*>(name);

	soa.append(ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA));
	ns.append(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_NS));
	ds.append(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_DS));

	// fill out glue
	auto ns_rrl = ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_NS);
	RRList glue = find_glue(ns_rrl, zone);

	// create unsigned answers
	plain[Answer::Type::tld_ds] = new Answer(ds, empty, empty, true);
	plain[Answer::Type::tld_referral] = new Answer(empty, ns, glue, false);
	plain[Answer::Type::nxdomain] = new Answer(empty, soa, empty, true);

	// signed SOA in NXD requires NSEC records
	soa.append(name->nsec);
	soa.append(name->nsec_signatures);
	soa.append(zone->soa->nsec);
	soa.append(zone->soa->nsec_signatures);

	// create signed answers - signed referral requires signed DS record
	dnssec[Answer::Type::tld_ds] = new Answer(ds, empty, empty, true, true);
	dnssec[Answer::Type::tld_referral] = new Answer(empty, ns + ds, glue, false, true);
	dnssec[Answer::Type::nxdomain] = new Answer(empty, soa, empty, true, true);
}

AnswerSet::AnswerSet(const ldns_dnssec_name* name, const ldns_dnssec_zone *zone)
{
	plain = new Answer*[Answer::Type::max];
	dnssec = new Answer*[Answer::Type::max];

	for (auto i = 0U; i < Answer::Type::max; ++i) {
		plain[i] = nullptr;
		dnssec[i] = nullptr;
	}

	if (name == zone->soa) {
		generate_root_answers(zone);
	} else {
		generate_tld_answers(name, zone);
	}
}

AnswerSet::~AnswerSet()
{
	for (int i = 0U; i < Answer::Type::max; ++i) {
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
