#include <arpa/inet.h>
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

void Answer::dname_to_wire(ldns_buffer* lbuf, const ldns_rdf* name)
{
	if (ldns_dname_label_count(name) == 0) {
		ldns_buffer_write_u8(lbuf, 0);
		return;
	}

	const auto& iter = c_table.find(name);
	if (iter != c_table.cend()) {
		auto pos = iter->second;
		c_offsets.push_back(ldns_buffer_position(lbuf));
		ldns_buffer_write_u16(lbuf, htons(pos | 0xc000));	// want host order in the buffer
		return;
	}

	uint16_t pos = ldns_buffer_position(lbuf);
	if (pos < 16384) {
		auto clone = ldns_rdf_clone(name);
		c_table[clone] = pos;
	}

	auto label = ldns_dname_label(name, 0);
	auto rest = ldns_dname_left_chop(name);
	auto size = ldns_rdf_size(label) - 1;
	auto data = ldns_rdf_data(label);

	ldns_buffer_write(lbuf, data, size);
	ldns_rdf_deep_free(label);

	dname_to_wire(lbuf, rest);	// recursive

	ldns_rdf_deep_free(rest);
}

void Answer::rr_to_wire(ldns_buffer* lbuf, const ldns_rr* rr, int section)
{
	dname_to_wire(lbuf, ldns_rr_owner(rr));
	ldns_buffer_write_u16(lbuf, ldns_rr_get_type(rr));
	ldns_buffer_write_u16(lbuf, ldns_rr_get_class(rr));

	if (section != LDNS_SECTION_QUESTION) {
		ldns_buffer_write_u32(lbuf, ldns_rr_ttl(rr));
		uint16_t rdlen_pos = ldns_buffer_position(lbuf);
		ldns_buffer_write_u16(lbuf, 0);

		// simple check for DNAME possible here because we know that the
		// only records with DNAME rdata that appear in the root zone are
		// compressible NS records

		for (auto i = 0U; i < ldns_rr_rd_count(rr); ++i) {
			auto rdf = ldns_rr_rdf(rr, i);
			if (ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_DNAME) {
				dname_to_wire(lbuf, rdf);
			} else {
				ldns_rdf2buffer_wire(lbuf, rdf);
			}
		}

		ldns_buffer_write_u16_at(lbuf, rdlen_pos, ldns_buffer_position(lbuf) - rdlen_pos - 2);
	}
}

size_t Answer::rrlist_to_wire(ldns_buffer* lbuf, const RRList& rrs, int section, bool sigs)
{
	size_t n = 0;

	for (const auto& rrp: rrs.list()) {
		auto rr = rrp.get();
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
			if (sigs) {
				rr_to_wire(lbuf, rrp.get(), section);
				++n;
			}
		} else {
			rr_to_wire(lbuf, rrp.get(), section);
			++n;
		}
	}

	return n;
}

iovec Answer::data_offset_by(const uint16_t offset, uint8_t* out) const
{
	std::copy(buf, buf + size, out);

	for (auto n: c_offsets) {
		auto& p = *reinterpret_cast<uint16_t*>(out + n);
		p = htons(p + offset);
	}

	return iovec { out, size };
}

Answer::Answer(const RRList& an, const RRList& ns, const RRList& ar, bool aa_bit, bool sigs) : aa_bit(aa_bit)
{
	size_t n = 4096;
	auto lbuf = ldns_buffer_new(n);

	ancount = rrlist_to_wire(lbuf, an, LDNS_SECTION_ANSWER, sigs);
	nscount = rrlist_to_wire(lbuf, ns, LDNS_SECTION_AUTHORITY, sigs);
	arcount = rrlist_to_wire(lbuf, ar, LDNS_SECTION_ADDITIONAL, sigs);

	size = ldns_buffer_position(lbuf);
	buf = reinterpret_cast<uint8_t*>(ldns_buffer_export(lbuf));
	ldns_buffer_free(lbuf);
}

Answer::~Answer()
{
	// clean up compression table pointers
	for (auto iter: c_table) {
		ldns_rdf_deep_free(const_cast<ldns_rdf*>(iter.first));
	}

	free(buf);
}

// --------------------------------------------------------------------

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
	auto name = zone->soa;

	RRList empty;
	RRList soa(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_SOA));
	RRList ns(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_NS));
	RRList dnskey(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_DNSKEY));

	RRList nsec;
	nsec.append(name->nsec);
	nsec.append(name->nsec_signatures);

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
	// temporary const_cast for older versions of ldns
	auto _name = const_cast<ldns_dnssec_name*>(name);

	RRList empty;
	RRList soa(ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA));
	RRList ns(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_NS));
	RRList ds(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_DS));

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
