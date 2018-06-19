#include <string>
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

const Answer* Answer::empty = new Answer(nullptr, RRList(), RRList(), RRList(), Flags::none);

// TODO: error checking
void Answer::dname_to_wire(ldns_buffer* lbuf, const ldns_rdf* name)
{
	// if compression is not enabled just write the data
	if (!compressed()) {
		ldns_buffer_write(lbuf, ldns_rdf_data(name), ldns_rdf_size(name));
		return;
	}

	// no labels left, right final zero
	if (ldns_dname_label_count(name) == 0) {
		ldns_buffer_write_u8(lbuf, 0);
		return;
	}

	// look up the name in the map of name locations
	const auto& iter = c_table.find(name);
	if (iter != c_table.cend()) {
		c_offsets.push_back(ldns_buffer_position(lbuf));
		auto pos = iter->second;
		ldns_buffer_write_u16(lbuf, pos | 0xc000);
		return;
	}

	// not found - store the current position in the map, with an
	// offset based on the assumed minimum question section size
	uint16_t pos = ldns_buffer_position(lbuf);
	if (pos < 16384) {
		auto clone = ldns_rdf_clone(name);
		c_table[clone] = pos + 12 + fix_offset;
	}

	// chop the name in two, writing the left hand label
	// into the memory buffer
	auto label = ldns_dname_label(name, 0);
	auto rest = ldns_dname_left_chop(name);
	auto size = ldns_rdf_size(label) - 1;
	auto data = ldns_rdf_data(label);
	ldns_buffer_write(lbuf, data, size);
	ldns_rdf_deep_free(label);

	// recursively do it all again for the trailing labels
	dname_to_wire(lbuf, rest);

	// which need to be deallocated after
	ldns_rdf_deep_free(rest);
}

void Answer::rr_to_wire(ldns_buffer* lbuf, const ldns_rr* rr)
{
	dname_to_wire(lbuf, ldns_rr_owner(rr));
	ldns_buffer_write_u16(lbuf, ldns_rr_get_type(rr));
	ldns_buffer_write_u16(lbuf, ldns_rr_get_class(rr));
	ldns_buffer_write_u32(lbuf, ldns_rr_ttl(rr));

	// store a dummy RDLENGTH field and remember its position for later
	uint16_t rdlen_pos = ldns_buffer_position(lbuf);
	ldns_buffer_write_u16(lbuf, 0);

	// output the sub RDFs that make up the individual fields within
	// the RDATA of the RR
	//
	// simple check for DNAME possible here because we know that the
	// only records with DNAME rdata that appear in the root zone are
	// compressible NS or SOA records
	for (auto i = 0U; i < ldns_rr_rd_count(rr); ++i) {
		auto rdf = ldns_rr_rdf(rr, i);
		if (ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_DNAME) {
			dname_to_wire(lbuf, rdf);
		} else {
			ldns_rdf2buffer_wire(lbuf, rdf);
		}
	}

	// overwrite the dummy RDLENGTH field with the real length
	ldns_buffer_write_u16_at(lbuf, rdlen_pos, ldns_buffer_position(lbuf) - rdlen_pos - 2);
}

size_t Answer::rrlist_to_wire(ldns_buffer* lbuf, const RRList& rrs)
{
	size_t n = 0;

	for (const auto& rrp: rrs.list()) {
		auto rr = rrp.get();
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
			if (flags & Flags::dnssec) {
				rr_to_wire(lbuf, rrp.get());
				++n;
			}
		} else {
			rr_to_wire(lbuf, rrp.get());
			++n;
		}
	}

	return n;
}

iovec Answer::data_offset_by(uint16_t offset, uint8_t* out) const
{
	// compression disabled, or offset matches minimal offset,
	// or no compression data actually found
	// - use pre-computer answer directly
	if (!compressed() || (offset == fix_offset) || c_offsets.size() == 0) {
		return iovec { buf, _size };
	}

	// adjust offset to account for excess
	offset -= fix_offset;

	// copy buffer and adjust compression pointers
	::memcpy(out, buf, _size);

	for (auto n: c_offsets) {
		auto& p = *reinterpret_cast<uint16_t*>(out + n);
		p = htons(ntohs(p) + offset);
	}

	return iovec { out, _size };
}

Answer::Answer(const ldns_rdf* name, const RRList& an, const RRList& ns, const RRList& ar, Flags flags)
	: flags(flags)
{
	// calculate likely size of response sections and pre-fill
	// the compression table with the TLD in the question section
	// (nb: may get adjusted later if the real question is longer)

	if (name && ldns_rdf_size(name) > 1) {
		auto clone = ldns_rdf_clone(name);
		fix_offset = 4 + ldns_rdf_size(clone);
		c_table[clone] = 12;
	} else {
		fix_offset = 5;
	}

	size_t n = 4096;
	auto lbuf = ldns_buffer_new(n);

	ancount = rrlist_to_wire(lbuf, an);
	nscount = rrlist_to_wire(lbuf, ns);
	arcount = rrlist_to_wire(lbuf, ar) + 1;	// EDNS record too

	// take a copy of the buffer, shrunk to fit, with room for EDNS on the end
	auto lbsize = ldns_buffer_position(lbuf);
	_size = lbsize + 11;
	buf = new uint8_t[_size];
	::memcpy(buf, ldns_buffer_begin(lbuf), lbsize);
	ldns_buffer_free(lbuf);

	// populate the EDNS OPT RR
	auto& opt = *reinterpret_cast<edns_opt_rr*>(buf + lbsize);
	opt.name = 0;           // "."
	opt.type = htons(LDNS_RR_TYPE_OPT);
	opt.bufsize = htons(1480);
	opt.ercode = 0;
	opt.version = 0;
	opt.flags = htons((flags & Flags::dnssec) ? 0x8000 : 0);
	opt.rdlen = 0;
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

void AnswerSet::generate_root_answers(const ldns_dnssec_zone* zone, bool compress)
{
	Answer::Flags flags = Answer::Flags::auth;
	if (!compress) {
		flags = flags | Answer::Flags::nocompress;
	}

	auto name = zone->soa;
	auto owner = ldns_dnssec_name_name(name);

	RRList empty;
	RRList soa(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_SOA));
	RRList ns(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_NS));
	RRList dnskey(ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_DNSKEY));

	RRList nsec;
	nsec.append(name->nsec);
	nsec.append(name->nsec_signatures);

	auto ns_rrl = ldns_dnssec_name_find_rrset(name, LDNS_RR_TYPE_NS);
	RRList glue = find_glue(ns_rrl, zone);

	// unsigned authoritative answers
	plain[Answer::Type::root_soa] = new Answer(owner, soa, ns, glue, flags);
	plain[Answer::Type::root_ns] = new Answer(owner, ns, empty, glue, flags);
	plain[Answer::Type::root_dnskey] = new Answer(owner, dnskey, empty, empty, flags);
	plain[Answer::Type::root_nsec] = new Answer(owner, nsec, ns, glue, flags);
	plain[Answer::Type::root_nodata] = new Answer(owner, empty, soa, empty, flags);

	// signed authoritative answers
	flags = flags | Answer::Flags::dnssec;
	dnssec[Answer::Type::root_soa] = new Answer(owner, soa, ns, glue, flags);
	dnssec[Answer::Type::root_ns] = new Answer(owner, ns, empty, glue, flags);
	dnssec[Answer::Type::root_dnskey] = new Answer(owner, dnskey, empty, empty, flags);
	dnssec[Answer::Type::root_nsec] = new Answer(owner, nsec, ns, glue, flags);
	dnssec[Answer::Type::root_nodata] = new Answer(owner, empty, soa, empty, flags);

	// query for '. ANY' always contains NS, NSEC, DNSKEY, RRSIGs etc
	plain[Answer::Type::root_any] = new Answer(owner, soa + ns + nsec + dnskey, empty, glue, flags);
	dnssec[Answer::Type::root_any] = new Answer(owner, soa + ns + nsec + dnskey, empty, glue, flags);
}

void AnswerSet::generate_tld_answers(const ldns_dnssec_name* name, const ldns_dnssec_zone* zone, bool compress)
{
	Answer::Flags flags = Answer::Flags::none;
	if (!compress) {
		flags = flags | Answer::Flags::nocompress;
	}

	// temporary const_cast for older versions of ldns
	auto _name = const_cast<ldns_dnssec_name*>(name);

	auto owner = ldns_dnssec_name_name(_name);

	RRList empty;
	RRList soa(ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA));
	RRList ns(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_NS));
	RRList ds(ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_DS));

	// signed SOA in NXD requires NSEC records
	RRList signed_soa = soa;
	signed_soa.append(name->nsec);
	signed_soa.append(name->nsec_signatures);
	signed_soa.append(zone->soa->nsec);
	signed_soa.append(zone->soa->nsec_signatures);

	// fill out glue
	auto ns_rrl = ldns_dnssec_name_find_rrset(_name, LDNS_RR_TYPE_NS);
	RRList glue = find_glue(ns_rrl, zone);

	// create unsigned answers
	if (ds.count()) {
		plain[Answer::Type::tld_ds] = new Answer(owner, ds, empty, empty, flags | Answer::Flags::auth);
	} else {
		plain[Answer::Type::tld_ds] = new Answer(owner, empty, soa, empty, flags | Answer::Flags::auth);
	}
	plain[Answer::Type::tld_referral] = new Answer(owner, empty, ns, glue, flags);
	plain[Answer::Type::nxdomain] = new Answer(owner, empty, soa, empty, flags | Answer::Flags::auth);

	// create signed answers - signed referral requires signed DS record
	flags = flags | Answer::Flags::dnssec;

	if (ds.count()) {
		dnssec[Answer::Type::tld_ds] = new Answer(owner, ds, empty, empty, flags | Answer::Flags::auth);
	} else {
		dnssec[Answer::Type::tld_ds] = new Answer(owner, empty, signed_soa, empty, flags | Answer::Flags::auth);
	}
	dnssec[Answer::Type::tld_referral] = new Answer(owner, empty, ns + ds, glue, flags);
	dnssec[Answer::Type::nxdomain] = new Answer(owner, empty, signed_soa, empty, flags | Answer::Flags::auth);
}

AnswerSet::AnswerSet(const ldns_dnssec_name* name, const ldns_dnssec_zone *zone, bool compressed)
{
	plain = new Answer*[Answer::Type::max];
	dnssec = new Answer*[Answer::Type::max];

	for (auto i = 0U; i < Answer::Type::max; ++i) {
		plain[i] = nullptr;
		dnssec[i] = nullptr;
	}

	if (name == zone->soa) {
		generate_root_answers(zone, compressed);
	} else {
		generate_tld_answers(name, zone, compressed);
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
