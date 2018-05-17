#include <iostream>
#include <cstdio>
#include <arpa/inet.h>
#include <ldns/dname.h>
#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>
#include <ldns/wire2host.h>

#include "zone.h"

static const unsigned char maptolower[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

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

void Zone::add_name(const ldns_dnssec_name* name, const ldns_dnssec_zone *zone)
{
	auto owner = name->name;
	auto str = ldns_rdf2str(owner);
	auto len = strlen(str) - 1;

	std::string key;
	key.reserve(len);
	for (auto i = 0; i < len; ++i) {
		auto c = static_cast<uint8_t>(str[i]);
		key += maptolower[c];
	}
	free(str);

	data.emplace(key, NameData(name, zone));
}

void Zone::build(const ldns_dnssec_zone* zone)
{
	auto node = ldns_rbtree_first(zone->names);
	while (node != LDNS_RBTREE_NULL) {
		auto name = reinterpret_cast<const ldns_dnssec_name *>(node->data);
		if (!ldns_dnssec_name_is_glue(name)) {
			add_name(name, zone);
		}
		node = ldns_rbtree_next(node);
	}
}

void Zone::load(const std::string& filename)
{
	ldns_dnssec_zone *zone = nullptr;

	auto origin = ldns_dname_new_frm_str(".");
	auto fp = fopen(filename.c_str(), "r");
#pragma GCC diagnostic ignored "-Wunused-variable"
	auto status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 3600, LDNS_RR_CLASS_IN);
	fclose(fp);
	ldns_rdf_free(origin);

	ldns_dnssec_zone_mark_glue(zone);
	build(zone);
	ldns_dnssec_zone_deep_free(zone);
}

Zone::Zone()
{
}

Zone::~Zone()
{
}

int Zone::lookup(const std::string& qname, uint16_t qtype) const
{
	auto itr = data.lower_bound(qname);
	if (itr->first == qname) {
		return 0;
	} else  {
		return 3;
	}
}

int Zone::lookup(const uint8_t* buffer, size_t len) const
{
	if (len < 17) {				// 12 + 1 + 2 + 2
		return LDNS_RCODE_FORMERR;
	}

	auto w = reinterpret_cast<const uint16_t *>(buffer);

	if (buffer[2] & 0x80) {			// QR == 0
		return LDNS_RCODE_FORMERR;	// should just drop
	}

	if ((ntohs(w[1]) & 0x780f) != 0) {	// OPCODE = 0 && RCODE == 0
		return LDNS_RCODE_FORMERR;
	}

	if (w[2] != htons(1)) {			// QDCOUNT == 1
		return LDNS_RCODE_FORMERR;
	}

	auto l = reinterpret_cast<const uint32_t *>(w + 3);
	if (*l) {				// ANCOUNT == 0 && NSCOUNT == 0
		return LDNS_RCODE_FORMERR;
	}

	size_t offset = 12;
	auto last = offset;

	uint8_t c;
	while ((c = buffer[offset++])) {
		if (c & 0xc0) {			// No compression in question
			return LDNS_RCODE_FORMERR;
		}
		last = offset;
		offset += c;
		if (offset > len - 4 || offset > (255 + 12)) {
			return LDNS_RCODE_FORMERR;
		}
	}
	auto qlen = offset - last - 1;

	uint16_t qtype = buffer[offset++] << 8;
	qtype |= buffer[offset++];

	uint16_t qclass = buffer[offset++] << 8;
	qclass |= buffer[offset++];

	// TODO: EDNS decoding

	if (offset != len) {
		return LDNS_RCODE_FORMERR;	// trailing garbage
	}

	// make lower cased qname
	std::string qname;
	qname.resize(qlen);
	auto p = buffer + last;
	std::transform(p, p + qlen, qname.begin(), ::tolower);

	return lookup(qname, qtype);
}
