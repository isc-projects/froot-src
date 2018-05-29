#include <ldns/dname.h>
#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>
#include <ldns/wire2host.h>
#include <ldns/host2wire.h>

#include "answer.h"
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

Answer* Answer::empty = new Answer(nullptr, nullptr, nullptr, false);

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
