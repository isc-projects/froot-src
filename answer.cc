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

Answer* Answer::empty = new Answer(RRList(), RRList(), RRList(), false);

ReadBuffer Answer::data() const
{
	return *buffer;
}

bool Answer::authoritative() const
{
	return aa_bit;
}

Answer::Answer(const RRList& an, const RRList& ns, const RRList& ar, bool aa_bit) : aa_bit(aa_bit)
{
	size_t n = 4096;
	auto lbuf = ldns_buffer_new(n);

	ancount = an.count();
	nscount = ns.count();
	arcount = ar.count();

	an.to_buffer_wire(lbuf, LDNS_SECTION_ANSWER);
	ns.to_buffer_wire(lbuf, LDNS_SECTION_AUTHORITY);
	ar.to_buffer_wire(lbuf, LDNS_SECTION_ADDITIONAL);

	auto size = ldns_buffer_position(lbuf);
	auto p = reinterpret_cast<uint8_t*>(ldns_buffer_export(lbuf));
	ldns_buffer_free(lbuf);

	buffer = new ReadBuffer(p, size);
}

Answer::~Answer()
{
	auto p = buffer->base();
	delete buffer;
	free(const_cast<void*>(p));
}
