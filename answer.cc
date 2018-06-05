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

const Answer* Answer::empty = new Answer(RRList(), RRList(), RRList(), false);

Answer::operator iovec() const
{
	return iovec { buf, size };
}

bool Answer::authoritative() const
{
	return aa_bit;
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
