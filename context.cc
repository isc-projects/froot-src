#include <string>
#include <cstring>
#include <arpa/inet.h>

#include "context.h"
#include "zone.h"
#include "util.h"

struct dnshdr {
	uint16_t	id;
	uint16_t	flags;
	uint16_t	qdcount;
	uint16_t	ancount;
	uint16_t	nscount;
	uint16_t	arcount;
};

struct __attribute__((__packed__)) edns_opt_rr {
	uint8_t		name;
	uint16_t	type;
	uint16_t	bufsize;
	uint8_t		ercode;
	uint8_t		version;
	uint16_t	flags;
	uint16_t	rdlen;
};

static bool valid_header(const dnshdr& h)
{
	// RCODE == 0
	if ((ntohs(h.flags) & 0x000f) != 0) {
		return false;
	}

	// QDCOUNT == 1
	if (htons(h.qdcount) != 1) {
		return false;
	}

	// ANCOUNT == 0 && NSCOUNT == 0
	if (h.ancount || h.nscount) {
		return false;
	}

	// ARCOUNT <= 1
	if (htons(h.arcount) > 1) {
		return false;
	}

	return true;
}

//
// find last label of qname
//
static bool parse_name(ReadBuffer& in, std::string& name, uint8_t& labels)
{
	auto total = 0U;
	auto last = in.position();
	labels = 0;

	while (in.available() > 0) {

		auto c = in.read<uint8_t>();
		if (c == 0) break;

		// remember the start of this label
		last = in.position();
		++labels;

		// No compression in question
		if (c & 0xc0) {
			return false;
		}

		// check maximum name length
		int label_length = c;
		total += label_length;
		total += 1;		// count length byte too

		if (total > 255) {
			return false;
		}

		// consume the label
		(void) in.read<uint8_t>(c);
	}

	// should now be pointing at one beyond the root label
	auto name_length = in.position() - last - 1;

	// make lower cased qname
	auto tmp = strlower(&in[last], name_length);
	std::swap(name, tmp);

	return true;
}

void Context::parse_edns(ReadBuffer& in)
{
	// nothing found
	if (in.available() == 0) {
		return;
	}

	// impossible EDNS length
	if (in.available() > 0 && in.available() < 11) {
		rcode = LDNS_RCODE_FORMERR;
		return;
	}

	// OPT RR must have '.' (\0) as owner name
	auto ch = in.read<uint8_t>();
	if (ch != 0) {
		rcode = LDNS_RCODE_FORMERR;
		return;
	}

	// check the RR type
	auto type = ntohs(in.read<uint16_t>());
	if (type != LDNS_RR_TYPE_OPT) {
		rcode = LDNS_RCODE_FORMERR;
		return;
	}

	// read UDP buffer size, and clamp to minimum
	bufsize = ntohs(in.read<uint16_t>());
	if (bufsize < 512) {
		bufsize = 512;
	}

	(void) in.read<uint8_t>();	// extended rcode
	auto version = in.read<uint8_t>();
	auto flags = ntohs(in.read<uint16_t>());
	auto rdlen = ntohs(in.read<uint16_t>());

	// packet was too short - FORMERR
	if (in.available() < rdlen) {
		rcode = LDNS_RCODE_FORMERR;
		return;
	}

	// skip the EDNS options
	(void) in.read<uint8_t>(rdlen);

	// we got a valid EDNS opt RR, so we need to return one
	has_edns = true;
	do_bit = (flags & 0x8000);

	if (version > 0) {
		rcode = 16;
	}
}

void Context::parse_question(ReadBuffer& in)
{
	qdstart = in.position();

	if (!parse_name(in, qname, qlabels)) {
		rcode = LDNS_RCODE_FORMERR;
		return;
	}

	// ensure there's room for qtype and qclass
	if (in.available() < 4) {
		rcode = LDNS_RCODE_FORMERR;
		return;
	}

	// read qtype and qclass
	qtype = ntohs(in.read<uint16_t>());
	auto qclass = ntohs(in.read<uint16_t>());

	// determine question section length for copying
	// returning before this point will result in an
	// empty question section in responses
	qdsize = in.position() - qdstart;

	// reject meta queries
	if (qtype >= 128 && qtype < LDNS_RR_TYPE_ANY) {
		rcode = LDNS_RCODE_NOTIMPL;
		return;
	}

	// reject unknown qclasses
	if (qclass != LDNS_RR_CLASS_IN) {
		rcode = LDNS_RCODE_NOTIMPL;
		return;
	}
}

void Context::parse_packet(ReadBuffer& in)
{
	rcode = LDNS_RCODE_NOERROR;

	parse_question(in);
	if (rcode != LDNS_RCODE_NOERROR) {
		return;
	}

	parse_edns(in);
	if (rcode != LDNS_RCODE_NOERROR) {
		return;
	}

	// check for trailing garbage
	if (in.available() > 0) {
		rcode = LDNS_RCODE_FORMERR;
		return;
	}
}

const Answer* Context::perform_lookup()
{
	auto* set = zone.lookup(qname, match);
	rcode = match ? LDNS_RCODE_NOERROR : LDNS_RCODE_NXDOMAIN;
	return set->answer(type(), do_bit);
}

bool Context::execute(ReadBuffer& in, std::vector<iovec>& out)
{
	// default answer
	auto answer = Answer::empty;

	// clear the context state
	reset();

	// minimum packet length = 12 + 1 + 2 + 2
	if (in.available() < 17) {
		return false;
	}

	// extract DNS header
	auto rx_hdr = in.read<dnshdr>();

	// drop if the QR bit is set
	if (ntohs(rx_hdr.flags) & 0x8000) {
		return false;
	}

	if (!valid_header(rx_hdr)) {
		rcode = LDNS_RCODE_FORMERR;
	} else {
		uint8_t opcode = (ntohs(rx_hdr.flags) >> 11) & 0x0f;
		if (opcode != LDNS_PACKET_QUERY) {
			rcode = LDNS_RCODE_NOTIMPL;
		} else {
			parse_packet(in);
			if (rcode == LDNS_RCODE_NOERROR) {
				answer = perform_lookup();
			}
		}
	}

	// response bits
	bool aa_bit = answer->authoritative();
	bool tc_bit = false;

#if 0
	// handle truncation
	size_t total_len = sizeof(dnshdr) + qdsize + answer->size() + (sizeof(edns_opt_rr) * has_edns);
	if (total_len > bufsize) {
		tc_bit = true;
		answer = Answer::empty;
	}
#endif

	// craft response header
	auto& tx_hdr = head.reserve<dnshdr>();
	tx_hdr.id = rx_hdr.id;

	// response flags
	uint16_t flags = ntohs(rx_hdr.flags);
	flags &= 0x0110;		// copy RD + CD
	flags |= 0x8000;		// QR
	flags |= (rcode & 0x0f);	// set rcode
	flags |= 0x0200 * tc_bit;	// TC bit
	flags |= 0x0400 * aa_bit;	// AA bit
	tx_hdr.flags = htons(flags);

	// section counts
	tx_hdr.qdcount = htons(qdsize ? 1 : 0);
	tx_hdr.ancount = htons(answer->ancount);
	tx_hdr.nscount = htons(answer->nscount);
	tx_hdr.arcount = htons(answer->arcount + has_edns);

	// copy question section and save
	auto p = &in[qdstart];
	std::copy(p, p + qdsize, head.reserve<uint8_t>(qdsize));
	out.push_back(head);

	// save answer
	if (answer) {
		if (answer == Answer::empty) {
			out.push_back(*answer);
		} else {
			out.push_back(answer->data_offset_by(qdsize, _an_buf));
		}
	}

	// add OPT RR if needed
	if (has_edns) {
		auto& opt = edns.reserve<edns_opt_rr>();
		opt.name = 0;		// "."
		opt.type = htons(LDNS_RR_TYPE_OPT);
		opt.bufsize = htons(1480);
		opt.ercode = (rcode >> 4);
		opt.version = 0;
		opt.flags = htons(do_bit ? 0x8000 : 0);
		opt.rdlen = 0;
		out.push_back(edns);
	}

	return true;
}

Answer::Type Context::type() const
{
	if (!match) {
		return Answer::Type::nxdomain;
	} else if (qlabels > 1) {
		return Answer::Type::tld_referral;
	} else if (qlabels == 1) {
		if (qtype == LDNS_RR_TYPE_DS) {
			return Answer::Type::tld_ds;
		} else {
			return Answer::Type::tld_referral;
		}
	} else  {
		if (qtype == LDNS_RR_TYPE_SOA) {
			return Answer::Type::root_soa;
		} else if (qtype == LDNS_RR_TYPE_NS) {
			return Answer::Type::root_ns;
		} else if (qtype == LDNS_RR_TYPE_NSEC) {
			return Answer::Type::root_nsec;
		} else if (qtype == LDNS_RR_TYPE_DNSKEY) {
			return Answer::Type::root_dnskey;
		} else if (qtype == LDNS_RR_TYPE_ANY) {
			return Answer::Type::root_any;
		} else {
			return Answer::Type::root_nodata;
		}
	}
}

// initial state
void Context::reset()
{
	// clear context variables
        qname.clear();
	qtype = 0;
	qdstart = 0;
	qdsize = 0;
	bufsize = 512;
	qlabels = 0;
	match = false;
	has_edns = false;
	do_bit = false;
	rcode = 0;

	// clear buffer positions
	head.reset();
	edns.reset();
}

Context::Context(const Zone& zone) : zone(zone)
{
}

Context::~Context()
{
}
