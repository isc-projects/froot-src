#include <cstring>
#include <arpa/inet.h>
#include <ldns/packet.h>

#include "parser.h"
#include "util.h"

struct dnshdr {
	uint16_t	id;
	uint16_t	flags;
	uint16_t	qdcount;
	uint16_t	ancount;
	uint16_t	nscount;
	uint16_t	arcount;
};

//
// reject headers that don't merit any response at all
//
static bool legal_header(const ReadBuffer& in)
{
	// minimum packet length = 12 + 1 + 2 + 2
	if (in.available() < 17) {
		return false;
	}

	// QR is set inbound
	auto header = in.current();
	if (header[2] & 0x80) {
		return false;
	}

	return true;
}

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
static bool parse_qname(ReadBuffer& in, std::string& qname, unsigned& labels)
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
		(void) in.read_array<uint8_t>(c);
	}

	// should now be pointing at one beyond the root label
	auto qname_length = in.position() - last - 1;

	// make lower cased qname
	qname.assign(strlower(&in[last], qname_length));

	return true;
}

#if 0
static bool parse_edns(ReadBuffer& in, uint16_t bufsize, bool& do_bit)
{
	bufsize = 512;
	do_bit = false;

	return true;
}
#endif

static const Answer* lookup(const Zone& zone, ReadBuffer& in, size_t& qdsize, ldns_enum_pkt_rcode& rcode)
{
	bool match = false;
	unsigned labels = 0;
	qdsize = 0;

	size_t qdstart = in.position();

	std::string qname;
	if (!parse_qname(in, qname, labels)) {
		rcode = LDNS_RCODE_FORMERR;
		return nullptr;
	}

	// ensure there's room for qtype and qclass
	if (in.available() < 4) {
		rcode = LDNS_RCODE_FORMERR;
		return nullptr;
	}

	// read qtype and qclass
	auto qtype = ntohs(in.read<uint16_t>());// qtype
	auto qclass = ntohs(in.read<uint16_t>());	// qclass

	// determine question section length for copying
	// returning before this point will result in an
	// empty question section in responses
	qdsize = in.position() - qdstart;

	// reject unknown qclasses
	if (qclass != LDNS_RR_CLASS_IN) {
		rcode = LDNS_RCODE_NOTIMPL;
		return nullptr;
	}

	// TODO: EDNS decoding
	bool do_bit = false;

	// apparent bug in AF_PACKET sets min size to 46
	if (in.available() > 0 && in.size() > 46) {
		rcode = LDNS_RCODE_FORMERR;	// trailing garbage
		return nullptr;
	}

	auto& data = zone.lookup(qname, match);
	rcode = match ? LDNS_RCODE_NOERROR : LDNS_RCODE_NXDOMAIN;

	return data.answer(rcode, labels, match, qtype, do_bit);
}

bool parse_query(const Zone& zone, ReadBuffer& in, WriteBuffer& head, ReadBuffer& body)
{
	// drop invalid packets
	if (!legal_header(in)) {
		return false;
	}

	ldns_enum_pkt_rcode rcode;
	size_t qdsize = 0;

	// extract DNS header
	auto rx_hdr = in.read<dnshdr>();

	// mark start of question section
	auto qdstart = in.current();

	const Answer *answer = nullptr;

	if (!valid_header(rx_hdr)) {
		rcode = LDNS_RCODE_FORMERR;
	} else {
		uint8_t opcode = (ntohs(rx_hdr.flags) >> 11) & 0x0f;
		if (opcode != LDNS_PACKET_QUERY) {
			rcode = LDNS_RCODE_NOTIMPL;
		} else {
			answer = lookup(zone, in, qdsize, rcode);
			if (answer) {
				body = answer->data();
			}
		}
	}

	// craft response header
	auto& tx_hdr = head.write<dnshdr>();
	tx_hdr.id = rx_hdr.id;

	uint16_t flags = ntohs(rx_hdr.flags);
	flags &= 0x0110;		// copy RD + CD
	flags |= 0x8000;		// QR
	flags |= (rcode & 0x0f);	// set rcode
	if (answer && answer->authoritative()) {
		flags |= 0x0400;	// AA bit
	}
	tx_hdr.flags = htons(flags);

	// section counts
	tx_hdr.qdcount = htons(qdsize ? 1 : 0);
	tx_hdr.ancount = htons(answer ? answer->ancount : 0);
	tx_hdr.nscount = htons(answer ? answer->nscount : 0);
	tx_hdr.arcount = htons(answer ? answer->arcount : 0);

	// copy question section
	::memcpy(head.write(qdsize), qdstart, qdsize);

	return true;
}
