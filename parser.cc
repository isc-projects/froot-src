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

static const Answer* lookup(const Zone& zone, ReadBuffer& in, size_t& qdsize, bool& match, ldns_enum_pkt_rcode& rcode)
{
	match = false;

	size_t qdstart = in.position();
	qdsize = 0;
	auto last = qdstart;
	auto total = 0U;

	// find last label of qname

	while (in.available() > 0) {

		auto c = in.read<uint8_t>();
		if (c == 0) break;

		// remember the start of this label
		last = in.position();

		// No compression in question
		if (c & 0xc0) {
			rcode = LDNS_RCODE_FORMERR;
			return nullptr;
		}

		// check maximum name length
		int label_length = c;
		total += label_length;
		total += 1;		// count length byte too

		if (total > 255) {
			rcode = LDNS_RCODE_FORMERR;
			return nullptr;
		}

		// consume the label
		(void) in.read_array<uint8_t>(c);
	}

	// ensure there's room for qtype and qclass
	if (in.available() < 4) {
		rcode = LDNS_RCODE_FORMERR;
		return nullptr;
	}

	// should now be pointing at one beyond the root label
	auto qname_length = in.position() - last - 1;

	// read qtype and qclass
	(void) ntohs(in.read<uint16_t>());	// qtype
	(void) ntohs(in.read<uint16_t>());	// qclass

	// TODO: parse qtype and qclass

	// TODO: EDNS decoding

	if (in.available() > 0) {
		rcode = LDNS_RCODE_FORMERR;	// trailing garbage
		return nullptr;
	}

	// determine question section length for copying
	qdsize = in.position() - qdstart;

	// make lower cased qname
	auto qname = strlower(&in[last], qname_length);

	match = false;
	auto& data = zone.lookup(qname, match);
	rcode = match ? LDNS_RCODE_NOERROR : LDNS_RCODE_NXDOMAIN;

	return data.answer(rcode);		// TODO: more flags
}

bool parse_query(const Zone& zone, ReadBuffer& in, WriteBuffer& head, ReadBuffer& body)
{
	// drop invalid packets
	if (!legal_header(in)) {
		return false;
	}

	ldns_enum_pkt_rcode rcode;
	bool match = false;
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
			answer = lookup(zone, in, qdsize, match, rcode);
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
	flags |= 0x0000;		// TODO: AA bit
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
