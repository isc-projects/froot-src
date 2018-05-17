#include <arpa/inet.h>
#include "server.h"
#include "util.h"

Server::Server()
{
}

Server::~Server()
{
}

void Server::load(const std::string& filename)
{
	zone.load(filename);
}

int Server::query(const uint8_t* buffer, size_t len) const
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
	auto qname = strlower(&buffer[last], qlen);

	return zone.lookup(qname);
}
