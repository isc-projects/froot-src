#include <iostream>
#include <functional>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "server.h"
#include "util.h"

void Server::load(const std::string& filename)
{
	zone.load(filename);
}

static bool valid_header(const uint8_t* buffer, size_t len)
{
	// minimum packet length = 12 + 1 + 2 + 2
	if (len < 17) {
		return false;
	}

	auto w = reinterpret_cast<const uint16_t *>(buffer);

	// OPCODE = 0 && RCODE == 0
	if ((ntohs(w[1]) & 0x780f) != 0) {
		return false;
	}

	// QDCOUNT == 1
	if (htons(w[2]) != 1) {
		return false;
	}

	// ANCOUNT == 0 && NSCOUNT == 0
	auto l = reinterpret_cast<const uint32_t *>(buffer + 6);
	if (*l) {
		return false;
	}

	// ARCOUNT <= 1
	if (htons(w[5]) > 1) {
		return false;
	}

	return true;
}

int Server::query(const uint8_t* buffer, size_t len) const
{
	if (!valid_header(buffer, len)) {
		return LDNS_RCODE_FORMERR;
	}

	if (buffer[2] & 0x80) {			// QR == 0
		return LDNS_RCODE_FORMERR;	// should just drop
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

	bool match = false;
	auto iter = zone.lookup(qname, match);

	if (!match) {
		--iter;
	}

	return match ? LDNS_RCODE_NOERROR : LDNS_RCODE_NXDOMAIN;
}

void Server::handle_packet_udp(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	// UDP header too short
	if (buflen < sizeof(udphdr)) return;

	auto& udp = *reinterpret_cast<udphdr*>(buffer);
	if (udp.uh_dport != htons(53)) return;

	buffer += sizeof udp;
	buflen -= sizeof udp;

	(void) query(buffer, buflen);
}

void Server::handle_packet_ipv4(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	// IP header too short
	if (buflen < sizeof(iphdr)) return;

	auto& ip = *reinterpret_cast<iphdr*>(buffer);
	if (ip.protocol != IPPROTO_UDP) return;

	// move to UDP header
	auto ihl = 4 * ip.ihl;
	buffer += ihl;
	buflen -= ihl;

	return handle_packet_udp(s, buffer, buflen, addr, userdata);
}

void Server::handle_packet_ipv6(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
}

void Server::handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	// empty frame
	if (!buflen) return;

	auto version = (buffer[0] >> 4) & 0x0f;
	if (version == 4) {
		handle_packet_ipv4(s, buffer, buflen, addr, userdata);
	} else if (version == 6) {
		handle_packet_ipv6(s, buffer, buflen, addr, userdata);
	}
}

void Server::loop(PacketSocket& s)
{
	using namespace std::placeholders;
	PacketSocket::rx_callback_t callback = std::bind(&Server::handle_packet, this, _1, _2, _3, _4, _5);
	while (true) {
		s.rx_ring_next(callback, -1, nullptr);
	}
}

void Server::worker(const std::string& ifname)
{
	try {
		PacketSocket socket;
		socket.open();
		socket.bind(ifname);
		socket.rx_ring_enable(11, 128);	// frame size = 2048
		loop(socket);
	} catch (std::exception& e) {
		std::cerr << "worker error: " << e.what() << std::endl;
	}
}

Server::Server()
{
}

Server::~Server()
{
}
