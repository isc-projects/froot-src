#include <iostream>
#include <functional>

#include <sys/types.h>
#include <sys/socket.h>

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

	// QR is set inbound
	if (buffer[2] & 0x80) {
		return false;
	}

	return true;
}

static bool valid_format(const uint8_t* buffer, size_t len)
{
	auto w = reinterpret_cast<const uint16_t *>(buffer);

	// RCODE == 0
	if ((ntohs(w[1]) & 0x000f) != 0) {
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

int Server::query(const uint8_t* buffer, size_t len, size_t& qdsize) const
{
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
	auto qname_length = offset - last - 1;

	uint16_t qtype = buffer[offset++] << 8;
	qtype |= buffer[offset++];

	uint16_t qclass = buffer[offset++] << 8;
	qclass |= buffer[offset++];

	// TODO: EDNS decoding

	if (offset != len) {
		return LDNS_RCODE_FORMERR;	// trailing garbage
	}

	// determine question section length for copying
	qdsize = offset - 12;

	// make lower cased qname
	auto qname = strlower(&buffer[last], qname_length);

	bool match = false;
	auto iter = zone.lookup(qname, match);

	// name not found, get its predecessor for NSECs
	if (!match) {
		--iter;
	}

	return match ? LDNS_RCODE_NOERROR : LDNS_RCODE_NXDOMAIN;
}

bool Server::handle_packet_dns(uint8_t* buffer, size_t buflen, uint8_t* outbuf, size_t& outoff)
{
	hexdump(std::cerr, buffer, buflen);

	// drop invalid packets
	if (!valid_header(buffer, buflen)) {
		return false;
	}

	uint16_t rcode;
	size_t qdsize = 0;

	if (!valid_format(buffer, buflen)) {
		rcode = LDNS_RCODE_FORMERR;
	} else {
		uint8_t opcode = (buffer[2] >> 3) & 0x0f;
		if (opcode != LDNS_PACKET_QUERY) {
			rcode = LDNS_RCODE_NOTIMPL;
		} else {
			rcode = query(buffer, buflen, qdsize);
		}
	}

	// craft response header
	auto* tx_header = reinterpret_cast<uint16_t*>(outbuf + outoff);
	auto* rx_header = reinterpret_cast<uint16_t*>(buffer);
	outoff += 12;

	tx_header[0] = rx_header[0];

	uint16_t flags = ntohs(rx_header[1]);
	flags &= 0x0110;		// copy RD + CD
	flags |= 0x8000;		// QR
	flags |= (rcode & 0x0f);	// set rcode
	flags |= 0x0000;		// TODO: AA bit

	tx_header[1] = htons(flags);
	tx_header[2] = htons(qdsize ? 1 : 0);	// QDCOUNT
	tx_header[3] = htons(0);	// TODO: ANCOUNT
	tx_header[4] = htons(0);	// TODO: NSCOUNT
	tx_header[5] = htons(0);	// TODO: ARCOUNT

	// copy qustion section
	memcpy(outbuf + outoff, buffer + 12, qdsize);
	outoff += qdsize;

	return true;
}

void Server::handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	// empty frame
	if (buflen <= 0) return;

	uint8_t outbuf[512];
	size_t outoff = 0;

	auto ip4p = reinterpret_cast<ip*>(outbuf + outoff);

	// extract L3 header
	auto version = (buffer[0] >> 4) & 0x0f;

	if (version == 4) {
		// IP header too short
		if (buflen < sizeof *ip4p) return;

		// consume IPv4 header, skipping IP options
		auto& l3 = *reinterpret_cast<ip*>(buffer);
		auto ihl = 4 * l3.ip_hl;
		buffer += ihl;
		buflen -= ihl;

		// UDP only supported
		if (l3.ip_p != IPPROTO_UDP) return;

		// populate reply header
		auto& ip = *ip4p;
		outoff += sizeof l3;

		ip.ip_v = 4;
		ip.ip_hl = (sizeof ip) / 4;
		ip.ip_tos = 0;
		ip.ip_len = 0;
		ip.ip_id = l3.ip_id;
		ip.ip_off = 0;
		ip.ip_ttl = 31;
		ip.ip_p = l3.ip_p;
		ip.ip_sum = 0;		// TODO: calculate
		ip.ip_src = l3.ip_dst;
		ip.ip_dst = l3.ip_src;

	} else if (version == 6) {
		return;
	}

	// consume L4 header
	if (buflen < sizeof(udphdr)) return;
	auto l4 = *reinterpret_cast<udphdr*>(buffer);
	buffer += sizeof l4;
	buflen -= sizeof l4;

	// require expected dest port
	if (l4.uh_dport != htons(8053)) return;

	// ignore illegal source ports
	if (l4.uh_sport == htons(0) || l4.uh_sport == htons(7) || l4.uh_sport == htons(123)) return;

	// populate response fields
	auto udpoff = outoff;
	auto& udp = *reinterpret_cast<udphdr*>(outbuf + udpoff);
	outoff += sizeof(udp);

	udp.uh_sport = l4.uh_dport;
	udp.uh_dport = l4.uh_sport;
	udp.uh_sum = 0;
	udp.uh_ulen = 0;

	if (handle_packet_dns(buffer, buflen, outbuf, outoff)) {

		// update IP length
		if (version == 4) {
			auto& ip = *ip4p;
			ip.ip_len = htons(outoff);
			ip.ip_sum = checksum(&ip, sizeof ip);
		}

		// update UDP length
		udp.uh_ulen = htons(outoff - udpoff);

		// construct response message
		msghdr msg;
		iovec iov[] = { { outbuf, outoff } };

		msg.msg_name = reinterpret_cast<void*>(const_cast<sockaddr_ll*>(addr));
		msg.msg_namelen = sizeof(sockaddr_ll);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = nullptr;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;

		// and send it on
		::sendmsg(s.fd, &msg, MSG_DONTWAIT);
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
