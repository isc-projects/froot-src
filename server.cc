#include <iostream>
#include <functional>
#include <vector>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "server.h"
#include "util.h"

struct dnshdr {
	uint16_t	id;
	uint16_t	flags;
	uint16_t	qdcount;
	uint16_t	ancount;
	uint16_t	nscount;
	uint16_t	arcount;
};

void Server::load(const std::string& filename)
{
	zone.load(filename);
}

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

const Answer* Server::query(ReadBuffer& in, size_t& qdsize, bool& match, ldns_enum_pkt_rcode& rcode) const
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

bool Server::handle_packet_dns(ReadBuffer& in, WriteBuffer& head, ReadBuffer& body)
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
			answer = query(in, qdsize, match, rcode);
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

void Server::handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	// empty frame
	if (buflen <= 0) return;

	uint8_t headbuf[512];
	ReadBuffer  in	 { buffer, buflen };
	WriteBuffer head { headbuf, sizeof headbuf };
	ReadBuffer  body { nullptr, 0 };

	auto head_l3_header = head.base();

	// extract L3 header
	auto version = (in[0] >> 4) & 0x0f;

	if (version == 4) {

		// check IP header length
		auto ihl = 4U * (in[0] & 0x0f);
		if (in.available() < ihl) return;

		// consume IPv4 header, skipping IP options
		auto& l3 = in.read<struct ip>();
		if (ihl > sizeof l3) {
			(void) in.read(ihl - sizeof l3);
		}

		// UDP only supported
		if (l3.ip_p != IPPROTO_UDP) return;

		// populate reply header
		auto& ip = head.write<struct ip>();

		ip.ip_v = 4;
		ip.ip_hl = (sizeof ip) / 4;
		ip.ip_tos = 0;
		ip.ip_len = 0;
		ip.ip_id = l3.ip_id;
		ip.ip_off = 0;
		ip.ip_ttl = 31;
		ip.ip_p = l3.ip_p;
		ip.ip_sum = 0;
		ip.ip_src = l3.ip_dst;
		ip.ip_dst = l3.ip_src;

	} else if (version == 6) {
		return;
	}

	// consume L4 header
	if (in.available() < sizeof(udphdr)) return;
	auto& l4 = in.read<udphdr>();

	// require expected dest port
	if (l4.uh_dport != htons(8053)) return;

	// ignore illegal source ports
	if (l4.uh_sport == htons(0) || l4.uh_sport == htons(7) || l4.uh_sport == htons(123)) return;

	// remember the start of the UDP header
	auto udpoff = head.position();

	// populate response fields
	auto& udp = head.write<udphdr>();
	udp.uh_sport = l4.uh_dport;
	udp.uh_dport = l4.uh_sport;
	udp.uh_sum = 0;
	udp.uh_ulen = 0;

	if (handle_packet_dns(in, head, body)) {

		auto payload = head.position() + body.position();

		// update IP length
		if (version == 4) {
			auto& ip = *reinterpret_cast<struct ip*>(head_l3_header);
			ip.ip_len = htons(payload);
			ip.ip_sum = checksum(&ip, sizeof ip);
		}

		// generate the chunks to be sent
		std::vector<iovec> iov = { { head.base(), head.position() } };
		if (body.position()) {
			iov.push_back(iovec {
				const_cast<void*>(body.base()),
				body.position()
			});
		}

		// update UDP length
		udp.uh_ulen = htons(payload - udpoff);

		// construct response message
		msghdr msg;
		msg.msg_name = reinterpret_cast<void*>(const_cast<sockaddr_ll*>(addr));
		msg.msg_namelen = sizeof(sockaddr_ll);
		msg.msg_iov = iov.data();
		msg.msg_iovlen = iov.size();
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
