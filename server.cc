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
#include "context.h"
#include "util.h"

void Server::load(const std::string& filename)
{
	zone.load(filename);
}

void Server::handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	static ip ip4_out;
	static udphdr udp_out;

	// empty frame
	if (buflen == 0) return;

	// buffer for extracting data
	ReadBuffer in(buffer, buflen);

	// iovecs for sending data
	std::vector<iovec> iov;
	iov.reserve(5);		// L3 + L4 + DNS (header + question) + BODY + EDNS

	// extract L3 header
	auto version = (in[0] >> 4) & 0x0f;

	if (version == 4) {

		iov.push_back( { &ip4_out, sizeof ip4_out } );

		// check IP header length
		auto ihl = 4U * (in[0] & 0x0f);
		if (in.available() < ihl) return;

		// consume IPv4 header, skipping IP options
		auto& ip4_in = in.read<struct ip>();
		if (ihl > sizeof ip4_in) {
			(void) in.read(ihl - sizeof ip4_in);
		}

		// UDP only supported
		if (ip4_in.ip_p != IPPROTO_UDP) return;

		ip4_out.ip_v = 4;
		ip4_out.ip_hl = (sizeof ip4_out) / 4;
		ip4_out.ip_tos = 0;
		ip4_out.ip_len = 0;
		ip4_out.ip_id = ip4_in.ip_id;
		ip4_out.ip_off = 0;
		ip4_out.ip_ttl = 31;
		ip4_out.ip_p = ip4_in.ip_p;
		ip4_out.ip_sum = 0;
		ip4_out.ip_src = ip4_in.ip_dst;
		ip4_out.ip_dst = ip4_in.ip_src;

	} else if (version == 6) {

		// TODO: IPv6 support
		return;

	}

	// consume L4 UDP header
	if (in.available() < sizeof(udphdr)) return;
	auto& udp_in = in.read<udphdr>();

	// require expected dest port
	if (udp_in.uh_dport != htons(8053)) return;

	// ignore illegal source ports
	auto sport = ntohs(udp_in.uh_sport);
	if (sport == 0 || sport == 7 || sport == 123) return;

	// populate response fields
	udp_out.uh_sport = udp_in.uh_dport;
	udp_out.uh_dport = udp_in.uh_sport;
	udp_out.uh_sum = 0;
	udp_out.uh_ulen = 0;

	iov.push_back( { &udp_out, sizeof udp_out } );

	// created on stack here to avoid use of the heap
	Context ctx(zone, in);

	if (ctx.execute(iov)) {

		// calculate total length
		size_t ip_len = 0;
		for (auto v : iov) {
			ip_len += v.iov_len;
		}

		// update IP length
		if (version == 4) {
			ip4_out.ip_len = htons(ip_len);
			ip4_out.ip_sum = checksum(&ip4_out, sizeof ip4_out);
		}

		// update UDP length
		udp_out.uh_ulen = htons(ip_len - iov[0].iov_len);

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
		ssize_t n = ::sendmsg(s.fd, &msg, MSG_DONTWAIT);
		if (n < 0) {
			perror("sendmsg");
		}
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
