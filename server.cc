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
	// empty frame
	if (buflen <= 0) return;

	uint8_t headbuf[512];
	ReadBuffer  in	 { buffer, buflen };
	WriteBuffer head { headbuf, sizeof headbuf };
	ReadBuffer  body { nullptr, 0 };

	Context ctx(zone, in, head, body);

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

	if (ctx.execute()) {

		auto payload = head.position() + body.size();

		// update IP length
		if (version == 4) {
			auto& ip = *reinterpret_cast<struct ip*>(head_l3_header);
			ip.ip_len = htons(payload);
			ip.ip_sum = checksum(&ip, sizeof ip);
		}

		// generate the chunks to be sent
		std::vector<iovec> iov = { { head.base(), head.position() } };
		if (body.size()) {
			iov.push_back(iovec {
				const_cast<void*>(body.base()),
				body.size()
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
