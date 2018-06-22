#include <iostream>
#include <functional>
#include <vector>
#include <thread>
#include <chrono>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "server.h"
#include "context.h"
#include "timer.h"
#include "util.h"

static void loader_thread(Zone& zone, std::string filename, bool compress)
{
	timespec mtim = { 0, 0 };

	while (true) {
		struct stat st;
		if (::stat(filename.c_str(), &st) == 0) {
			if (!(st.st_mtim == mtim)) {
				mtim = st.st_mtim;
				zone.load(filename, compress);
			}
		}
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void Server::load(const std::string& filename, bool compress)
{
	auto t = std::thread(loader_thread, std::ref(zone), filename, compress);
	t.detach();
}

void dump(const std::vector<iovec>& iov, size_t n)
{
	size_t total = 0;
	for (auto i = 0U; i < n; ++i) {
		fprintf(stderr, "%16p %4ld\n", iov[i].iov_base, iov[i].iov_len);
		total += iov[i].iov_len;
	}
	fprintf(stderr, "total len = %ld\n", total);
}

void Server::send(PacketSocket& s, msghdr& msg, std::vector<iovec>& iov) const
{
	auto& ip = *reinterpret_cast<struct ip*>(iov[0].iov_base);

	// determine maximum payload fragment size
	auto mtu = s.getmtu();
	auto max_frag = mtu - sizeof ip;

	// state variables
	auto iter = iov.begin() + 1;
	auto chunk = 0U;
	auto offset = 0U;

	while (iter != iov.end()) {

		auto& vec = *iter++;
		auto p = reinterpret_cast<uint8_t*>(vec.iov_base);
		auto len = vec.iov_len;
		chunk += len;

		// did we take too much?
		if (chunk > max_frag) {

			// how much too much?
			auto excess = chunk - max_frag;
			chunk -= excess;

			// frags need to be a multiple of 8 in length
			auto round = chunk % 8;
			chunk -= round;
			excess += round;

			// adjust this iovec's len to the new total length
			vec.iov_len -= excess;

			// and insert a new iovec after this one that holds the left-overs
			// assignment necessary in case old iterator is invalidated
			iter = iov.insert(iter, iovec { p + vec.iov_len, len - vec.iov_len});

			// determine the number of iovecs to send
			msg.msg_iov = iov.data();
			msg.msg_iovlen = iter - iov.begin();

			// send here
			ip.ip_len = htons(chunk + sizeof ip);
			ip.ip_off = htons(0x2000 | (offset >> 3));
			ip.ip_sum = 0;
			ip.ip_sum = checksum(&ip, sizeof ip);

			if (::sendmsg(s.fd, &msg, 0) < 0) {
				perror("sendmsg");
			}

			// remove the already transmitted iovecs (excluding the IP header)
			iter = iov.erase(iov.begin() + 1, iter);

			// start collecting the next chunk
			offset += chunk;
			chunk = 0;
		}
	}

	msg.msg_iov = iov.data();
	msg.msg_iovlen = iov.size();

	ip.ip_len = htons(chunk + sizeof ip);
	ip.ip_off = htons(offset >> 3);
	ip.ip_sum = 0;
	ip.ip_sum = checksum(&ip, sizeof ip);
	if (::sendmsg(s.fd, &msg, 0) < 0) {
		perror("sendmsg");
	}
}

void Server::handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	ip ip4_out;
	udphdr udp_out;

	// empty frame
	if (buflen == 0) return;

	// buffer for extracting data
	ReadBuffer in(buffer, buflen);

	// iovecs for sending data
	std::vector<iovec> iov;
	iov.reserve(5);		// 5 = L3 + L4 + DNS (header + question) + BODY + EDNS

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
			(void) in.read<uint8_t>(ihl - sizeof ip4_in);
		}

		// hack for broken AF_PACKET size - recreate the buffer
		// based on the IP header specified length instead of what
		// was returned by the AF_PACKET layer
		if (in.size() == 46) {
			size_t pos = in.position();
			size_t len = ntohs(ip4_in.ip_len);
			if (len < 46) {
				in = ReadBuffer(buffer, len);
				(void) in.read<uint8_t>(pos);
			}
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
	if (udp_in.uh_dport != port) return;

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
	Context ctx(zone);

	if (ctx.execute(in, iov)) {

		// calculate UDP length
		size_t udp_len = 0;
		for (auto iter = iov.cbegin() + 1; iter != iov.cend(); ++iter) {
			udp_len += iter->iov_len;
		}
		udp_out.uh_ulen = htons(udp_len);

		// construct response message
		msghdr msg;
		msg.msg_name = reinterpret_cast<void*>(const_cast<sockaddr_ll*>(addr));
		msg.msg_namelen = sizeof(sockaddr_ll);
		msg.msg_control = nullptr;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;

		// and send it on
		send(s, msg, iov);
	}
}

void Server::worker(PacketSocket& s, uint16_t _port)
{
	// set listening port
	port = ntohs(_port);

	using namespace std::placeholders;
	PacketSocket::rx_callback_t callback =
		std::bind(&Server::handle_packet, this, _1, _2, _3, _4, _5);

	try {
		while (true) {
			s.rx_ring_next(callback, -1, nullptr);
		}
	} catch (std::exception& e) {
		std::cerr << "worker error: " << e.what() << std::endl;
	}
}

Server::Server() : port(htons(8053))
{
}

Server::~Server()
{
}
