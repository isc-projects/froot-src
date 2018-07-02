#include <cstring>
#include <iostream>
#include <functional>
#include <numeric>
#include <vector>
#include <thread>
#include <random>
#include <chrono>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "checksum.h"
#include "server.h"
#include "context.h"
#include "timer.h"
#include "util.h"

static size_t payload_length(const std::vector<iovec>& iov)
{
	return std::accumulate(iov.cbegin() + 1, iov.cend(), 0U,
		[](size_t a, const iovec& b) {
			return a + b.iov_len;
		}
	);
}

static ssize_t sendmsg(int fd, const sockaddr_ll* addr, std::vector<iovec>& iov, size_t iovlen)
{
	msghdr msg;

	msg.msg_name = reinterpret_cast<void*>(const_cast<sockaddr_ll*>(addr));
        msg.msg_namelen = sizeof(sockaddr_ll);
        msg.msg_control = nullptr;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
	msg.msg_iov = iov.data();
	msg.msg_iovlen = iovlen;

	auto res = ::sendmsg(fd, &msg, 0);
	if (res < 0) {
		perror("sendmsg");
	}
	return res;
}

static void sendfrag_ipv4(int fd, const sockaddr_ll* addr, uint16_t offset, uint16_t chunk, std::vector<iovec>& iov, size_t iovlen, bool mf)
{
	// calculate offsets and populate IP header
	auto& ip = *reinterpret_cast<struct ip*>(iov[0].iov_base);
	ip.ip_len = htons(chunk + sizeof ip);
	ip.ip_off = htons((mf << 13) | (offset >> 3));
	ip.ip_sum = 0;
	ip.ip_sum = Checksum().add(&ip, sizeof ip).value();

	sendmsg(fd, addr, iov, iovlen);
}

//
// send an IPv4 packet, fragmented per the interface MTU
//
static void send_ipv4(PacketSocket& s, const sockaddr_ll* addr, std::vector<iovec>& iov)
{
	thread_local auto rnd = std::mt19937(std::chrono::system_clock::now().time_since_epoch().count() + 1);

	// set a random packet ID
	auto& ip = *reinterpret_cast<struct ip*>(iov[0].iov_base);
	ip.ip_id = rnd();

	// determine maximum payload fragment size
	auto mtu = s.getmtu();
	auto max_frag = mtu - sizeof(struct ip);

	// state variables
	auto chunk = 0U;
	auto offset = 0U;

	auto iter = iov.begin() + 1;
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

			// send fragment (with MF bit)
			sendfrag_ipv4(s.fd, addr, offset, chunk,  iov, iter - iov.begin(), true);

			// remove the already transmitted iovecs (excluding the IP header)
			iter = iov.erase(iov.begin() + 1, iter);

			// start collecting the next chunk
			offset += chunk;
			chunk = 0;
		}
	}

	// send final fragment
	sendfrag_ipv4(s.fd, addr, offset, chunk, iov, iov.size(), false);
}

void Server::handle_udp(PacketSocket&s, ReadBuffer& in, const sockaddr_ll* addr, std::vector<iovec>& iov)
{
	// consume L4 UDP header
	if (in.available() < sizeof(udphdr)) return;
	auto& udp_in = in.read<udphdr>();

	// require expected dest port
	if (udp_in.uh_dport != port) return;

	// ignore illegal source ports
	auto sport = ntohs(udp_in.uh_sport);
	if (sport == 0 || sport == 7 || sport == 123) return;

	// populate response fields
	udphdr udp_out;
	udp_out.uh_sport = udp_in.uh_dport;
	udp_out.uh_dport = udp_in.uh_sport;
	udp_out.uh_sum = 0;
	udp_out.uh_ulen = 0;

	// iovecs for sending data
	iov.push_back( { &udp_out, sizeof udp_out } );

	// created on stack here to avoid use of the heap
	Context ctx(zone);

	if (ctx.execute(in, iov)) {

		// update UDP length
		udp_out.uh_ulen = htons(payload_length(iov));

		// and send the message
		send_ipv4(s, addr, iov);
	}
}

struct __attribute__((packed)) tcp_mss_opt {
	uint8_t		type;
	uint8_t		len;
	uint16_t	mss;
};

static void tcp_checksum(std::vector<iovec>& iov)
{
	auto& ip = *reinterpret_cast<struct ip*>(iov[0].iov_base);
	auto& tcp = *reinterpret_cast<tcphdr*>(iov[1].iov_base);

	// clear staring checksum
	tcp.th_sum = 0;

	// add pseudo header
	Checksum crc;
	crc.add(&ip.ip_src, sizeof ip.ip_src);
	crc.add(&ip.ip_dst, sizeof ip.ip_dst);
	crc.add(ip.ip_p);
	crc.add(payload_length(iov));

	// payload
	for (auto iter = iov.cbegin() + 1; iter != iov.cend(); ++iter) {
		crc.add(*iter);
	}

	// save the result in the packet
	tcp.th_sum = crc.value();
}

static void send_tcp_flags(PacketSocket&s, const sockaddr_ll* addr, std::vector<iovec>& iov, uint8_t flags)
{
	thread_local auto rnd = std::mt19937(std::chrono::system_clock::now().time_since_epoch().count());

	// generate TCP outbound header from inbound header
	auto& tcp = *reinterpret_cast<tcphdr*>(iov[1].iov_base);

	uint32_t ack = ntohl(tcp.th_ack);
	uint32_t seq = ntohl(tcp.th_seq);

	if (flags == (TH_SYN + TH_ACK)) {
		tcp.th_seq = rnd();
	} else {
		tcp.th_seq = ntohl(ack);
	}
	tcp.th_ack = htonl(seq + 1);
	tcp.th_flags = flags;
	tcp_checksum(iov);

	send_ipv4(s, addr, iov);
}

//
// assumes that iov[0] contains the IP header and iov[1] contains the TCP header
//
static void send_tcp_data(PacketSocket&s, const sockaddr_ll* addr, std::vector<iovec>& iov, uint16_t acked)
{
	// generate TCP outbound header from inbound header
	auto& tcp = *reinterpret_cast<tcphdr*>(iov[1].iov_base);

	uint32_t ack = ntohl(tcp.th_ack);
	uint32_t seq = ntohl(tcp.th_seq);

	tcp.th_ack = htonl(seq + acked);
	tcp.th_seq = htonl(ack);
	tcp.th_flags = TH_ACK;

	// use a copy of the vector because send_ipv4() will mutate it
	std::vector<iovec> out = { iov[0], iov[1] };
	out.reserve(5);

	// state variables
	auto segment = 0U;
	uint16_t mss = s.getmss();

	auto iter = iov.begin() + 2;
	while (iter != iov.end()) {

		// take the current iovec
		auto vec = *iter++;
		auto len = vec.iov_len;
		segment += len;

		// copy it to the output list
		out.push_back(vec);

		// did we take too much?
		if (segment > mss) {

			// how much too much?
			auto excess = segment - mss;
			segment = mss;

			// adjust the output iovec's len to the new total length
			vec.iov_len -= excess;
			out.back() = vec;

			// insert a new iovec in the input list that holds the left-overs
			// assignment necessary in case old iterator is invalidated
			auto p = reinterpret_cast<uint8_t*>(vec.iov_base);
			iter = iov.insert(iter, iovec { p + vec.iov_len, len - vec.iov_len});

			// send segment
			tcp_checksum(out);
			send_ipv4(s, addr, out);

			// remove the already transmitted iovecs (excluding the IP and TCP headers)
			iter = iov.erase(iov.begin() + 2, iter);

			// get ready for the next segment
			tcp.th_seq = htonl(ntohl(tcp.th_seq) + segment);
			out.resize(2);
			out[0] = iov[0];
			out[1] = iov[1];
			segment = 0;
		}
	}

	// send final segment
	tcp.th_flags |= TH_FIN;

	tcp_checksum(iov);
	send_ipv4(s, addr, iov);
}

void Server::handle_tcp(PacketSocket&s, ReadBuffer& in, const sockaddr_ll* addr, std::vector<iovec>& iov)
{
	// consume L4 UDP header
	if (in.available() < sizeof(tcphdr)) return;
	auto& tcp_in = in.read<tcphdr>();

	// require expected dest port
	if (tcp_in.th_dport != port) return;

	// find data
	auto offset = 4U * tcp_in.th_off;

	// ignore illegal packets
	if (offset < sizeof tcp_in) return;
	auto skip = offset - sizeof tcp_in;

	// skip any options
	if (in.available() < skip) return;
	(void) in.read<uint8_t>(skip);

	// create buffer large enough for a TCP header and MSS option
	uint8_t buf[sizeof(tcp_in) + sizeof(tcp_mss_opt)];
	WriteBuffer out(buf, sizeof(buf));

	// copy the TCP header, swapping source and dest ports
	auto& tcp = out.write<tcphdr>(tcp_in);
	std::swap(tcp.th_sport, tcp.th_dport);

	// and set our outbound TCP parameters
	tcp.th_win = htons(65535U);
	tcp.th_urp = 0;

	// add MSS option on initial syn
	if (tcp_in.th_flags & TH_SYN) {
		tcp_mss_opt opt = { TCP_MAXSEG, 4, htons(s.getmss()) };
		out.write<tcp_mss_opt>(opt);
	}

	// set TCP data offset at current position
	tcp.th_off = out.position() >> 2;

	// store the resulting TCP header in the list of iovecs.
	iov.push_back(out);

	// send the appropriate TCP response
	uint8_t flags = tcp_in.th_flags;

	if (flags == (TH_SYN + TH_ACK)) {
		send_tcp_flags(s, addr, iov, TH_RST);
	} else if (flags == TH_SYN) {
		send_tcp_flags(s, addr, iov, TH_SYN + TH_ACK);
	} else if ((flags == TH_FIN) || flags == (TH_FIN + TH_ACK)) {
		send_tcp_flags(s, addr, iov, TH_FIN + TH_ACK);
	} else if (flags == TH_ACK) {
		// ignore
	} else {
		if (in.available() < 2) {
			send_tcp_flags(s, addr, iov, TH_RST);
			return;
		}
		auto len = ntohs(in.read<uint16_t>());
		if (in.available() < len) {
			send_tcp_flags(s, addr, iov, TH_RST);
			return;
		}

		Context ctx(zone);
		if (ctx.execute(in, iov, true)) {
			send_tcp_data(s, addr, iov, len + 2);
		}
	}
}

void Server::handle_ipv4(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr)
{
	// buffer for extracting data
	ReadBuffer in(buffer, buflen);

	// extract L3 header
	auto version = (in[0] >> 4) & 0x0f;
	if (version != 4) return;

	// check IP header length
	auto ihl = 4U * (in[0] & 0x0f);
	if (in.available() < ihl) return;

	// consume IPv4 header, skipping IP options
	auto& ip4_in = in.read<struct ip>();
	if (ihl > sizeof ip4_in) {
		(void) in.read<uint8_t>(ihl - sizeof ip4_in);
	}

	// check if it's for us
	if (::memcmp(&ip4_in.ip_dst, &addr_v4, sizeof(in_addr)) != 0) return;

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

	// response chunks get stored here
	std::vector<iovec> iov;
	iov.reserve(5);		// 5 = L3 + L4 + DNS (header + question) + BODY + EDNS

	// IPv4 header creation
	ip ip4_out;
	ip4_out.ip_v = 4;
	ip4_out.ip_hl = (sizeof ip4_out) / 4;
	ip4_out.ip_tos = 0;
	ip4_out.ip_len = 0;
	ip4_out.ip_off = 0;
	ip4_out.ip_ttl = 31;
	ip4_out.ip_p = ip4_in.ip_p;
	ip4_out.ip_sum = 0;
	ip4_out.ip_src = ip4_in.ip_dst;
	ip4_out.ip_dst = ip4_in.ip_src;
	iov.push_back( { &ip4_out, sizeof ip4_out } );

	// dispatch to layer four handling

	if (ip4_in.ip_p == IPPROTO_UDP) {
		handle_udp(s, in, addr, iov);
	} else if (ip4_in.ip_p == IPPROTO_TCP) {
		handle_tcp(s, in, addr, iov);
	}
}

//---------------------------------------------------------------------

void Server::handle_arp(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr)
{
	ReadBuffer in(buffer, buflen);

	// read fixed size ARP header
	if (in.available() < sizeof(arphdr)) return;
	auto hdr = in.read<arphdr>();

	// we only handle requests
	if (ntohs(hdr.ar_op) != ARPOP_REQUEST) return;

	// we only handle Ethernet
	if (ntohs(hdr.ar_hrd) != ARPHRD_ETHER) return;

	// we only handle IPv4
	if (ntohs(hdr.ar_pro) != ETHERTYPE_IP) return;

	// sanity check the lengths
	if (hdr.ar_hln != 6 || hdr.ar_pln != 4) return;

	// extract the remaining variable length fields
	if (in.available() < (2 * (hdr.ar_hln + hdr.ar_pln))) return;

	auto sha = in.read<ether_addr>();
	auto spa = in.read<in_addr>();
	(void) in.read<ether_addr>();
	auto tip = in.read<in_addr>();

	// it's not for us
	if (::memcmp(&tip, &addr_v4, sizeof tip) != 0) return;

	// generate reply packet
	uint8_t reply[28];
	auto out = WriteBuffer(reply, sizeof reply);

	auto& hdr_out = out.write<arphdr>(hdr);
	hdr_out.ar_op = htons(ARPOP_REPLY);

	out.write<ether_addr>(s.gethwaddr());
	out.write<in_addr>(tip);
	out.write<ether_addr>(sha);
	out.write<in_addr>(spa);

	// construct response message descriptor
	iovec iov(out);
	msghdr msg;
	msg.msg_name = reinterpret_cast<void*>(const_cast<sockaddr_ll*>(addr));
	msg.msg_namelen = sizeof(sockaddr_ll);
	msg.msg_control = nullptr;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	::sendmsg(s.fd, &msg, 0);
}

//---------------------------------------------------------------------

void Server::handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata)
{
	uint16_t ethertype = htons(addr->sll_protocol);

	if (ethertype == ETHERTYPE_IP) {
		handle_ipv4(s,  buffer, buflen, addr);
	} else if (ethertype == ETHERTYPE_ARP) {
		handle_arp(s,  buffer, buflen, addr);
	}
}

void Server::worker_thread(PacketSocket& s, in_addr _addr, uint16_t _port)
{
	// set listening address and port
	addr_v4 = _addr;
	port = htons(_port);

	try {
		using namespace std::placeholders;
		auto callback = std::bind(&Server::handle_packet, this, _1, _2, _3, _4, _5);

		while (true) {
			s.rx_ring_next(callback, -1, nullptr);
		}

	} catch (std::exception& e) {
		std::cerr << "worker error: " << e.what() << std::endl;
	}
}

//---------------------------------------------------------------------

void Server::loader_thread(std::string filename, bool compress)
{
	timespec mtim = { 0, 0 };
	struct stat st;
	bool first = true;

	while (true) {
		int res = ::stat(filename.c_str(), &st);
		if (first || (res == 0 && !(st.st_mtim == mtim))) {
			try {
				zone.load(filename, compress);
				mtim = st.st_mtim;
			} catch (std::exception& e) {
				std::cerr << "error: " << e.what() << std::endl;
			}
		}
		first = false;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void Server::load(const std::string& filename, bool compress)
{
	auto t = std::thread(&Server::loader_thread, this, filename, compress);
	t.detach();
}
