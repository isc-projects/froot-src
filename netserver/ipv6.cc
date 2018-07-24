#include <cstring>
#include <vector>
#include <random>
#include <chrono>

#include <arpa/inet.h>
#include <netinet/ip6.h>

#include "ipv6.h"
#include "checksum.h"

#if 0
void Netserver_IPv4::send_fragment(NetserverPacket& p,
	uint16_t offset, uint16_t chunk,
	const std::vector<iovec>& iovs, size_t iovlen, bool mf) const
{
	// calculate offsets and populate IP header
	auto& ip = *reinterpret_cast<struct ip*>(iovs[0].iov_base);	// TODO: offset 0
	ip.ip_len = htons(chunk + sizeof ip);
	ip.ip_off = htons((mf << 13) | (offset >> 3));
	ip.ip_sum = 0;
	ip.ip_sum = Checksum().add(&ip, sizeof ip).value();

	send_up(p, iovs, iovlen);
}
#endif

void Netserver_IPv6::send(NetserverPacket& p, const std::vector<iovec>& iovs_in, size_t iovlen) const
{
}

#if 0
void Netserver_IPv4::send(NetserverPacket& p, const std::vector<iovec>& iovs_in, size_t iovlen) const
{
	// thread local RNG for generating IP IDs
	thread_local auto rnd = std::mt19937(std::chrono::system_clock::now().time_since_epoch().count() + 1);

	// copy vectors because we're going to modify them
	auto iovs = iovs_in;

	// set a random packet ID
	auto& ip = *reinterpret_cast<struct ip*>(iovs[0].iov_base);
	ip.ip_id = rnd();

	// determine maximum payload fragment size
	auto mtu = 1500;			// TODO: s.getmtu();
	auto max_frag = mtu - sizeof(struct ip);

	// state variables
	auto chunk = 0U;
	auto offset = 0U;

	auto iter = iovs.begin() + 1;
	while (iter != iovs.end()) {

		auto& vec = *iter++;
		auto base = reinterpret_cast<uint8_t*>(vec.iov_base);
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
			iter = iovs.insert(iter, iovec { base + vec.iov_len, len - vec.iov_len});

			// send fragment (with MF bit), remembering which layer we're on
			auto tmp = p.current;
			send_fragment(p, offset, chunk, iovs, iovs.size(), false);
			p.current = tmp;;

			// remove the already transmitted iovecs (excluding the IP header)
			iter = iovs.erase(iovs.begin() + 1, iter);

			// start collecting the next chunk
			offset += chunk;
			chunk = 0;
		}
	}

	// send final fragment
	send_fragment(p, offset, chunk, iovs, iovs.size(), false);
}
#endif

void Netserver_IPv6::recv(NetserverPacket& p) const
{
	ReadBuffer& in = p.readbuf;

	// extract L3 header
	auto version = (in[0] >> 4) & 0x0f;
	if (version != 6) return;

	// check IPv6 header length
	auto ihl = sizeof(ip6_hdr);
	if (in.available() < ihl) return;

	// read IPv6 header
	auto& ip6_in = in.read<ip6_hdr>();

	// check it's a registered protocol
	if (!registered(ip6_in.ip6_nxt)) return;

	// check if it's for us
	if (::memcmp(&ip6_in.ip6_dst, &addr, sizeof addr) != 0) return;

	// hack for broken AF_PACKET size - recreate the buffer
	// based on the IP header specified length instead of what
	// was returned by the AF_PACKET layer
	if (in.size() == 46) {
		size_t pos = in.position();
		size_t len = ntohs(ip6_in.ip6_plen);
		if (len < 46) {
			in = ReadBuffer(&in[0], len);
			(void) in.read<uint8_t>(pos);
		}
	}

	// IPv6 header creation
	ip6_hdr ip6_out;
	ip6_out.ip6_flow = ip6_in.ip6_flow;
	ip6_out.ip6_plen = 0;
	ip6_out.ip6_nxt = ip6_in.ip6_nxt;
	ip6_out.ip6_hlim = 31;
	ip6_out.ip6_src = ip6_in.ip6_dst;
	ip6_out.ip6_dst = ip6_in.ip6_src;
	p.push(iovec { &ip6_out, sizeof ip6_out } );

	// dispatch to layer four handling
	dispatch(p, ip6_in.ip6_nxt);
}

Netserver_IPv6::Netserver_IPv6(const ether_addr& ether, const in6_addr& addr)
	: addr(addr)
{
	memset(&link_local, 0, sizeof link_local);
	link_local.s6_addr[0] = 0xfe;
	link_local.s6_addr[1] = 0x80;
	link_local.s6_addr[8] = (ether.ether_addr_octet[0] ^ 0x01) | 0x02;
	link_local.s6_addr[9] = ether.ether_addr_octet[1];
	link_local.s6_addr[10] = ether.ether_addr_octet[2];
	link_local.s6_addr[11] = 0xff;
	link_local.s6_addr[12] = 0xfe;
	link_local.s6_addr[13] = ether.ether_addr_octet[3];
	link_local.s6_addr[14] = ether.ether_addr_octet[4];
	link_local.s6_addr[15] = ether.ether_addr_octet[5];
}
