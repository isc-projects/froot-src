#include <cstring>
#include <vector>
#include <random>
#include <chrono>

#include <arpa/inet.h>
#include <netinet/ip.h>

#include "ipv4.h"
#include "checksum.h"

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

	// send the fragment, but reset the current layer after if there's MF
	auto current = p.current;
	send_up(p, iovs, iovlen);
	if (mf) {
		p.current = current;
	}
}

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

			// send fragment (with MF bit)
			send_fragment(p, offset, chunk, iovs, iter - iovs.begin(), true);

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

void Netserver_IPv4::recv(NetserverPacket& p) const
{
	ReadBuffer& in = p.readbuf;

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

	// check it's a registered protocol
	if (!registered(ip4_in.ip_p)) return;

	// check if it's for us
	if (::memcmp(&ip4_in.ip_dst, &addr, sizeof addr) != 0) return;

	// hack for broken AF_PACKET size - recreate the buffer
	// based on the IP header specified length instead of what
	// was returned by the AF_PACKET layer
	if (in.size() == 46) {
		size_t pos = in.position();
		size_t len = ntohs(ip4_in.ip_len);
		if (len < 46) {
			in = ReadBuffer(&in[0], len);
			(void) in.read<uint8_t>(pos);
		}
	}

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
	p.push(iovec { &ip4_out, sizeof ip4_out } );

	// IPv4 pseudo-header
	p.crc.add(&ip4_in.ip_src, sizeof(in_addr));
	p.crc.add(&ip4_in.ip_dst, sizeof(in_addr));
	p.crc.add(ip4_in.ip_p);

	// dispatch to layer four handling
	dispatch(p, ip4_in.ip_p);
}
