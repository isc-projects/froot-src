#include <functional>
#include <numeric>
#include <vector>

#include <arpa/inet.h>
#include <netinet/udp.h>

#include "checksum.h"
#include "udp.h"

static size_t payload_length(const std::vector<iovec>& iov)
{
	return std::accumulate(iov.cbegin() + 1, iov.cend(), 0U,
		[](size_t a, const iovec& b) {
			return a + b.iov_len;
		}
	);
}

void Netserver_UDP::recv(NetserverPacket& p) const
{
	auto& in = p.readbuf;

	// consume L4 UDP header
	if (in.available() < sizeof(udphdr)) return;
	auto& udp_in = in.read<udphdr>();

	// require registered destination port
	auto proto = ntohs(udp_in.uh_dport);
	if (!registered(proto)) return;

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
	p.push(iovec { &udp_out, sizeof udp_out });

	dispatch(p, proto);
}

void Netserver_UDP::send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen, int current) const
{
	auto& udp_out = *reinterpret_cast<udphdr*>(iovs[1].iov_base);	// FIXME
	udp_out.uh_ulen = htons(payload_length(iovs));

	send_up(p, iovs, iovlen, current);
}
