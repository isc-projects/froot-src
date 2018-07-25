#include <iostream>

#include <netinet/icmp6.h>

#include "icmpv6.h"
#include "checksum.h"

Netserver_ICMPv6::Netserver_ICMPv6(/* const ether_addr& ether, const in6_addr& ipv6 */)
{
}

void Netserver_ICMPv6::recv(NetserverPacket &p) const
{
	auto& in = p.readbuf;

	if (in.available() < sizeof(icmp6_hdr)) return;
	auto& hdr = in.read<icmp6_hdr>();

	if (hdr.icmp6_type == ND_NEIGHBOR_SOLICIT && hdr.icmp6_code == 0) {
		if (in.available() < sizeof(in6_addr)) return;
		auto& target = in.read<in6_addr>();

		nd_neighbor_advert out;

		out.nd_na_type = ND_NEIGHBOR_ADVERT;
		out.nd_na_code = 0;
		out.nd_na_flags_reserved = htonl(ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE);
		out.nd_na_target = target;

		out.nd_na_cksum = hdr.icmp6_cksum + 1;

		p.push(iovec { &out, sizeof out });

		send(p);
	}
}
