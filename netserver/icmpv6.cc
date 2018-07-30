#include <iostream>

#include <netinet/icmp6.h>

#include "icmpv6.h"
#include "checksum.h"

Netserver_ICMPv6::Netserver_ICMPv6(const ether_addr& ether /*, const in6_addr& ipv6 */)
	: ether(ether)
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

		// buffer for accumulated output
		uint8_t buffer[sizeof(nd_neighbor_advert) + sizeof(nd_opt_hdr) + sizeof(ether_addr)];
		WriteBuffer out(buffer, sizeof buffer);

		// ND advert header
		auto& na = out.reserve<nd_neighbor_advert>();
		na.nd_na_type = ND_NEIGHBOR_ADVERT;
		na.nd_na_code = 0;
		na.nd_na_cksum = 0;
		na.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
		na.nd_na_target = target;

		// Target link-address option
		auto& opt = out.reserve<nd_opt_hdr>();
		opt.nd_opt_type = ND_OPT_TARGET_LINKADDR;
		opt.nd_opt_len = 1;	// units of 8 octets
		out.write<ether_addr>(ether);

		// calculate ICMPv6 checksum
		auto crc = p.crc;		// IPv6 pseudo-header
		crc.add(sizeof buffer);		// payload length
		crc.add(buffer, sizeof buffer);	// ICMP data
		na.nd_na_cksum = crc.value();

		p.push(out);
		send(p);
	}
}
