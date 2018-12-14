#include <iostream>

#include <netinet/icmp6.h>

#include "icmpv6.h"
#include "checksum.h"

Netserver_ICMPv6::Netserver_ICMPv6(const ether_addr& ether)
	: ether(ether)
{
}

void Netserver_ICMPv6::neighbor_solicit(NetserverPacket& p) const
{
	auto& in = p.readbuf;

	// read ND solicit header
	if (in.available() < sizeof(nd_neighbor_solicit)) return;
	auto& ns = in.read<nd_neighbor_solicit>();

	// create buffer for accumulated output
	uint8_t buffer[sizeof(nd_neighbor_advert) + sizeof(nd_opt_hdr) + sizeof(ether_addr)];
	WriteBuffer out(buffer, sizeof buffer);

	// ND advert header
	auto& na = out.reserve<nd_neighbor_advert>();
	na.nd_na_type = ND_NEIGHBOR_ADVERT;
	na.nd_na_code = 0;
	na.nd_na_cksum = 0;
	na.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
	na.nd_na_target = ns.nd_ns_target;

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

void Netserver_ICMPv6::echo_request(NetserverPacket& p) const
{
	auto& in = p.readbuf;
	auto hdr = in.read<icmp6_hdr>(); // length already checked

	// construct the reply in the copy of the request
	hdr.icmp6_type = ICMP6_ECHO_REPLY;
	hdr.icmp6_cksum = 0;

	auto crc = p.crc;		// IPv6 pseudo-header
	crc.add(&hdr, sizeof hdr);
	p.push(iovec {&hdr, sizeof hdr});

	// use the remaining data in the read buffer as payload
	auto n = in.available();
	auto payload = const_cast<uint8_t*>(in.read<uint8_t>(n));
	p.push(iovec { payload, n });

	// update the IPv6 checksum
	crc.add(payload, n);
	crc.add((sizeof hdr) + n);
	hdr.icmp6_cksum = crc.value();

	send(p);
}

void Netserver_ICMPv6::recv(NetserverPacket &p) const
{
	auto in = p.readbuf;	// NB: copy, so we can peek inside

	// check for legal packet
	if (in.available() < sizeof(icmp6_hdr)) return;
	auto& hdr = in.read<icmp6_hdr>();

	if (hdr.icmp6_type == ND_NEIGHBOR_SOLICIT && hdr.icmp6_code == 0) {
		neighbor_solicit(p);
	} else if (hdr.icmp6_type == ICMP6_ECHO_REQUEST && hdr.icmp6_code == 0) {
		echo_request(p);
	}
}
