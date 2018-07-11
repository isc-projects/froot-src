#include <cstring>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>

#include "arp.h"

void Netserver_ARP::recv(NetserverPacket& p) const
{
	auto& in = p.readbuf;

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
	if (::memcmp(&tip, &ipv4, sizeof ipv4) != 0) return;

	// generate reply packet
	uint8_t reply[28];
	auto out = WriteBuffer(reply, sizeof reply);

	auto& hdr_out = out.write<arphdr>(hdr);
	hdr_out.ar_op = htons(ARPOP_REPLY);

	out.write<ether_addr>(ether);
	out.write<in_addr>(tip);
	out.write<ether_addr>(sha);
	out.write<in_addr>(spa);

	p.push(out);
	send(p);
}
