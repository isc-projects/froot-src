/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <cstring>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>

#include "arp.h"

static bool valid_packet(arphdr& hdr)
{
	// we only handle requests
	if (ntohs(hdr.ar_op) != ARPOP_REQUEST) return false;

	// we only handle Ethernet
	if (ntohs(hdr.ar_hrd) != ARPHRD_ETHER) return false;

	// we only handle IPv4
	if (ntohs(hdr.ar_pro) != ETHERTYPE_IP) return false;

	// sanity check the lengths
	if (hdr.ar_hln != 6 || hdr.ar_pln != 4) return false;

	return true;
}

void Netserver_ARP::recv(NetserverPacket& p) const
{
	auto& in = p.readbuf;

	// read and validate fixed size ARP header
	if (in.available() < sizeof(arphdr)) return;
	auto hdr = in.read<arphdr>();

	if (!valid_packet(hdr)) return;

	// check the payload length
	if (in.available() < (2 * (hdr.ar_hln + hdr.ar_pln))) return;

	// extract the remaining variable length fields
	auto sha = in.read<ether_addr>();
	auto spa = in.read<in_addr>();
	(void)in.read<ether_addr>();
	auto tip = in.read<in_addr>();

	// it's not for us
	if (::memcmp(&tip, &ipv4, sizeof ipv4) != 0) return;

	// generate reply packet
	uint8_t reply[28];
	auto    out = WriteBuffer(reply, sizeof reply);

	auto& hdr_out = out.write<arphdr>(hdr);
	hdr_out.ar_op = htons(ARPOP_REPLY);

	out.write<ether_addr>(ether);
	out.write<in_addr>(tip);
	out.write<ether_addr>(sha);
	out.write<in_addr>(spa);

	p.push(out);
	send(p);
}
