/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <netinet/ip_icmp.h>

#include "icmp.h"
#include "checksum.h"

void Netserver_ICMP::recv(NetserverPacket& p) const
{
	auto& in = p.readbuf;

	// read ICMP header
	if (in.available() < sizeof(icmphdr)) return;
	auto hdr = in.read<icmphdr>();

	// we only answer pings
	if (hdr.type != ICMP_ECHO) return;

	// code 0 is the only valid one for echo
	if (hdr.code != 0) return;

	// use the copy of the header to generate the response
	p.push(iovec { &hdr, sizeof hdr });
	hdr.type = ICMP_ECHOREPLY;
	hdr.checksum = 0;

	// start accumulating the checksum
	Checksum crc;
	crc.add(&hdr, sizeof hdr);

	// use the remaining data in the read buffer as payload
	size_t n = in.available();
	auto payload = const_cast<uint8_t*>(in.read<uint8_t>(n));
	p.push(iovec { payload, n} );

	// update the checksum
	crc.add(payload, n);
	hdr.checksum = crc.value();

	send(p);
}
