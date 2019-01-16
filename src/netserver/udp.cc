/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

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

void Netserver_UDP::send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const
{
	auto& udp_out = *reinterpret_cast<udphdr*>(iovs[1].iov_base);	// FIXME

	uint16_t len = payload_length(iovs);

	udp_out.uh_ulen = htons(len);

        // optionally update checksum with the UCP header and other payload data
	if (p.l3 == ETHERTYPE_IPV6) {
		auto crc = p.crc;
		crc.add(len);		// add payload length to the pseudo-header

		udp_out.uh_sum = 0;
		for (auto iter = iovs.cbegin() + 1; iter != iovs.cend(); ++iter) {
			crc.add(*iter);
		}
		udp_out.uh_sum = crc.value();
	}

	send_up(p, iovs, iovlen);
}
