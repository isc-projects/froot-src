/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <chrono>
#include <random>

#include <netinet/ip.h>

#include "checksum.h"
#include "netserver.h"
#include "tcp.h"

static size_t payload_length(const std::vector<iovec>& iov)
{
	return std::accumulate(iov.cbegin() + 1, iov.cend(), 0U,
			       [](size_t a, const iovec& b) { return a + b.iov_len; });
}

struct __attribute__((packed)) tcp_mss_opt {
	uint8_t  type;
	uint8_t  len;
	uint16_t mss;
};

static void tcp_checksum(NetserverPacket p, std::vector<iovec>& iov)
{
	// take a copy of the pseudo-header checksum so far
	auto crc = p.crc;

	// update it with payload length info
	crc.add(payload_length(iov));

	// clear starting checksum
	auto& tcp = *reinterpret_cast<tcphdr*>(iov[1].iov_base);
	tcp.th_sum = 0;

	// update checksum with the TCP header and other payload data
	for (auto iter = iov.cbegin() + 1; iter != iov.cend(); ++iter) {
		crc.add(*iter);
	}

	// save the result back in the packet
	tcp.th_sum = crc.value();
}

void Netserver_TCP::send_flags(NetserverPacket& p, uint8_t flags) const
{
	thread_local auto rnd =
	    std::mt19937(std::chrono::system_clock::now().time_since_epoch().count());

	// generate TCP outbound header from inbound header
	auto& tcp = *reinterpret_cast<tcphdr*>(p.iovs[1].iov_base); // FIXME

	uint32_t ack = ntohl(tcp.th_ack);
	uint32_t seq = ntohl(tcp.th_seq);

	if (flags == (TH_SYN + TH_ACK)) {
		tcp.th_seq = rnd();
	} else {
		tcp.th_seq = ntohl(ack);
	}
	tcp.th_ack = htonl(seq + 1);
	tcp.th_flags = flags;
	tcp_checksum(p, p.iovs);

	send_up(p);
}

//
// assumes that iov[0] contains the IP header and iov[1] contains the TCP header
//
void Netserver_TCP::send(NetserverPacket& p, const std::vector<iovec>& iovs_in, size_t iovlen) const
{
	uint16_t acked = p.readbuf.position() - p.iovs[0].iov_len - p.iovs[1].iov_len; // FIXME

	// copy iovs so we can mutate them
	auto iovs = iovs_in;

	// generate TCP outbound header from inbound header
	auto& tcp = *reinterpret_cast<tcphdr*>(iovs[1].iov_base);

	uint32_t ack = ntohl(tcp.th_ack);
	uint32_t seq = ntohl(tcp.th_seq);

	tcp.th_ack = htonl(seq + acked);
	tcp.th_seq = htonl(ack);
	tcp.th_flags = TH_ACK;

	// use a copy of the vector because send_ipv4() will mutate it
	std::vector<iovec> out = {iovs[0], iovs[1]};
	out.reserve(5);

	// state variables
	auto     segment = 0U;
	uint16_t mss = 1220; // FIXME: s.getmss();

	auto iter = iovs.begin() + 2;
	while (iter != iovs.end()) {

		// take the current iovec
		auto vec = *iter++;
		auto len = vec.iov_len;
		segment += len;

		// copy it to the output list
		out.push_back(vec);

		// did we take too much?
		if (segment > mss) {

			// how much too much?
			auto excess = segment - mss;
			segment = mss;

			// adjust the output iovec's len to the new total length
			vec.iov_len -= excess;
			out.back() = vec;

			// insert a new iovec in the input list that holds the left-overs
			// assignment necessary in case old iterator is invalidated
			auto base = reinterpret_cast<uint8_t*>(vec.iov_base);
			iter = iovs.insert(iter, iovec{base + vec.iov_len, len - vec.iov_len});

			// send segment, remembering current layer ready for next segment
			tcp_checksum(p, out);
			auto current = p.current;
			send_up(p, out, out.size());
			p.current = current;

			// remove the already transmitted iovecs (excluding the IP and TCP headers)
			iter = iovs.erase(iovs.begin() + 2, iter);

			// get ready for the next segment
			tcp.th_seq = htonl(ntohl(tcp.th_seq) + segment);
			out.resize(2);
			out[0] = iovs[0];
			out[1] = iovs[1];
			segment = 0;
		}
	}

	// send final segment
	tcp.th_flags |= TH_FIN;

	tcp_checksum(p, iovs);
	send_up(p, iovs, iovs.size());
}

void Netserver_TCP::recv(NetserverPacket& p) const
{
	auto& in = p.readbuf;

	// consume L4 UDP header
	if (in.available() < sizeof(tcphdr)) return;
	auto& tcp_in = in.read<tcphdr>();

	// require expected dest port
	auto port = ntohs(tcp_in.th_dport);
	if (!registered(port)) return;

	// find data
	auto offset = 4U * tcp_in.th_off;

	// ignore illegal packets
	if (offset < sizeof tcp_in) return;
	auto skip = offset - sizeof tcp_in;

	// skip any options
	if (in.available() < skip) return;
	(void)in.read<uint8_t>(skip);

	// create buffer large enough for a TCP header and MSS option
	uint8_t     buf[sizeof(tcp_in) + sizeof(tcp_mss_opt)];
	WriteBuffer out(buf, sizeof(buf));

	// copy the TCP header, swapping source and dest ports
	auto& tcp = out.write<tcphdr>(tcp_in);
	std::swap(tcp.th_sport, tcp.th_dport);

	// and set our outbound TCP parameters
	tcp.th_win = htons(65535U);
	tcp.th_urp = 0;

	// add MSS option on initial syn
	if (tcp_in.th_flags & TH_SYN) {
		tcp_mss_opt opt = {TCP_MAXSEG, 4, htons(1220)}; // FIXME: s.getmss();
		out.write<tcp_mss_opt>(opt);
	}

	// set TCP data offset at current position
	tcp.th_off = out.position() >> 2;

	// store the resulting TCP header in the list of iovecs.
	p.push(out);

	// send the appropriate TCP response
	uint8_t flags = tcp_in.th_flags;

	if (flags == (TH_SYN + TH_ACK)) {
		send_flags(p, TH_RST);
	} else if (flags == TH_SYN) {
		send_flags(p, TH_SYN + TH_ACK);
	} else if ((flags == TH_FIN) || flags == (TH_FIN + TH_ACK)) {
		send_flags(p, TH_FIN + TH_ACK);
	} else if (flags == TH_ACK) {
		// ignore
	} else {
		// remember current layer and send the packet on
		auto current = p.current;
		dispatch(p, port);

		// if we haven't changed layer we didn't reply, so send a TCP RST
		if (current == p.current) {
			send_flags(p, TH_RST);
		}
	}
}
