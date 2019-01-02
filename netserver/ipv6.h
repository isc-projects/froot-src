/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <ostream>
#include <vector>

#include <net/ethernet.h>
#include <netinet/ip6.h>
#include "netserver.h"

class Netserver_IPv6 : public NetserverLayer {

private:
	std::vector<in6_addr> addr;

	bool match(const in6_addr& a) const;
	void send_fragment(NetserverPacket& p, uint16_t offset, uint16_t chunk, const std::vector<iovec>& iov, size_t iovlen, bool mf) const;
	
public:
	Netserver_IPv6(const std::vector<in6_addr>& addr);

	void attach(NetserverLayer& parent) {
		NetserverLayer::attach(parent, ETHERTYPE_IPV6);
	}

	static in6_addr ether_to_link_local(const ether_addr& ether);

public:
	void recv(NetserverPacket &p) const override;
	void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const override;

};

std::ostream& operator<<(std::ostream& os, const in6_addr& addr);
