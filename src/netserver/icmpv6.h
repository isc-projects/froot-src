/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <net/ethernet.h>
#include <netinet/in.h>

#include "netserver.h"

class Netserver_ICMPv6 : public NetserverLayer {

private:
	const ether_addr& ether;

private:
	void neighbor_solicit(NetserverPacket& p) const;
	void echo_request(NetserverPacket& p) const;

public:
	Netserver_ICMPv6(const ether_addr& ether /*, const in6_addr& ipv6 */);

	void attach(NetserverLayer& parent)
	{
		NetserverLayer::attach(parent, IPPROTO_ICMPV6);
	}

public:
	void recv(NetserverPacket& p) const override;
};
