/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include "netserver.h"
#include <net/ethernet.h>
#include <netinet/in.h>

class Netserver_IPv4 : public NetserverLayer {

private:
	const in_addr& addr;
	void	   send_fragment(NetserverPacket& p, uint16_t offset, uint16_t chunk,
				     const std::vector<iovec>& iov, size_t iovlen, bool mf) const;

public:
	Netserver_IPv4(const in_addr& addr) : addr(addr){};

	void attach(NetserverLayer& parent)
	{
		NetserverLayer::attach(parent, ETHERTYPE_IP);
	}

public:
	void recv(NetserverPacket& p) const override;
	void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const override;
};
