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
#include <netinet/udp.h>

#include "netserver.h"

class Netserver_UDP : public NetserverLayer {

public:
	Netserver_UDP(){};

	void attach(NetserverLayer& parent)
	{
		NetserverLayer::attach(parent, IPPROTO_UDP);
	}

public:
	void recv(NetserverPacket& p) const override;
	void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const override;
};
