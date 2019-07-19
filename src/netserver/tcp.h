/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "netserver.h"

class Netserver_TCP : public NetserverLayer {

protected:
	void send_flags(NetserverPacket& p, uint8_t flags) const;

public:
	void attach(NetserverLayer& parent)
	{
		NetserverLayer::attach(parent, IPPROTO_TCP);
	}

public:
	void recv(NetserverPacket& p) const override;
	void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const override;
};
