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

#include "netserver.h"

class Netserver_ICMP : public NetserverLayer {

public:
	Netserver_ICMP(){};

	void attach(NetserverLayer& parent)
	{
		NetserverLayer::attach(parent, IPPROTO_ICMP);
	}

public:
	void recv(NetserverPacket& p) const override;
};
