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
#include <net/ethernet.h>

#include "netserver.h"

class Netserver_ARP : public NetserverLayer {

private:
	const ether_addr& ether;
	const in_addr& ipv4;
	
public:
	Netserver_ARP(const ether_addr& ether, const in_addr& ipv4) :
		ether(ether), ipv4(ipv4) {};

	void attach(NetserverLayer& parent) {
		NetserverLayer::attach(parent, ETHERTYPE_ARP);
	}

public:
	void recv(NetserverPacket &p) const override;

};
