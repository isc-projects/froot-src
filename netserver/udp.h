#pragma once

#include <netinet/in.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "netserver.h"

class Netserver_UDP : public NetserverLayer {

public:
	Netserver_UDP() {};

	void attach(NetserverLayer& parent) {
		NetserverLayer::attach(parent, IPPROTO_UDP);
	}

public:
	void recv(NetserverPacket& p) const override;
	void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const override;

};
