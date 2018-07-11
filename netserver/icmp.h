#pragma once

#include <netinet/in.h>

#include "netserver.h"

class Netserver_ICMP : public NetserverLayer {

public:
	Netserver_ICMP() {};

	void attach(NetserverLayer& parent) {
		NetserverLayer::attach(parent, IPPROTO_ICMP);
	}

public:
	void recv(NetserverPacket &p) const;

};
