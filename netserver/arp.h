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
	void recv(NetserverPacket &p) const;

};
