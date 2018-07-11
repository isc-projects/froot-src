#pragma once

#include <net/ethernet.h>
#include <netinet/in.h>
#include "netserver.h"

class Netserver_IPv4 : public NetserverLayer {

private:
	const in_addr& addr;
	void send_fragment(NetserverPacket& p, int current, uint16_t offset, uint16_t chunk, const std::vector<iovec>& iov, size_t iovlen, bool mf) const;
	
public:
	Netserver_IPv4(const in_addr& addr) : addr(addr) { };

	void attach(NetserverLayer& parent) {
		NetserverLayer::attach(parent, ETHERTYPE_IP);
	}

public:
	void recv(NetserverPacket &p) const;
	void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen, int current) const;

};
