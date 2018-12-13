#pragma once

#include "netserver/netserver.h"
#include "zone.h"

class DNSServer : public NetserverLayer {

private:
	Zone			zone;

private:
	void loader_thread(std::string filename, bool compress);

public:
	void recv(NetserverPacket& p) const;
	void attach(NetserverLayer& parent, uint16_t port = 53) {
		NetserverLayer::attach(parent, port);
	}

public:
	void load(const std::string& filename, bool compress);
	void load_sync(const std::string& filename, bool compress);
};
