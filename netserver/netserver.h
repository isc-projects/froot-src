#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <sys/socket.h>

#include "../buffer.h"

class NetserverLayer;

typedef std::vector<const NetserverLayer*> NetserverLayers;

struct NetserverPacket {

public:
	ReadBuffer			readbuf;
	const sockaddr*			addr = nullptr;
	socklen_t			addrlen = 0;

	NetserverLayers			layers;
	std::vector<iovec>		iovs;

public:
	NetserverPacket(uint8_t* buf, size_t buflen, const sockaddr* addr, socklen_t addrlen);

	void push(const iovec iov) {
		iovs.push_back(iov);
	}
};

class NetserverLayer {

protected:
	std::array<const NetserverLayer*, 65536> layers = { nullptr };

	bool registered(uint16_t protocol) const;
	void dispatch(NetserverPacket& p, uint16_t proto) const;

	void send_up(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen, int current) const;
	void send_up(NetserverPacket& p, int current) const;

public:
	void attach(NetserverLayer& layer, uint16_t proto);

public:
	virtual void recv(NetserverPacket& p) const = 0;
	virtual void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen, int current) const;
	virtual void send(NetserverPacket& p, int current) const;
	virtual void send(NetserverPacket& p) const;
};

class NetserverRoot : public NetserverLayer {

public:
	virtual void loop() = 0;

};

//--  implementation  -------------------------------------------------

inline bool NetserverLayer::registered(uint16_t protocol) const
{
	return layers[protocol] != nullptr;
}

inline void NetserverLayer::dispatch(NetserverPacket& p, uint16_t protocol) const
{
	if (!layers[protocol]) return;

	p.layers.push_back(this);
	layers[protocol]->recv(p);
}

inline void NetserverLayer::send_up(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen, int current) const
{
	--current;
	assert(current >= 0);
	p.layers[current]->send(p, iovs, iovlen, current);
}

inline void NetserverLayer::send_up(NetserverPacket& p, int current) const
{
	send_up(p, p.iovs, p.iovs.size(), current);
}

// default send methods just push the data up a layer
inline void NetserverLayer::send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen, int current) const
{
	send_up(p, iovs, iovlen, current);
}

inline void NetserverLayer::send(NetserverPacket& p, int current) const {
	send(p, p.iovs, p.iovs.size(), current);
}

inline void NetserverLayer::send(NetserverPacket& p) const {
	send(p, p.iovs, p.iovs.size(), p.layers.size());
}
