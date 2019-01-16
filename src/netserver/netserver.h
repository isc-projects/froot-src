/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include <sys/socket.h>

#include "checksum.h"
#include "buffer.h"

class NetserverLayer;

typedef std::pair<const NetserverLayer*, void *> NetserverState;
typedef std::vector<NetserverState> NetserverLayers;

struct NetserverPacket {

public:
	ReadBuffer			readbuf;
	Checksum			crc;
	const sockaddr*			addr = nullptr;
	socklen_t			addrlen = 0;

	NetserverLayers			layers;
	std::vector<iovec>		iovs;
	uint16_t			l3 = 0;
	uint8_t				l4 = 0;
	int8_t				current = 0;

public:
	NetserverPacket(const uint8_t* buf, size_t buflen, const sockaddr* addr, socklen_t addrlen);

	void push(const iovec& iov) {
		iovs.push_back(iov);
	}
};

class NetserverLayer {

protected:
	std::map<uint16_t, const NetserverLayer*> layers;

	bool registered(uint16_t protocol) const;
	void dispatch(NetserverPacket& p, uint16_t proto, void *data = nullptr) const;

	void send_up(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const;
	void send_up(NetserverPacket& p) const;

public:
	void attach(NetserverLayer& layer, uint16_t proto);

public:
	virtual void recv(NetserverPacket& p) const = 0;
	virtual void send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const;
	virtual void send(NetserverPacket& p) const;
};

class NetserverRoot : public NetserverLayer {

public:
	virtual void loop() = 0;

};

//--  implementation  -------------------------------------------------

inline bool NetserverLayer::registered(uint16_t protocol) const
{
	return layers.find(protocol) != layers.end();
}

inline void NetserverLayer::dispatch(NetserverPacket& p, uint16_t protocol, void *data) const
{
	auto iter = layers.find(protocol);
	if (iter != layers.end()) {
		p.current++;
		p.layers.push_back(NetserverState { this, data });
		iter->second->recv(p);
	}
}

inline void NetserverLayer::send_up(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const
{
	auto current = --p.current;
	assert(current >= 0);
	auto state = p.layers[current];
	state.first->send(p, iovs, iovlen);
}

inline void NetserverLayer::send_up(NetserverPacket& p) const
{
	send_up(p, p.iovs, p.iovs.size());
}

// default send methods just push the data up a layer
inline void NetserverLayer::send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const
{
	send_up(p, iovs, iovlen);
}

inline void NetserverLayer::send(NetserverPacket& p) const {
	send(p, p.iovs, p.iovs.size());
}
