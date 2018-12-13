#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "netserver.h"

class Netserver_Fuzz : public NetserverRoot {

private:
	const size_t		mtu = 1500;
	int			fd = -1;

private:
	void			recv(NetserverPacket& p) const override;

public:
	void			send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const override;

public:
	Netserver_Fuzz(const std::string& filename);
	~Netserver_Fuzz();

public:
	void			loop();

public:
	size_t			getmtu() const { return mtu; };
	size_t			getmss() const { return std::min(size_t(1220), mtu); };

};
