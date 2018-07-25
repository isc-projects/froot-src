#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <functional>

#include <poll.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

#include "netserver.h"

class Netserver_AFPacket : public NetserverRoot {

private:
	int			fd = -1;
	pollfd			pfd;
	tpacket_req		req;

	uint8_t*		map = nullptr;
	uint32_t		rx_current = 0;
	ptrdiff_t		ll_offset;

	int			ifindex;
	size_t			mtu;
	ether_addr		hwaddr;

private:
	void			bind(const std::string& ifnam);
	bool			next(int timeout);
	void			rxring(size_t frame_bits, size_t frame_nr);

private:
	void			recv(NetserverPacket& p) const override;

public:
	void			send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const override;

public:
	Netserver_AFPacket(const std::string& ifname);
	~Netserver_AFPacket();

public:
	void			loop();

public:
	size_t			getmtu() const { return mtu; };
	size_t			getmss() const { return std::min(size_t(1220), mtu); };
	const ether_addr&	gethwaddr() const { return hwaddr; };

};
