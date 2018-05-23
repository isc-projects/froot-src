#ifndef __packet_h
#define __packet_h

#include <cstddef>
#include <string>
#include <functional>

#include <poll.h>

#include <net/ethernet.h>
#include <linux/if_packet.h>

class PacketSocket {

public:
	typedef std::function<void (PacketSocket& s, uint8_t* buf, size_t buflen, const sockaddr_ll* addr, void *userdata)> rx_callback_t;

private:
	pollfd		pfd;
	tpacket_req	req;

	uint8_t*	map = nullptr;
	uint32_t	rx_current = 0;
	ptrdiff_t	ll_offset;

public:
	int		fd = -1;

public:
			~PacketSocket();

public:
	void		open(int proto = ETH_P_ALL);
	void		close();

	void		bind(unsigned int ifindex);
	void		bind(const std::string& ifname);
	int		poll(int timeout = -1);

	int		setopt(int optname, const uint32_t val);
	int		getopt(int optname, uint32_t& val);

	void		rx_ring_enable(size_t frame_bits, size_t frame_nr);
	int		rx_ring_next(rx_callback_t cb, int timeout = -1, void *userdata = nullptr);
};

#endif // __packet_h
