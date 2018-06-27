#include <cstring>
#include <iostream>
#include <stdexcept>
#include <algorithm>

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>

#include "packet.h"
#include "util.h"

extern "C" unsigned int if_nametoindex (const char *__ifname);

PacketSocket::~PacketSocket()
{
	if (map) {
		::munmap(map, req.tp_frame_size * req.tp_frame_nr);
		map = nullptr;
	}

	if (fd >= 0) {
		::close(fd);
	}
}

void PacketSocket::open(int proto)
{
	fd = ::socket(AF_PACKET, SOCK_DGRAM, htons(proto));
	if (fd < 0) {
		throw_errno("socket(AF_PACKET, SOCK_DGRAM)");
	}

	pfd = { fd, POLLIN, 0 };
}

void PacketSocket::close()
{
	if (fd >= 0) {
		::close(fd);
		fd = -1;
	}
}

int PacketSocket::setopt(int name, const uint32_t val) const
{
	return ::setsockopt(fd, SOL_PACKET, name, &val, sizeof val);
}

int PacketSocket::getopt(int name, uint32_t& val) const
{
	socklen_t len = sizeof(val);
	return ::getsockopt(fd, SOL_PACKET, name, &val, &len);
}

void PacketSocket::bind(const std::string& ifnam)
{
	ifreq ifr;
	auto n = ifnam.copy(ifr.ifr_name, IFNAMSIZ);
	if (n < IFNAMSIZ) {
		ifr.ifr_name[n] = '\0';
	}

	// get the interface's MTU
	if (::ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		throw_errno("ioctl(SIOCGIFMTU)");
	}
	mtu = ifr.ifr_mtu;

	// get the interface's HWADDR
	if (::ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		throw_errno("ioctl(SIOCGIFHWADDR)");
	}
	::memcpy(&hwaddr, &ifr.ifr_hwaddr.sa_data, sizeof hwaddr);

	// get the interface's index for the following bind call
	if (::ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		throw_errno("ioctl(SIOCGIFINDEX)");
	}

	// bind the AF_PACKET socket to the specified interface
	sockaddr_ll saddr = { 0, };
	saddr.sll_family = AF_PACKET;
	saddr.sll_ifindex = ifr.ifr_ifindex;

	if (::bind(fd, reinterpret_cast<sockaddr *>(&saddr), sizeof(saddr)) < 0) {
		throw_errno("bind AF_PACKET");
	}

	// set the AF_PACKET socket's fanout mode
	uint32_t fanout = (getpid() & 0xffff) | (PACKET_FANOUT_CPU << 16);
	if (setopt(PACKET_FANOUT, fanout) < 0) {
		throw_errno("setsockopt PACKET_FANOUT");
	}
}

int PacketSocket::poll(int timeout)
{
	int res = ::poll(&pfd, 1, timeout);
	if (res < 0) {
		throw_errno("poll");
	}

	return res;
}

void PacketSocket::rx_ring_enable(size_t frame_bits, size_t frame_nr)
{
	size_t page_size = sysconf(_SC_PAGESIZE);

	req.tp_frame_nr = frame_nr;
	req.tp_frame_size = (1 << frame_bits);

	size_t map_size = req.tp_frame_size * req.tp_frame_nr;

	req.tp_block_size = std::max(page_size, size_t(req.tp_frame_size));
	req.tp_block_nr = map_size / req.tp_block_size;

	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
		throw_errno("PacketSocket::rx_ring_enable(PACKET_RX_RING)");
	}

	void *p = ::mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
	if (p == MAP_FAILED) {
		throw_errno("mmap");
	}

	map = reinterpret_cast<uint8_t*>(p);

	ll_offset = TPACKET_ALIGN(sizeof(struct tpacket_hdr));
}

int PacketSocket::rx_ring_next(Callback callback, int timeout, void *userdata)
{
	if (!map) {
		throw std::runtime_error("AF_PACKET rx_ring not enabled");
	}

	auto frame = map + rx_current * req.tp_frame_size;
	auto& hdr = *reinterpret_cast<tpacket_hdr*>(frame);

	if ((hdr.tp_status & TP_STATUS_USER) == 0) {
		if (poll(timeout) == 0) return 0;
	}

	// empty frame - ignore
	if (hdr.tp_len == 0) {
		return 0;
	}

	auto client = reinterpret_cast<sockaddr_ll *>(frame + ll_offset);
	auto buf = frame + hdr.tp_net;

	callback(*this, buf, hdr.tp_len, client, userdata);

	hdr.tp_status = TP_STATUS_KERNEL;
	rx_current = (rx_current + 1) % req.tp_frame_nr;

	return 1;
}
