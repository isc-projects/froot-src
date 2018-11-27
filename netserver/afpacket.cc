#include <cstring>
#include <iostream>
#include <stdexcept>

#include <unistd.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "afpacket.h"
#include "../util.h"

Netserver_AFPacket::Netserver_AFPacket(const std::string& ifname)
{
	fd = ::socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (fd < 0) {
		throw_errno("socket(AF_PACKET, SOCK_DGRAM)");
	}
	pfd = { fd, POLLIN, 0 };

	bind(ifname);
	rxring(11, 128);
}

void Netserver_AFPacket::bind(const std::string& ifname)
{
	ifreq ifr;
	auto n = ifname.copy(ifr.ifr_name, IFNAMSIZ);
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
	ifindex = ifr.ifr_ifindex;

	// bind the AF_PACKET socket to the specified interface
	sockaddr_ll saddr = { 0, };
	saddr.sll_family = AF_PACKET;
	saddr.sll_ifindex = ifindex;

	if (::bind(fd, reinterpret_cast<sockaddr *>(&saddr), sizeof(saddr)) < 0) {
		throw_errno("bind(AF_PACKET)");
	}

	// enable multicast reception
	packet_mreq mreq = { ifindex, PACKET_MR_ALLMULTI, 0 };
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof mreq) < 0) {
		throw_errno("setsockopt(PACKET_ADD_MEMBERSHIP)");
	}

	// set the AF_PACKET socket's fanout mode
	uint32_t fanout = (getpid() & 0xffff) | (PACKET_FANOUT_CPU << 16);
	if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout, sizeof fanout) < 0) {
		throw_errno("setsockopt(PACKET_FANOUT)");
	}

}

Netserver_AFPacket::~Netserver_AFPacket()
{
	if (map) {
		::munmap(map, req.tp_frame_size * req.tp_frame_nr);
		map = nullptr;
	}

	if (fd >= 0) {
		::close(fd);
	}
}

void Netserver_AFPacket::rxring(size_t frame_bits, size_t frame_nr)
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

void Netserver_AFPacket::recv(NetserverPacket& p) const
{
	auto* addr = reinterpret_cast<const sockaddr_ll*>(p.addr);
	uint16_t ethertype = ntohs(addr->sll_protocol);
	p.l3 = ethertype;
	dispatch(p, ethertype);
}

void Netserver_AFPacket::send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const
{
	msghdr msg;

	msg.msg_name = const_cast<void*>(reinterpret_cast<const void*>(p.addr));
	msg.msg_namelen = p.addrlen;
	msg.msg_control = nullptr;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = const_cast<iovec*>(iovs.data());
	msg.msg_iovlen = iovlen;

	auto res = ::sendmsg(fd, &msg, 0);
	if (res < 0) {
		perror("sendmsg");
	}
}

bool Netserver_AFPacket::next(int timeout)
{
	if (!map) {
		throw std::runtime_error("AF_PACKET rx_ring not enabled");
	}

	auto frame = map + rx_current * req.tp_frame_size;
	auto& hdr = *reinterpret_cast<tpacket_hdr*>(frame);

	if ((hdr.tp_status & TP_STATUS_USER) == 0) {
		int res = ::poll(&pfd, 1, timeout);
		if (res < 0) {
			throw_errno("poll");
		} else if (res == 0) {
			return false;
		}
	}

	// empty frame - ignore
	if (hdr.tp_len == 0) {
		return false;
	}

	try {
		NetserverPacket packet(
			frame + hdr.tp_net,
			hdr.tp_len,
			reinterpret_cast<const sockaddr *>(frame + ll_offset),
			sizeof(sockaddr_ll)
		);

		recv(packet);

	} catch (std::exception& e) {
		syslog(LOG_WARNING, "Netserver_AFPacket exception: %s", e.what());
	}

	hdr.tp_status = TP_STATUS_KERNEL;
	rx_current = (rx_current + 1) % req.tp_frame_nr;

	return true;
}

void Netserver_AFPacket::loop()
{
	while (true) {
		next(-1);
	}
}
