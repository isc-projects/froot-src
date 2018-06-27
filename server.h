#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "zone.h"
#include "packet.h"

class Server {

private:
	Zone			zone;

	in_addr			addr_v4;
	uint16_t		port;

private:
	void handle_udp(PacketSocket& s, ReadBuffer& in, const sockaddr_ll* addr, std::vector<iovec>& iov);
	void handle_tcp(PacketSocket& s, ReadBuffer& in, const sockaddr_ll* addr, std::vector<iovec>& iov);

	void handle_ipv4(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr);
	void handle_arp(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr);

	void handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);

private:
	void loader_thread(std::string filename, bool compress);

public:
	void worker_thread(PacketSocket& s, in_addr host, uint16_t port);
	void load(const std::string& filename, bool compress);
};
