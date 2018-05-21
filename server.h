#pragma once

#include "zone.h"
#include "packet.h"

class Server {

private:
	Zone			zone;

private:
	void handle_packet_udp(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);
	void handle_packet_ipv4(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);
	void handle_packet_ipv6(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);
	void handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);
	void loop(PacketSocket& s);

public:
	void worker(const std::string& ifname);
	void load(const std::string& filename);
	int query(const uint8_t* buffer, size_t len) const;

public:
	Server();
	~Server();

};
