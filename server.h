#pragma once

#include "zone.h"
#include "packet.h"
#include "response.h"

class Server {

private:
	Zone			zone;

private:
	int query(const uint8_t* buffer, size_t len, size_t& qdsize) const;
	bool handle_packet_dns(uint8_t* buffer, size_t buflen, uint8_t* outbuf, size_t& outoff);
	void handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);
	void loop(PacketSocket& s);

public:
	void worker(const std::string& ifname);
	void load(const std::string& filename);

public:
	Server();
	~Server();

};
