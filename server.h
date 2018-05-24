#pragma once

#include "zone.h"
#include "packet.h"
#include "buffer.h"

class Server {

private:
	Zone			zone;

private:
	bool handle_packet_dns(ReadBuffer& in, WriteBuffer& head, ReadBuffer& body);
	void handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);
	void loop(PacketSocket& s);

public:
	// exposed for benchmarking
	const Answer* query(ReadBuffer& in, size_t& qdsize, bool& match, ldns_enum_pkt_rcode& rcode) const;

	void worker(const std::string& ifname);
	void load(const std::string& filename);

public:
	Server();
	~Server();
};
